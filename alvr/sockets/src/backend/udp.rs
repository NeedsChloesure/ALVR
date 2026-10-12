use crate::LOCAL_IP;

use super::{SocketReader, SocketWriter};
use alvr_common::{anyhow::Result, hex_preview, info, io_err_desc, ConResult, HandleTryAgain};
use alvr_session::{DscpTos, SocketBufferSize};
use socket2::{MaybeUninitSlice, Socket};
use std::{
    ffi::c_int,
    mem::MaybeUninit,
    net::{IpAddr, UdpSocket},
    ptr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

static UDP_IO_COUNTER: AtomicU64 = AtomicU64::new(0);

// See tcp.rs for the rationale of the throttling.
fn should_log_io(operation_index: u64) -> bool {
    operation_index <= 200 || operation_index % 500 == 0
}

// Create tokio socket, convert to socket2, apply settings, convert back to tokio. This is done to
// let tokio set all the internal parameters it needs from the start.
pub fn bind(
    port: u16,
    dscp: Option<DscpTos>,
    send_buffer_bytes: SocketBufferSize,
    recv_buffer_bytes: SocketBufferSize,
) -> Result<UdpSocket> {
    info!(
        "[UDP] bind: port {port} on {LOCAL_IP}, buffers (send {}, recv {})",
        crate::socket_buffer_size_desc(&send_buffer_bytes),
        crate::socket_buffer_size_desc(&recv_buffer_bytes),
    );

    let socket = UdpSocket::bind((LOCAL_IP, port))?.into();

    info!("[UDP] bind: bound to {}", crate::local_addr_desc(&socket));

    match crate::set_socket_buffers(&socket, send_buffer_bytes, recv_buffer_bytes) {
        Ok(()) => {}
        Err(e) => info!("[UDP] bind: socket buffers not configured: {e:?}"),
    }

    crate::set_dscp(&socket, dscp);

    Ok(socket.into())
}

pub fn connect(
    socket: &UdpSocket,
    peer_ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> Result<(UdpSocket, Socket)> {
    info!(
        "[UDP] connect: peer {peer_ip}:{port}, local {:?}",
        socket.local_addr()
    );

    socket.connect((peer_ip, port))?;
    socket.set_read_timeout(Some(timeout))?;

    info!(
        "[UDP] connect: done. local {:?}, peer {:?}, read timeout {:?}",
        socket.local_addr(),
        socket.peer_addr(),
        socket.read_timeout(),
    );

    Ok((socket.try_clone()?, socket.try_clone()?.into()))
}

impl SocketWriter for UdpSocket {
    fn send(&mut self, buffer: &[u8]) -> Result<()> {
        let operation = UDP_IO_COUNTER.fetch_add(1, Ordering::Relaxed);
        let verbose = should_log_io(operation);
        let start = verbose.then(Instant::now);

        let res = UdpSocket::send(self, buffer);

        match &res {
            Ok(sent) => {
                if verbose {
                    info!(
                        "[UDP-TX] op #{operation}: sent {sent}B of {}B in {:?}; local {:?}, peer {:?}",
                        buffer.len(),
                        start.map_or(Duration::ZERO, |start| start.elapsed()),
                        self.local_addr().ok(),
                        self.peer_addr().ok(),
                    );
                }
            }
            Err(e) => info!(
                "[UDP-TX] op #{operation}: FAILED to send {}B: {}; first bytes: {}",
                buffer.len(),
                io_err_desc(e),
                hex_preview(buffer),
            ),
        }

        res?;

        Ok(())
    }
}

impl SocketReader for Socket {
    fn recv(&mut self, buffer: &mut [u8]) -> ConResult<usize> {
        let operation = UDP_IO_COUNTER.fetch_add(1, Ordering::Relaxed);
        let verbose = should_log_io(operation);
        let start = Instant::now();

        let res = Socket::recv(self, unsafe {
            &mut *(ptr::from_mut(buffer) as *mut [MaybeUninit<u8>])
        })
        .handle_try_again();

        match &res {
            Ok(count) => {
                if verbose {
                    info!(
                        "[UDP-RX] op #{operation}: read {count}B of {}B available in {:?}; first bytes: {}",
                        buffer.len(),
                        start.elapsed(),
                        hex_preview(&buffer[..(*count).min(48)]),
                    );
                }
            }
            Err(e) => info!(
                "[UDP-RX] op #{operation}: read FAILED ({}B buffer) after {:?}: {e}",
                buffer.len(),
                start.elapsed(),
            ),
        }

        res
    }

    fn peek(&self, buffer: &mut [u8]) -> ConResult<usize> {
        #[cfg(windows)]
        const FLAGS: c_int = 0x02 | 0x8000; // MSG_PEEK | MSG_PARTIAL
        #[cfg(not(windows))]
        const FLAGS: c_int = 0x02 | 0x20; // MSG_PEEK | MSG_TRUNC

        let operation = UDP_IO_COUNTER.fetch_add(1, Ordering::Relaxed);
        let verbose = should_log_io(operation);
        let start = Instant::now();
        let buffer_length = buffer.len();

        let buffer = MaybeUninitSlice::new(unsafe {
            &mut *(ptr::from_mut(buffer) as *mut [MaybeUninit<u8>])
        });
        let res = self
            .recv_vectored_with_flags(&mut [buffer], FLAGS)
            .handle_try_again();

        match &res {
            Ok((count, _flags)) => {
                if verbose {
                    info!(
                        "[UDP-PEEK] op #{operation}: {count}B of {buffer_length}B buffer after {:?}",
                        start.elapsed(),
                    );
                }
            }
            Err(e) => info!(
                "[UDP-PEEK] op #{operation}: peek FAILED after {:?}: {e}",
                start.elapsed(),
            ),
        }

        res.map(|(count, _flags)| count)
    }
}
