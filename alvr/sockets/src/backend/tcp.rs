use crate::LOCAL_IP;

use super::{SocketReader, SocketWriter};
use alvr_common::{
    anyhow::Result, con_bail, hex_preview, info, io_err_desc, ConResult, HandleTryAgain, ToCon,
};
use alvr_session::{DscpTos, SocketBufferSize};
use std::{
    io::Read,
    io::Write,
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

static TCP_CONNECT_ATTEMPT_COUNTER: AtomicU64 = AtomicU64::new(0);
static TCP_IO_COUNTER: AtomicU64 = AtomicU64::new(0);

// Per-operation socket logging is throttled: a streaming session generates thousands of packets per
// second, which would drown the log and slow the stream down. The first operations (which include
// the whole control channel handshake) are always logged. Failures are never throttled.
fn should_log_io(operation_index: u64) -> bool {
    operation_index <= 200 || operation_index % 500 == 0
}

fn listener_addr_desc(listener: &TcpListener) -> String {
    match listener.local_addr() {
        Ok(addr) => addr.to_string(),
        Err(e) => format!("<error: {e}>"),
    }
}

pub fn bind(
    timeout: Duration,
    port: u16,
    dscp: Option<DscpTos>,
    send_buffer_bytes: SocketBufferSize,
    recv_buffer_bytes: SocketBufferSize,
) -> Result<TcpListener> {
    info!("[TCP] bind: port {port} on {LOCAL_IP}, read timeout {timeout:?}");

    let socket = TcpListener::bind((LOCAL_IP, port))?.into();

    info!(
        "[TCP] bind: socket bound, local addr {}",
        crate::local_addr_desc(&socket)
    );

    match crate::set_socket_buffers(&socket, send_buffer_bytes, recv_buffer_bytes) {
        Ok(()) => {}
        Err(e) => info!("[TCP] bind: socket buffers not configured: {e:?}"),
    }

    crate::set_dscp(&socket, dscp);

    socket.set_read_timeout(Some(timeout))?;

    let socket: TcpListener = socket.into();

    info!(
        "[TCP] bind: listener ready on {}",
        listener_addr_desc(&socket)
    );

    Ok(socket)
}

pub fn accept_from_server(
    listener: &TcpListener,
    server_ip: Option<IpAddr>,
    timeout: Duration,
) -> ConResult<(TcpStream, TcpStream)> {
    info!(
        "[TCP] accept: waiting for one connection on {} (expected peer: {server_ip:?}, timeout {timeout:?})",
        listener_addr_desc(listener)
    );

    // Uses timeout set during bind()
    let (socket, server_address) = match listener.accept() {
        Ok(pair) => pair,
        Err(e) => {
            // WouldBlock is expected while polling and is mapped to TryAgain, so it is only logged
            // with its raw error code.
            info!("[TCP] accept: no connection in time: {}", io_err_desc(&e));
            return Err(e).handle_try_again();
        }
    };

    info!(
        "[TCP] accept: connection from {server_address}, local addr {:?}",
        socket.local_addr()
    );

    if let Some(ip) = server_ip {
        if server_address.ip() != ip {
            info!(
                "[TCP] accept: REJECTING connection, expected peer {ip}, found {}",
                server_address.ip()
            );

            con_bail!(
                "Connected to wrong client: Expected: {ip}, Found {}",
                server_address.ip()
            );
        }
    }

    socket.set_read_timeout(Some(timeout)).to_con()?;
    socket.set_nodelay(true).to_con()?;

    info!(
        "[TCP] accept: accepted socket ready. read timeout {:?}, nodelay {:?}, local {:?}, peer {:?}",
        socket.read_timeout(),
        socket.nodelay(),
        socket.local_addr(),
        socket.peer_addr(),
    );

    Ok((socket.try_clone().to_con()?, socket))
}

pub fn connect_to_client(
    timeout: Duration,
    client_ips: &[IpAddr],
    port: u16,
    send_buffer_bytes: SocketBufferSize,
    recv_buffer_bytes: SocketBufferSize,
) -> ConResult<(TcpStream, TcpStream)> {
    let attempt = TCP_CONNECT_ATTEMPT_COUNTER.fetch_add(1, Ordering::Relaxed);

    let split_timeout = timeout / client_ips.len() as u32;

    info!(
        "[TCP] connect #{attempt}: port {port}, {} candidate IP(s) {:?}, total timeout {timeout:?}, per-IP timeout {split_timeout:?}, buffers (send {}, recv {})",
        client_ips.len(),
        client_ips,
        crate::socket_buffer_size_desc(&send_buffer_bytes),
        crate::socket_buffer_size_desc(&recv_buffer_bytes),
    );

    let mut res = alvr_common::try_again();
    for ip in client_ips {
        let target = SocketAddr::new(*ip, port);
        let start = Instant::now();

        res = TcpStream::connect_timeout(&target, split_timeout).handle_try_again();

        let elapsed = start.elapsed();
        match &res {
            Ok(socket) => info!(
                "[TCP] connect #{attempt}: {target} CONNECTED in {elapsed:?}, local addr {:?}",
                socket.local_addr()
            ),
            Err(e) => info!("[TCP] connect #{attempt}: {target} FAILED after {elapsed:?}: {e}"),
        }

        if res.is_ok() {
            break;
        }
    }
    let socket = match res {
        Ok(socket) => socket.into(),
        Err(e) => {
            info!("[TCP] connect #{attempt}: all candidate IPs failed, giving up");
            return Err(e);
        }
    };

    match crate::set_socket_buffers(&socket, send_buffer_bytes, recv_buffer_bytes) {
        Ok(()) => {}
        Err(e) => info!("[TCP] connect #{attempt}: socket buffers not configured: {e:?}"),
    }

    socket.set_read_timeout(Some(timeout)).to_con()?;

    let socket = TcpStream::from(socket);

    socket.set_nodelay(true).to_con()?;

    info!(
        "[TCP] connect #{attempt}: socket ready. local {:?}, peer {:?}, read timeout {:?}, nodelay {:?}",
        socket.local_addr(),
        socket.peer_addr(),
        socket.read_timeout(),
        socket.nodelay(),
    );

    Ok((socket.try_clone().to_con()?, socket))
}

impl SocketWriter for TcpStream {
    fn send(&mut self, buffer: &[u8]) -> Result<()> {
        let operation = TCP_IO_COUNTER.fetch_add(1, Ordering::Relaxed);
        let verbose = should_log_io(operation);
        let start = verbose.then(Instant::now);

        let res = self.write_all(buffer);

        match &res {
            Ok(()) => {
                if verbose {
                    info!(
                        "[TCP-TX] op #{operation}: sent {}B in {:?}; local {:?}, peer {:?}",
                        buffer.len(),
                        start.map_or(Duration::ZERO, |start| start.elapsed()),
                        self.local_addr().ok(),
                        self.peer_addr().ok(),
                    );
                }
            }
            Err(e) => info!(
                "[TCP-TX] op #{operation}: FAILED to send {}B: {}; first bytes: {}",
                buffer.len(),
                io_err_desc(e),
                hex_preview(buffer),
            ),
        }

        res?;

        Ok(())
    }
}

impl SocketReader for TcpStream {
    fn recv(&mut self, buffer: &mut [u8]) -> ConResult<usize> {
        let operation = TCP_IO_COUNTER.fetch_add(1, Ordering::Relaxed);
        let verbose = should_log_io(operation);
        let start = Instant::now();

        let res = Read::read(self, buffer).handle_try_again();

        match &res {
            Ok(count) => {
                if verbose {
                    info!(
                        "[TCP-RX] op #{operation}: read {count}B of {}B requested in {:?}; first bytes: {}",
                        buffer.len(),
                        start.elapsed(),
                        hex_preview(&buffer[..(*count).min(48)]),
                    );
                }
            }
            Err(e) => info!(
                "[TCP-RX] op #{operation}: read FAILED ({}B requested) after {:?}: {e}",
                buffer.len(),
                start.elapsed(),
            ),
        }

        res
    }

    fn peek(&self, buffer: &mut [u8]) -> ConResult<usize> {
        let operation = TCP_IO_COUNTER.fetch_add(1, Ordering::Relaxed);
        let verbose = should_log_io(operation);
        let start = Instant::now();

        let res = TcpStream::peek(self, buffer).handle_try_again();

        match &res {
            Ok(count) => {
                if verbose {
                    info!(
                        "[TCP-PEEK] op #{operation}: {count}B available of {}B requested in {:?}; first bytes: {}",
                        buffer.len(),
                        start.elapsed(),
                        hex_preview(&buffer[..(*count).min(48)]),
                    );
                }
            }
            Err(e) => info!(
                "[TCP-PEEK] op #{operation}: peek FAILED after {:?}: {e}",
                start.elapsed(),
            ),
        }

        res
    }
}
