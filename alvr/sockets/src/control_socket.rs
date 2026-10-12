use crate::backend::{tcp, SocketReader, SocketWriter};

use super::CONTROL_PORT;
use alvr_common::{
    anyhow::Result, hex_preview, info, io_err_desc, ConResult, ConnectionError, HandleTryAgain,
    ToCon,
};
use alvr_session::SocketBufferSize;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    marker::PhantomData,
    mem,
    net::{IpAddr, TcpListener, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

// This corresponds to the length of the payload
const FRAMED_PREFIX_LENGTH: usize = mem::size_of::<u32>();

// A packet bigger than this indicates a desynchronized or corrupt stream rather than a real packet.
const MAX_PLAUSIBLE_PACKET_LENGTH: usize = 32 * 1024 * 1024;

static CTRL_TX_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static CTRL_RX_SEQUENCE: AtomicU64 = AtomicU64::new(0);

// The prefix and payload read loops spin as fast as the socket allows when only a part of the packet
// is available, which can produce hundreds of thousands of iterations per second. Only the first
// iterations are logged; the terminating iteration (success, timeout or error) is always logged.
fn should_log_iteration(iteration: u32) -> bool {
    iteration <= 3 || iteration % 2000 == 0
}

struct RecvState {
    packet_length: usize, // contains length prefix
    packet_cursor: usize, // counts also the length prefix bytes
}

fn framed_send<S: Serialize>(
    socket: &mut TcpStream,
    buffer: &mut Vec<u8>,
    packet: &S,
) -> Result<()> {
    let sequence = CTRL_TX_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let start = Instant::now();

    let serialized_size = bincode::serialized_size(&packet)? as usize;
    let packet_size = serialized_size + FRAMED_PREFIX_LENGTH;

    info!(
        "[CTRL-TX #{sequence}] serializing {}: {}B payload, {packet_size}B on the wire. local {:?}, peer {:?}",
        std::any::type_name::<S>(),
        serialized_size,
        socket.local_addr().ok(),
        socket.peer_addr().ok(),
    );

    if buffer.len() < packet_size {
        buffer.resize(packet_size, 0);
    }

    buffer[0..FRAMED_PREFIX_LENGTH].copy_from_slice(&(serialized_size as u32).to_be_bytes());
    bincode::serialize_into(&mut buffer[FRAMED_PREFIX_LENGTH..packet_size], &packet)?;

    let res = socket.send(&buffer[0..packet_size]);

    match &res {
        Ok(()) => info!(
            "[CTRL-TX #{sequence}] sent {packet_size}B of {} in {:?}; first bytes: {}",
            std::any::type_name::<S>(),
            start.elapsed(),
            hex_preview(&buffer[0..packet_size]),
        ),
        Err(e) => info!(
            "[CTRL-TX #{sequence}] FAILED to send {packet_size}B of {} after {:?}: {e:#}; bytes: {}",
            std::any::type_name::<S>(),
            start.elapsed(),
            hex_preview(&buffer[0..packet_size]),
        ),
    }

    res?;

    Ok(())
}

fn framed_recv<R: DeserializeOwned>(
    socket: &mut TcpStream,
    buffer: &mut Vec<u8>,
    maybe_recv_state: &mut Option<RecvState>,
    timeout: Duration,
) -> ConResult<R> {
    let sequence = CTRL_RX_SEQUENCE.fetch_add(1, Ordering::Relaxed);

    let start = Instant::now();
    let deadline = start + timeout;

    let local_addr = socket.local_addr().ok();
    let peer_addr = socket.peer_addr().ok();

    info!(
        "[CTRL-RX #{sequence}] waiting for {} on {:?} (local {:?}); timeout {timeout:?}, resuming a partial packet: {}",
        std::any::type_name::<R>(),
        peer_addr,
        local_addr,
        maybe_recv_state.is_some(),
    );

    let recv_state_mut = if let Some(state) = maybe_recv_state {
        info!(
            "[CTRL-RX #{sequence}] resuming partial packet: {}B of {}B already received",
            state.packet_cursor, state.packet_length,
        );

        state
    } else {
        let mut payload_length_bytes = [0; FRAMED_PREFIX_LENGTH];

        let mut peek_iterations = 0u32;
        loop {
            peek_iterations += 1;

            let peek_start = Instant::now();
            let count = socket
                .peek(&mut payload_length_bytes)
                .inspect_err(|e| {
                    info!(
                        "[CTRL-RX #{sequence}] peek #{peek_iterations} on {:?} FAILED after {:?} (total {:?}): {}",
                        peer_addr,
                        peek_start.elapsed(),
                        start.elapsed(),
                        io_err_desc(e),
                    );
                })
                .handle_try_again()?;

            if should_log_iteration(peek_iterations) || count == FRAMED_PREFIX_LENGTH {
                info!(
                    "[CTRL-RX #{sequence}] peek #{peek_iterations}: {count}B of {FRAMED_PREFIX_LENGTH}B length prefix available from {:?} after {:?} (total {:?}); raw prefix: {}",
                    peer_addr,
                    peek_start.elapsed(),
                    start.elapsed(),
                    hex_preview(&payload_length_bytes),
                );
            }

            if count == FRAMED_PREFIX_LENGTH {
                break;
            } else if Instant::now() > deadline {
                info!(
                    "[CTRL-RX #{sequence}] TIMEOUT while reading length prefix: only {count}B of {FRAMED_PREFIX_LENGTH}B after {:?}",
                    start.elapsed(),
                );

                return alvr_common::try_again();
            }
        }

        let packet_length =
            FRAMED_PREFIX_LENGTH + u32::from_be_bytes(payload_length_bytes) as usize;

        info!(
            "[CTRL-RX #{sequence}] length prefix says: {}B payload, {packet_length}B total packet (read after {:?})",
            packet_length - FRAMED_PREFIX_LENGTH,
            start.elapsed(),
        );

        if packet_length > MAX_PLAUSIBLE_PACKET_LENGTH {
            info!(
                "[CTRL-RX #{sequence}] IMPLAUSIBLE PACKET LENGTH {packet_length}B (over {MAX_PLAUSIBLE_PACKET_LENGTH}B). The stream is likely desynchronized or contains garbage; prefix bytes: {}",
                hex_preview(&payload_length_bytes),
            );
        }

        if buffer.len() < packet_length {
            buffer.resize(packet_length, 0);
        }

        maybe_recv_state.insert(RecvState {
            packet_length,
            packet_cursor: 0,
        })
    };

    let mut recv_iterations = 0u32;
    loop {
        recv_iterations += 1;

        let recv_start = Instant::now();
        let count = socket
            .recv(&mut buffer[recv_state_mut.packet_cursor..recv_state_mut.packet_length])
            .inspect_err(|e| {
                info!(
                    "[CTRL-RX #{sequence}] recv #{recv_iterations} on {:?} FAILED at {}B of {}B after {:?} (total {:?}): {e}",
                    peer_addr,
                    recv_state_mut.packet_cursor,
                    recv_state_mut.packet_length,
                    recv_start.elapsed(),
                    start.elapsed(),
                );
            })?;
        recv_state_mut.packet_cursor += count;

        if should_log_iteration(recv_iterations)
            || recv_state_mut.packet_cursor == recv_state_mut.packet_length
        {
            info!(
                "[CTRL-RX #{sequence}] recv #{recv_iterations}: +{count}B ({score}/{total}B) from {:?} in {:?} (total {:?})",
                peer_addr,
                recv_start.elapsed(),
                start.elapsed(),
                score = recv_state_mut.packet_cursor,
                total = recv_state_mut.packet_length,
            );
        }

        if recv_state_mut.packet_cursor == recv_state_mut.packet_length {
            break;
        } else if Instant::now() > deadline {
            info!(
                "[CTRL-RX #{sequence}] TIMEOUT mid-packet: {}B of {}B after {:?}",
                recv_state_mut.packet_cursor,
                recv_state_mut.packet_length,
                start.elapsed(),
            );

            return alvr_common::try_again();
        }
    }

    let packet = match bincode::deserialize(
        &buffer[FRAMED_PREFIX_LENGTH..recv_state_mut.packet_length],
    )
    .to_con()
    {
        Ok(packet) => packet,
        Err(e) => {
            info!(
                "[CTRL-RX #{sequence}] DESERIALIZATION of {} FAILED after {:?}: {e}; {}-byte packet, raw bytes: {}",
                std::any::type_name::<R>(),
                start.elapsed(),
                recv_state_mut.packet_length,
                hex_preview(&buffer[0..recv_state_mut.packet_length]),
            );

            return Err(e);
        }
    };

    let packet_length = recv_state_mut.packet_length;

    *maybe_recv_state = None;

    info!(
        "[CTRL-RX #{sequence}] received {} ({packet_length}-byte packet) from {:?} in {:?}",
        std::any::type_name::<R>(),
        peer_addr,
        start.elapsed(),
    );

    Ok(packet)
}

pub struct ControlSocketSender<T> {
    inner: TcpStream,
    buffer: Vec<u8>,
    _phantom: PhantomData<T>,
}

impl<S: Serialize> ControlSocketSender<S> {
    pub fn send(&mut self, packet: &S) -> Result<()> {
        framed_send(&mut self.inner, &mut self.buffer, packet)
    }
}

pub struct ControlSocketReceiver<T> {
    inner: TcpStream,
    buffer: Vec<u8>,
    recv_state: Option<RecvState>,
    _phantom: PhantomData<T>,
}

impl<R: DeserializeOwned> ControlSocketReceiver<R> {
    pub fn recv(&mut self, timeout: Duration) -> ConResult<R> {
        framed_recv(
            &mut self.inner,
            &mut self.buffer,
            &mut self.recv_state,
            timeout,
        )
    }

    // Waits for a packet for up to `timeout` overall, retrying when the socket read timeout (which
    // is kept short so that a stalled stream is noticed quickly) interrupts the read. `recv` alone
    // gives up after the socket timeout, which is a common cause of spurious handshake failures: a
    // 2 second handshake deadline silently behaves like a 500 millisecond one.
    pub fn recv_within(&mut self, timeout: Duration) -> ConResult<R> {
        let start = Instant::now();

        loop {
            let remaining = timeout
                .saturating_sub(start.elapsed())
                .max(Duration::from_millis(1));

            match self.recv(remaining) {
                Err(ConnectionError::TryAgain(e)) if start.elapsed() < timeout => {
                    info!(
                        "[CTRL] recv interrupted after {:?} of {timeout:?}, retrying (the socket read timeout is shorter than the handshake deadline): {e}",
                        start.elapsed(),
                    );
                }
                result => return result,
            }
        }
    }
}

pub fn get_server_listener(timeout: Duration) -> Result<TcpListener> {
    info!("[CTRL] creating server control listener on port {CONTROL_PORT}, timeout {timeout:?}");

    let listener = tcp::bind(
        timeout,
        CONTROL_PORT,
        None,
        SocketBufferSize::Default,
        SocketBufferSize::Default,
    )?;

    info!(
        "[CTRL] server control listener ready on {:?}",
        listener.local_addr()
    );

    Ok(listener)
}

// Proto-control-socket that can send and receive any packet. After the split, only the packets of
// the specified types can be exchanged
pub struct ProtoControlSocket {
    inner: TcpStream,
}

pub enum PeerType<'a> {
    AnyClient(Vec<IpAddr>),
    Server(&'a TcpListener),
}

impl ProtoControlSocket {
    pub fn connect_to(timeout: Duration, peer: PeerType<'_>) -> ConResult<(Self, IpAddr)> {
        let start = Instant::now();

        match &peer {
            PeerType::AnyClient(ips) => info!(
                "[CTRL] connecting to a client: attempting {:?} on port {CONTROL_PORT}, timeout {timeout:?}",
                ips
            ),
            PeerType::Server(listener) => info!(
                "[CTRL] waiting for a server connection on {:?}, timeout {timeout:?}",
                listener.local_addr()
            ),
        }

        let socket = match peer {
            PeerType::AnyClient(ips) => {
                tcp::connect_to_client(
                    timeout,
                    &ips,
                    CONTROL_PORT,
                    SocketBufferSize::Default,
                    SocketBufferSize::Default,
                )?
                .0
            }
            PeerType::Server(listener) => tcp::accept_from_server(listener, None, timeout)?.0,
        };

        let peer_ip = socket.peer_addr().to_con()?.ip();

        info!(
            "[CTRL] control socket established with {peer_ip} in {:?} (local {:?}, peer {:?})",
            start.elapsed(),
            socket.local_addr().ok(),
            socket.peer_addr().ok(),
        );

        Ok((Self { inner: socket }, peer_ip))
    }

    pub fn send<S: Serialize>(&mut self, packet: &S) -> Result<()> {
        framed_send(&mut self.inner, &mut vec![], packet)
    }

    pub fn recv<R: DeserializeOwned>(&mut self, timeout: Duration) -> ConResult<R> {
        framed_recv(&mut self.inner, &mut vec![], &mut None, timeout)
    }

    // Non-blocking liveness check, used to tell whether the peer hung up before/while we were busy
    // doing work. It only distinguishes "the peer closed the connection" (a closed socket reports
    // zero readable bytes immediately) from "no data received yet".
    pub fn peer_is_alive(&self) -> bool {
        let previous_read_timeout = self.inner.read_timeout().ok();

        if self
            .inner
            .set_read_timeout(Some(Duration::from_millis(1)))
            .is_err()
        {
            return true;
        }

        let mut byte = [0_u8; 1];
        let result = self.inner.peek(&mut byte);

        _ = self.inner.set_read_timeout(previous_read_timeout.flatten());

        !matches!(result, Ok(0))
    }

    pub fn split<S: Serialize, R: DeserializeOwned>(
        self,
        timeout: Duration,
    ) -> Result<(ControlSocketSender<S>, ControlSocketReceiver<R>)> {
        info!("[CTRL] splitting control socket, setting read timeout to {timeout:?}");

        self.inner.set_read_timeout(Some(timeout))?;

        info!(
            "[CTRL] control socket split. effective read timeout {:?}, local {:?}, peer {:?}",
            self.inner.read_timeout(),
            self.inner.local_addr().ok(),
            self.inner.peer_addr().ok(),
        );

        Ok((
            ControlSocketSender {
                inner: self.inner.try_clone()?,
                buffer: vec![],
                _phantom: PhantomData,
            },
            ControlSocketReceiver {
                inner: self.inner,
                buffer: vec![],
                recv_state: None,
                _phantom: PhantomData,
            },
        ))
    }
}
