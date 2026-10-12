mod backend;
mod control_socket;
mod stream_socket;

use alvr_common::{anyhow::Result, info, io_err_desc, warn};
use alvr_session::{DscpTos, SocketBufferSize};
use socket2::Socket;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

pub use control_socket::*;
pub use stream_socket::*;

pub const LOCAL_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
pub const CONTROL_PORT: u16 = 9943;
pub const HANDSHAKE_PACKET_SIZE_BYTES: usize = 56; // this may change in future protocols
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(500);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(2);

pub const MDNS_SERVICE_TYPE: &str = "_alvr._tcp.local.";
pub const MDNS_PROTOCOL_KEY: &str = "protocol";
pub const MDNS_DEVICE_ID_KEY: &str = "device_id";

pub const WIRED_CLIENT_HOSTNAME: &str = "client.wired";

pub(crate) fn socket_buffer_size_desc(size: &SocketBufferSize) -> String {
    match size {
        SocketBufferSize::Default => "default (leave unchanged)".to_owned(),
        SocketBufferSize::Maximum => format!("maximum ({})", u32::MAX),
        SocketBufferSize::Custom(bytes) => format!("custom ({bytes})"),
    }
}

pub(crate) fn local_addr_desc(socket: &socket2::Socket) -> String {
    match socket.local_addr() {
        Ok(addr) => addr
            .as_socket()
            .map_or_else(|| format!("{addr:?}"), |addr| addr.to_string()),
        Err(e) => format!("<error: {e}>"),
    }
}

fn set_socket_buffers(
    socket: &socket2::Socket,
    send_buffer_bytes: SocketBufferSize,
    recv_buffer_bytes: SocketBufferSize,
) -> Result<()> {
    info!(
        "Initial socket buffer size: send: {}B, recv: {}B",
        socket.send_buffer_size()?,
        socket.recv_buffer_size()?
    );

    info!(
        "[BUF] requested send buffer: {}, requested recv buffer: {} (local addr {})",
        socket_buffer_size_desc(&send_buffer_bytes),
        socket_buffer_size_desc(&recv_buffer_bytes),
        local_addr_desc(socket),
    );

    {
        let maybe_size = match send_buffer_bytes {
            SocketBufferSize::Default => None,
            SocketBufferSize::Maximum => Some(u32::MAX),
            SocketBufferSize::Custom(size) => Some(size),
        };

        if let Some(size) = maybe_size {
            if let Err(e) = socket.set_send_buffer_size(size as usize) {
                info!("Error setting socket send buffer: {e}");
            } else {
                info!(
                    "Set socket send buffer succeeded: {}",
                    socket.send_buffer_size()?
                );
            }

            info!(
                "[BUF] send buffer after request: requested {size}B, actual {}B",
                socket.send_buffer_size()?
            );
        } else {
            info!(
                "[BUF] send buffer left at system default: {}B",
                socket.send_buffer_size()?
            );
        }
    }

    {
        let maybe_size = match recv_buffer_bytes {
            SocketBufferSize::Default => None,
            SocketBufferSize::Maximum => Some(u32::MAX),
            SocketBufferSize::Custom(size) => Some(size),
        };

        if let Some(size) = maybe_size {
            if let Err(e) = socket.set_recv_buffer_size(size as usize) {
                info!("Error setting socket recv buffer: {e}");
            } else {
                info!(
                    "Set socket recv buffer succeeded: {}",
                    socket.recv_buffer_size()?
                );
            }

            info!(
                "[BUF] recv buffer after request: requested {size}B, actual {}B",
                socket.recv_buffer_size()?
            );
        } else {
            info!(
                "[BUF] recv buffer left at system default: {}B",
                socket.recv_buffer_size()?
            );
        }
    }

    Ok(())
}

fn set_dscp(socket: &Socket, dscp: Option<DscpTos>) {
    // https://en.wikipedia.org/wiki/Differentiated_services
    if let Some(dscp) = dscp {
        let tos = match dscp {
            DscpTos::BestEffort => 0,
            DscpTos::ClassSelector(precedence) => precedence << 3,
            DscpTos::AssuredForwarding {
                class,
                drop_probability,
            } => (class << 3) | drop_probability as u8,
            DscpTos::ExpeditedForwarding => 0b101110,
        };

        match socket.set_tos((tos << 2) as u32) {
            Ok(()) => info!("[BUF] dscp set: tos byte {tos}"),
            Err(e) => warn!("[BUF] dscp NOT set (tos byte {tos}): {}", io_err_desc(&e)),
        }
    } else {
        info!("[BUF] dscp not requested");
    }
}
