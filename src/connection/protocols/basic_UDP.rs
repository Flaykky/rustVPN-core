use crate::utils::logging::{log_debug, log_info, log_warn};
use crate::utils::error::VpnError;
use tokio::net::UdpSocket;
use std::net::SocketAddr;
use super::{Protocol, Connection};

pub struct BasicUdp {
    server_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl BasicUdp {
    pub fn new(local_ip: &str, local_port: u16, server_ip: &str, server_port: u16) -> Result<Self, VpnError> {
        let local_addr = format!("{}:{}", local_ip, local_port)
            .parse::<SocketAddr>()
            .map_err(|e| {
                log_warn!("Invalid local address: {}", e);
                VpnError::ConfigError(format!("Неверный локальный адрес: {}", e))
            })?;
        let server_addr = format!("{}:{}", server_ip, server_port)
            .parse::<SocketAddr>()
            .map_err(|e| {
                log_warn!("Invalid server address: {}", e);
                VpnError::ConfigError(format!("Неверный адрес сервера: {}", e))
            })?;
        log_info!("Initialized UDP connection from {} to {}", local_addr, server_addr);
        Ok(Self { server_addr, local_addr })
    }
}

#[async_trait::async_trait]
impl Protocol for BasicUdp {
    type Connection = BasicUdpConnection;

    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        log_info!("Binding UDP socket at {}", self.local_addr);
        let socket = UdpSocket::bind(self.local_addr)
            .await
            .map_err(|e| {
                log_warn!("Failed to bind UDP socket: {}", e);
                VpnError::ConnectionError(format!("Не удалось привязать сокет: {}", e))
            })?;
        log_info!("Connecting UDP socket to {}", self.server_addr);
        socket
            .connect(self.server_addr)
            .await
            .map_err(|e| {
                log_warn!("Failed to connect UDP socket: {}", e);
                VpnError::ConnectionError(format!("Не удалось подключиться к серверу: {}", e))
            })?;
        log_info!("Successfully connected UDP socket to {}", self.server_addr);
        Ok(BasicUdpConnection { socket })
    }
}

pub struct BasicUdpConnection {
    socket: UdpSocket,
}

#[async_trait::async_trait]
impl Connection for BasicUdpConnection {
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        if packet.len() > 65535 {
            log_warn!("Attempted to send oversized UDP packet: {} bytes", packet.len());
            return Err(VpnError::ProtocolError("Слишком большой пакет для UDP".to_string()));
        }
        log_debug!("Sending UDP packet of size {} bytes", packet.len());
        self.socket
            .send(packet)
            .await
            .map_err(|e| {
                log_warn!("Failed to send UDP packet: {}", e);
                VpnError::ConnectionError(format!("Не удалось отправить пакет: {}", e))
            })?;
        log_info!("Sent UDP packet of size {} bytes", packet.len());
        Ok(())
    }

    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        let mut buffer = vec![0u8; 65535];
        let len = self.socket
            .recv(&mut buffer)
            .await
            .map_err(|e| {
                log_warn!("Failed to receive UDP packet: {}", e);
                VpnError::ConnectionError(format!("Не удалось получить пакет: {}", e))
            })?;
        buffer.truncate(len);
        log_debug!("Received UDP packet of size {} bytes", len);
        Ok(buffer)
    }

    async fn close(&mut self) -> Result<(), VpnError> {
        log_info!("Closing UDP connection");
        Ok(())
    }
}
