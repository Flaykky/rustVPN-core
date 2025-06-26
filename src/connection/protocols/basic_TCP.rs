use crate::utils::logging::{log_debug, log_info, log_warn};
use crate::utils::error::VpnError;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use super::{Protocol, Connection};

pub struct BasicTcp {
    server_addr: SocketAddr,
}

impl BasicTcp {
    pub fn new(server_ip: &str, server_port: u16) -> Result<Self, VpnError> {
        let server_addr = format!("{}:{}", server_ip, server_port)
            .parse::<SocketAddr>()
            .map_err(|e| {
                log_warn!("Invalid server address: {}", e);
                VpnError::ConfigError(format!("Неверный адрес сервера: {}", e))
            })?;
        log_info!("Initialized TCP connection to {}", server_addr);
        Ok(Self { server_addr })
    }
}

#[async_trait::async_trait]
impl Protocol for BasicTcp {
    type Connection = BasicTcpConnection;

    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        log_info!("Connecting to TCP server at {}", self.server_addr);
        let stream = TcpStream::connect(self.server_addr)
            .await
            .map_err(|e| {
                log_warn!("Failed to connect: {}", e);
                VpnError::ConnectionError(format!("Не удалось подключиться: {}", e))
            })?;
        stream
            .set_nodelay(true)
            .map_err(|e| {
                log_warn!("Failed to set TCP_NODELAY: {}", e);
                VpnError::ConnectionError(format!("Не удалось установить TCP_NODELAY: {}", e))
            })?;
        log_info!("Successfully connected to TCP server at {}", self.server_addr);
        Ok(BasicTcpConnection { stream })
    }
}

pub struct BasicTcpConnection {
    stream: TcpStream,
}

#[async_trait::async_trait]
impl Connection for BasicTcpConnection {
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        let len = packet.len() as u32;
        log_debug!("Sending TCP packet of size {} bytes", len);
        self.stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| {
                log_warn!("Failed to send packet length: {}", e);
                VpnError::ConnectionError(format!("Не удалось отправить длину пакета: {}", e))
            })?;
        self.stream
            .write_all(packet)
            .await
            .map_err(|e| {
                log_warn!("Failed to send packet: {}", e);
                VpnError::ConnectionError(format!("Не удалось отправить пакет: {}", e))
            })?;
        self.stream
            .flush()
            .await
            .map_err(|e| {
                log_warn!("Failed to flush buffer: {}", e);
                VpnError::ConnectionError(format!("Не удалось сбросить буфер: {}", e))
            })?;
        log_info!("Sent TCP packet of size {} bytes", len);
        Ok(())
    }

    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| {
                log_warn!("Failed to read packet length: {}", e);
                VpnError::ConnectionError(format!("Не удалось прочитать длину пакета: {}", e))
            })?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 65535 {
            log_warn!("Received oversized TCP packet: {} bytes", len);
            return Err(VpnError::ProtocolError("Слишком большой пакет".to_string()));
        }
        let mut packet = vec![0u8; len];
        self.stream
            .read_exact(&mut packet)
            .await
            .map_err(|e| {
                log_warn!("Failed to read packet: {}", e);
                VpnError::ConnectionError(format!("Не удалось прочитать пакет: {}", e))
            })?;
        log_debug!("Received TCP packet of size {} bytes", len);
        Ok(packet)
    }

    async fn close(&mut self) -> Result<(), VpnError> {
        log_info!("Closing TCP connection");
        self.stream
            .shutdown()
            .await
            .map_err(|e| {
                log_warn!("Failed to shutdown connection: {}", e);
                VpnError::ConnectionError(format!("Не удалось закрыть соединение: {}", e))
            })?;
        Ok(())
    }
}
