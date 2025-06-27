use crate::utils::error::VpnError;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use super::super::super::super::super::{Protocol, Connection};

pub struct Socks4Proxy {
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
}

impl Socks4Proxy {
    pub fn new(proxy_ip: &str, proxy_port: u16, target_ip: &str, target_port: u16) -> Result<Self, VpnError> {
        let proxy_addr = format!("{}:{}", proxy_ip, proxy_port)
            .parse::<SocketAddr>()
            .map_err(|e| VpnError::ConfigError(format!("Неверный адрес прокси: {}", e)))?;
        let target_addr = format!("{}:{}", target_ip, target_port)
            .parse::<SocketAddr>()
            .map_err(|e| VpnError::ConfigError(format!("Неверный адрес цели: {}", e)))?;
        Ok(Self { proxy_addr, target_addr })
    }
}

#[async_trait::async_trait]
impl Protocol for Socks4Proxy {
    type Connection = Socks4ProxyConnection;

    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        let mut stream = TcpStream::connect(self.proxy_addr).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось подключиться к прокси: {}", e)))?;

        // SOCKS4 handshake
        let ip = match self.target_addr.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            _ => return Err(VpnError::ConfigError("SOCKS4 поддерживает только IPv4-адреса".to_string())),
        };
        let port = self.target_addr.port().to_be_bytes();

        // Build request (no authentication support in SOCKS4)
        let mut request = vec![0x04, 0x01]; // Version 4, CMD CONNECT
        request.extend_from_slice(&port);
        request.extend_from_slice(&ip);
        request.push(0); // Null-terminated user ID

        stream.write_all(&request).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось отправить запрос SOCKS4: {}", e)))?;

        // Read response
        let mut response = [0u8; 8];
        stream.read_exact(&mut response).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось прочитать ответ SOCKS4: {}", e)))?;

        if response[1] != 0x5A { // Success code
            return Err(VpnError::ConnectionError("SOCKS4: Соединение отклонено прокси".to_string()));
        }

        Ok(Socks4ProxyConnection { stream })
    }
}

pub struct Socks4ProxyConnection {
    stream: TcpStream,
}

#[async_trait::async_trait]
impl Connection for Socks4ProxyConnection {
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        self.stream.write_all(packet).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось отправить данные через SOCKS4-прокси: {}", e)))
    }

    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        let mut buffer = vec![0u8; 65535];
        let n = self.stream.read(&mut buffer).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось получить данные через SOCKS4-прокси: {}", e)))?;
        buffer.truncate(n);
        Ok(buffer)
    }

    async fn close(&mut self) -> Result<(), VpnError> {
        self.stream.shutdown().await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось закрыть соединение: {}", e)))
    }
}
