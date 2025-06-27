use crate::utils::error::VpnError;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use super::super::super::super::super::{Protocol, Connection};

pub struct HttpProxy {
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
}

impl HttpProxy {
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
impl Protocol for HttpProxy {
    type Connection = HttpProxyConnection;

    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        let mut stream = TcpStream::connect(self.proxy_addr).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось подключиться к прокси: {}", e)))?;

        // Send CONNECT request
        let host = self.target_addr.ip().to_string();
        let port = self.target_addr.port();
        let request = format!("CONNECT {}:{} HTTP/1.1\r\nHost: {}\r\n\r\n", host, port, host);
        stream.write_all(request.as_bytes()).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось отправить CONNECT-запрос: {}", e)))?;

        // Read response
        let mut buffer = [0u8; 1024];
        let n = stream.read(&mut buffer).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось прочитать ответ прокси: {}", e)))?;

        let response = String::from_utf8_lossy(&buffer[..n]);
        if !response.starts_with("HTTP/1.1 200") {
            return Err(VpnError::ConnectionError(format!("Прокси отклонил CONNECT-запрос: {}", response)));
        }

        Ok(HttpProxyConnection { stream })
    }
}

pub struct HttpProxyConnection {
    stream: TcpStream,
}

#[async_trait::async_trait]
impl Connection for HttpProxyConnection {
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        self.stream.write_all(packet).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось отправить данные через HTTP-прокси: {}", e)))
    }

    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        let mut buffer = vec![0u8; 65535];
        let n = self.stream.read(&mut buffer).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось получить данные через HTTP-прокси: {}", e)))?;
        buffer.truncate(n);
        Ok(buffer)
    }

    async fn close(&mut self) -> Result<(), VpnError> {
        self.stream.shutdown().await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось закрыть соединение: {}", e)))
    }
}
