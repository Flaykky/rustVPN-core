// src/connection/protocols/udp.rs

use std::{
    io,
    net::SocketAddr,
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    time::timeout,
};
use anyhow::{Result, Context};
use crate::utils::logging::{log, LogLevel};

pub struct UdpConnection {
    socket: UdpSocket,
    peer_addr: SocketAddr,
    timeout: Duration,
}

impl UdpConnection {
    /// Создание нового UDP-подключения
    pub async fn bind(
        local_addr: &SocketAddr,
        peer_addr: SocketAddr,
        timeout_duration: Duration,
    ) -> Result<Self> {
        log!(LogLevel::Info, "Binding UDP socket to {}", local_addr);
        
        let socket = UdpSocket::bind(local_addr)
            .await
            .context("Failed to bind UDP socket")?;
            
        socket.connect(peer_addr)
            .await
            .context("Failed to connect UDP socket")?;
            
        log!(LogLevel::Info, "UDP socket bound to {}", local_addr);
        Ok(Self {
            socket,
            peer_addr,
            timeout: timeout_duration,
        })
    }

    /// Отправка данных
    pub async fn send_to(&self, data: &[u8]) -> Result<usize> {
        log!(LogLevel::Debug, "Sending {} bytes to {}", data.len(), self.peer_addr);
        
        let sent = timeout(self.timeout, self.socket.send(data))
            .await
            .context("Send timed out")?
            .context("Failed to send data")?;
            
        Ok(sent)
    }

    /// Получение данных
    pub async fn recv_from(&self, buffer_size: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0; buffer_size];
        
        let received = timeout(self.timeout, self.socket.recv(&mut buffer))
            .await
            .context("Receive timed out")?
            .context("Failed to receive data")?;
            
        buffer.truncate(received);
        log!(LogLevel::Debug, "Received {} bytes from {}", received, self.peer_addr);
        Ok(buffer)
    }

    /// Закрытие соединения
    pub async fn close(self) -> Result<()> {
        log!(LogLevel::Info, "Closing UDP socket");
        self.socket.shutdown().await?;
        Ok(())
    }

    /// Получение локального адреса
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr()
            .context("Failed to get local address")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[tokio::test]
    async fn test_udp_communication() -> Result<()> {
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081);
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        // Запуск тестового сервера
        let server_socket = UdpSocket::bind(server_addr).await?;
        tokio::spawn(async move {
            let mut buf = [0; 5];
            loop {
                if let Ok((size, addr)) = server_socket.recv_from(&mut buf).await {
                    server_socket.send_to(&buf[..size], addr).await.unwrap();
                }
            }
        });

        // Тест клиента
        let conn = UdpConnection::bind(
            &client_addr,
            server_addr,
            Duration::from_secs(1)
        ).await?;

        conn.send_to(b"Hello").await?;
        let response = conn.recv_from(5).await?;
        assert_eq!(response, b"Hello");
        
        Ok(())
    }
}
