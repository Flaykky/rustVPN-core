
use std::{
    io,
    net::SocketAddr,
    time::Duration,
};
use tokio::{
    net::TcpStream,
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use anyhow::{Result, Context};
use crate::utils::logging::{log, LogLevel};

pub struct TcpConnection {
    stream: TcpStream,
    peer_addr: SocketAddr,
    timeout: Duration,
}

impl TcpConnection {
    /// Создание нового TCP-соединения
    pub async fn connect(
        addr: &SocketAddr,
        timeout_duration: Duration,
    ) -> Result<Self> {
        log!(LogLevel::Info, "Connecting to {}", addr);
        
        let stream = timeout(timeout_duration, TcpStream::connect(addr))
            .await
            .context("Connection timed out")?
            .context("Failed to connect")?;
            
        stream.set_nodelay(true)?;
        let peer_addr = stream.peer_addr()?;
        
        log!(LogLevel::Info, "Connected to {}", peer_addr);
        Ok(Self {
            stream,
            peer_addr,
            timeout: timeout_duration,
        })
    }

    /// Отправка данных
    pub async fn send(&mut self, data: &[u8]) -> Result<usize> {
        log!(LogLevel::Debug, "Sending {} bytes to {}", data.len(), self.peer_addr);
        
        let write_result = timeout(self.timeout, self.stream.write(data))
            .await
            .context("Write timed out")?
            .context("Failed to write data")?;
            
        Ok(write_result)
    }

    /// Получение данных
    pub async fn receive(&mut self, buffer_size: usize) -> Result<Vec<u8>> {
        let mut buffer = vec![0; buffer_size];
        
        let read_bytes = timeout(self.timeout, self.stream.read(&mut buffer))
            .await
            .context("Read timed out")?
            .context("Failed to read data")?;
            
        buffer.truncate(read_bytes);
        log!(LogLevel::Debug, "Received {} bytes from {}", read_bytes, self.peer_addr);
        Ok(buffer)
    }

    /// Закрытие соединения
    pub async fn close(self) -> Result<()> {
        log!(LogLevel::Info, "Closing connection to {}", self.peer_addr);
        self.stream.shutdown().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_tcp_connection() -> Result<()> {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        
        // Запуск тестового сервера
        let listener = TcpListener::bind(addr).await?;
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0; 5];
            socket.read_exact(&mut buf).await.unwrap();
            socket.write_all(b"world").await.unwrap();
        });

        // Тест клиента
        let mut conn = TcpConnection::connect(&addr, Duration::from_secs(1)).await?;
        conn.send(b"hello").await?;
        let response = conn.receive(5).await?;
        assert_eq!(response, b"world");
        Ok(())
    }
}
