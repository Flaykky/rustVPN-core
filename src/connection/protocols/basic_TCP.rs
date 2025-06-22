use crate::utils::error::VpnError;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;

// Предполагается, что Protocol и Connection определены в connection/protocols/mod.rs
use super::{Protocol, Connection};

/// Структура для базового TCP-протокола VPN.
pub struct BasicTcp {
    server_addr: SocketAddr,
}

impl BasicTcp {
    /// Создает новый экземпляр `BasicTcp` с указанным адресом сервера.
    ///
    /// # Аргументы
    /// * `server_ip` - IP-адрес сервера.
    /// * `server_port` - Порт сервера.
    pub fn new(server_ip: &str, server_port: u16) -> Result<Self, VpnError> {
        let server_addr = format!("{}:{}", server_ip, server_port)
            .parse::<SocketAddr>()
            .map_err(|e| VpnError::ConfigError(format!("Неверный адрес сервера: {}", e)))?;
        Ok(Self { server_addr })
    }
}

#[async_trait::async_trait]
impl Protocol for BasicTcp {
    type Connection = BasicTcpConnection;

    /// Устанавливает TCP-соединение с сервером.
    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        let stream = TcpStream::connect(self.server_addr)
            .await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось подключиться: {}", e)))?;
        stream
            .set_nodelay(true)
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось установить TCP_NODELAY: {}", e)))?;
        Ok(BasicTcpConnection { stream })
    }
}

/// Структура для управления TCP-соединением.
pub struct BasicTcpConnection {
    stream: TcpStream,
}

#[async_trait::async_trait]
impl Connection for BasicTcpConnection {
    /// Отправляет пакет через TCP-соединение с фреймингом (длина пакета перед данными).
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        let len = packet.len() as u32;
        self.stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось отправить длину пакета: {}", e)))?;
        self.stream
            .write_all(packet)
            .await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось отправить пакет: {}", e)))?;
        self.stream
            .flush()
            .await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось сбросить буфер: {}", e)))?;
        Ok(())
    }

    /// Получает пакет через TCP-соединение, сначала читая длину.
    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        let mut len_buf = [0u8; 4];
        self.stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось прочитать длину пакета: {}", e)))?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > 65535 {
            return Err(VpnError::ProtocolError("Слишком большой пакет".to_string()));
        }
        let mut packet = vec![0u8; len];
        self.stream
            .read_exact(&mut packet)
            .await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось прочитать пакет: {}", e)))?;
        Ok(packet)
    }

    /// Закрывает TCP-соединение.
    async fn close(&mut self) -> Result<(), VpnError> {
        self.stream
            .shutdown()
            .await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось закрыть соединение: {}", e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_tcp_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let protocol = BasicTcp::new("127.0.0.1", addr.port()).unwrap();
        let result = protocol.connect().await;
        assert!(result.is_ok());
    }
}
