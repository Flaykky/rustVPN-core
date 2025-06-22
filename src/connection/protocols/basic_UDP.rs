use crate::utils::error::VpnError;
use tokio::net::UdpSocket;
use std::net::SocketAddr;

// Предполагается, что Protocol и Connection определены в connection/protocols/mod.rs
use super::{Protocol, Connection};

/// Структура для базового UDP-протокола VPN.
pub struct BasicUdp {
    server_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl BasicUdp {
    /// Создает новый экземпляр `BasicUdp` с указанными локальным и серверным адресами.
    ///
    /// # Аргументы
    /// * `local_ip` - Локальный IP-адрес.
    /// * `local_port` - Локальный порт.
    /// * `server_ip` - IP-адрес сервера.
    /// * `server_port` - Порт сервера.
    pub fn new(local_ip: &str, local_port: u16, server_ip: &str, server_port: u16) -> Result<Self, VpnError> {
        let local_addr = format!("{}:{}", local_ip, local_port)
            .parse::<SocketAddr>()
            .map_err(|e| VpnError::ConfigError(format!("Неверный локальный адрес: {}", e)))?;
        let server_addr = format!("{}:{}", server_ip, server_port)
            .parse::<SocketAddr>()
            .map_err(|e| VpnError::ConfigError(format!("Неверный адрес сервера: {}", e)))?;
        Ok(Self { server_addr, local_addr })
    }
}

#[async_trait::async_trait]
impl Protocol for BasicUdp {
    type Connection = BasicUdpConnection;

    /// Создает UDP-сокет и подключается к серверу.
    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        let socket = UdpSocket::bind(self.local_addr)
            .await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось привязать сокет: {}", e)))?;
        socket
            .connect(self.server_addr)
            .await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось подключиться к серверу: {}", e)))?;
        Ok(BasicUdpConnection { socket })
    }
}

/// Структура для управления UDP-соединением.
pub struct BasicUdpConnection {
    socket: UdpSocket,
}

#[async_trait::async_trait]
impl Connection for BasicUdpConnection {
    /// Отправляет пакет через UDP-сокет.
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        if packet.len() > 65535 {
            return Err(VpnError::ProtocolError("Слишком большой пакет для UDP".to_string()));
        }
        self.socket
            .send(packet)
            .await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось отправить пакет: {}", e)))?;
        Ok(())
    }

    /// Получает пакет через UDP-сокет.
    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        let mut buffer = vec![0u8; 65535];
        let len = self.socket
            .recv(&mut buffer)
            .await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось получить пакет: {}", e)))?;
        buffer.truncate(len);
        Ok(buffer)
    }

    /// Закрывает UDP-соединение (освобождает сокет).
    async fn close(&mut self) -> Result<(), VpnError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_udp_connect() {
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server_socket.local_addr().unwrap();
        let protocol = BasicUdp::new("127.0.0.1", 0, "127.0.0.1", server_addr.port()).unwrap();
        let result = protocol.connect().await;
        assert!(result.is_ok());
    }
}
