use crate::utils::error::VpnError;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use super::super::super::super::super::{Protocol, Connection};

pub struct Socks5Proxy {
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
    username: Option<String>,
    password: Option<String>,
}

impl Socks5Proxy {
    pub fn new(
        proxy_ip: &str, 
        proxy_port: u16, 
        target_ip: &str, 
        target_port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> Result<Self, VpnError> {
        let proxy_addr = format!("{}:{}", proxy_ip, proxy_port)
            .parse::<SocketAddr>()
            .map_err(|e| VpnError::ConfigError(format!("Неверный адрес прокси: {}", e)))?;
        let target_addr = format!("{}:{}", target_ip, target_port)
            .parse::<SocketAddr>()
            .map_err(|e| VpnError::ConfigError(format!("Неверный адрес цели: {}", e)))?;
        Ok(Self { proxy_addr, target_addr, username, password })
    }
}

#[async_trait::async_trait]
impl Protocol for Socks5Proxy {
    type Connection = Socks5ProxyConnection;

    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        let mut stream = TcpStream::connect(self.proxy_addr).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось подключиться к прокси: {}", e)))?;

        // Authentication negotiation
        let mut auth_methods = vec![0x00]; // NO AUTH
        if self.username.is_some() && self.password.is_some() {
            auth_methods.push(0x02); // USERNAME/PASSWORD
        }

        let mut request = vec![0x05]; // Version
        request.push(auth_methods.len() as u8);
        request.extend_from_slice(&auth_methods);

        stream.write_all(&request).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось отправить запрос аутентификации SOCKS5: {}", e)))?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось прочитать ответ аутентификации SOCKS5: {}", e)))?;

        if response[1] == 0x02 { // Need auth
            if let (Some(user), Some(pass)) = (&self.username, &self.password) {
                let mut auth_request = vec![0x01, user.len() as u8];
                auth_request.extend_from_slice(user.as_bytes());
                auth_request.push(pass.len() as u8);
                auth_request.extend_from_slice(pass.as_bytes());

                stream.write_all(&auth_request).await
                    .map_err(|e| VpnError::ConnectionError(format!("Не удалось отправить учетные данные SOCKS5: {}", e)))?;

                let mut auth_response = [0u8; 2];
                stream.read_exact(&mut auth_response).await
                    .map_err(|e| VpnError::ConnectionError(format!("Не удалось прочитать ответ проверки подлинности SOCKS5: {}", e)))?;

                if auth_response[1] != 0x00 {
                    return Err(VpnError::ConnectionError("SOCKS5: Ошибка аутентификации".to_string()));
                }
            } else {
                return Err(VpnError::ConnectionError("SOCKS5: Требуется аутентификация, но учетные данные не предоставлены".to_string()));
            }
        } else if response[1] != 0x00 { // No auth supported
            return Err(VpnError::ConnectionError("SOCKS5: Не поддерживается метод аутентификации".to_string()));
        }

        // Connect to target
        let ip = match self.target_addr.ip() {
            std::net::IpAddr::V4(ip) => {
                let octets = ip.octets();
                vec![0x01, octets[0], octets[1], octets[2], octets[3]]
            },
            std::net::IpAddr::V6(ip) => {
                let segments = ip.segments();
                let mut v = vec![0x04];
                for seg in segments {
                    v.push((seg >> 8) as u8);
                    v.push(seg as u8);
                }
                v
            }
        };
        let port = self.target_addr.port().to_be_bytes();

        let mut connect_request = vec![0x05, 0x01, 0x00]; // Version, CMD CONNECT, RSV
        connect_request.extend_from_slice(&ip);
        connect_request.extend_from_slice(&port);

        stream.write_all(&connect_request).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось отправить запрос подключения SOCKS5: {}", e)))?;

        let mut connect_response = [0u8; 10];
        stream.read_exact(&mut connect_response).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось прочитать ответ подключения SOCKS5: {}", e)))?;

        if connect_response[1] != 0x00 { // Success
            return Err(VpnError::ConnectionError("SOCKS5: Не удалось установить соединение с целевым сервером".to_string()));
        }

        Ok(Socks5ProxyConnection { stream })
    }
}

pub struct Socks5ProxyConnection {
    stream: TcpStream,
}

#[async_trait::async_trait]
impl Connection for Socks5ProxyConnection {
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        self.stream.write_all(packet).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось отправить данные через SOCKS5-прокси: {}", e)))
    }

    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        let mut buffer = vec![0u8; 65535];
        let n = self.stream.read(&mut buffer).await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось получить данные через SOCKS5-прокси: {}", e)))?;
        buffer.truncate(n);
        Ok(buffer)
    }

    async fn close(&mut self) -> Result<(), VpnError> {
        self.stream.shutdown().await
            .map_err(|e| VpnError::ConnectionError(format!("Не удалось закрыть соединение: {}", e)))
    }
}
