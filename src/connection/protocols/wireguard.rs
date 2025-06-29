use crate::utils::logging::{log_debug, log_info, log_warn};
use crate::utils::error::VpnError;
use tokio::net::UdpSocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use boringtun::noise::{Tunn, TunnConfig, TunnResult};
use std::net::SocketAddr;
use super::{Protocol, Connection};
use tokio::net::lookup_host;
use base64::Engine;

pub struct WireGuardConfig {
    private_key: String,
    peer_public_key: String,
    endpoint: String,
}

impl WireGuardConfig {
    pub fn new(private_key: &str, peer_public_key: &str, endpoint: &str) -> Self {
        Self {
            private_key: private_key.to_string(),
            peer_public_key: peer_public_key.to_string(),
            endpoint: endpoint.to_string(),
        }
    }
}

pub struct WireGuard {
    config: WireGuardConfig,
}

impl WireGuard {
    pub fn new(config: WireGuardConfig) -> Result<Self, VpnError> {
        log_info!("Инициализация WireGuard с конечной точкой {}", config.endpoint);
        if config.private_key.is_empty() || config.peer_public_key.is_empty() || config.endpoint.is_empty() {
            log_warn!("Недопустимая конфигурация WireGuard: пустые поля");
            return Err(VpnError::ConfigError("Недопустимая конфигурация WireGuard".to_string()));
        }
        Ok(Self { config })
    }
}

#[async_trait::async_trait]
impl Protocol for WireGuard {
    type Connection = WireGuardConnection;

    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        log_info!("Подключение к WireGuard пиру на {}", self.config.endpoint);
        
        // Декодирование ключей
        let private_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.config.private_key)
            .map_err(|e| {
                log_warn!("Ошибка декодирования приватного ключа: {}", e);
                VpnError::ConfigError(format!("Неверный формат приватного ключа: {}", e))
            })?;

        let public_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.config.peer_public_key)
            .map_err(|e| {
                log_warn!("Ошибка декодирования публичного ключа: {}", e);
                VpnError::ConfigError(format!("Неверный формат публичного ключа: {}", e))
            })?;

        // Резолвинг DNS
        let endpoint_str = self.config.endpoint.clone();
        let mut addrs = lookup_host(endpoint_str).await.map_err(|e| {
            log_warn!("Ошибка резолва DNS для {}: {}", self.config.endpoint, e);
            VpnError::ConfigError(format!("Не удалось разрешить адрес: {}", e))
        })?;

        let endpoint = addrs.next().ok_or_else(|| {
            log_warn!("Не найден адрес для {}", self.config.endpoint);
            VpnError::ConfigError("Не найден адрес для конечной точки".to_string())
        })?;

        // Создание UDP-сокета
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            log_warn!("Ошибка привязки UDP-сокета: {}", e);
            VpnError::ConnectionError(format!("Не удалось привязать сокет: {}", e))
        })?;

        // Инициализация Tunn
        let tunn_config = TunnConfig {
            private_key: Some(private_key_bytes),
            peer_public_key: Some(public_key_bytes),
            index: 0,
            seq_number: 0,
            remote_endpoint: Some(endpoint),
            preshared_key: None,
            platform_impl: Default::default(),
        };

        let tun = Tunn::new(tunn_config).map_err(|e| {
            log_warn!("Ошибка инициализации туннеля: {:?}", e);
            VpnError::ConnectionError("Ошибка инициализации туннеля".to_string())
        })?;

        log_info!("Успешно подключено к WireGuard пиру на {}", self.config.endpoint);
        Ok(WireGuardConnection { tun, socket })
    }
}

pub struct WireGuardConnection {
    tun: Tunn,
    socket: UdpSocket,
}

#[async_trait::async_trait]
impl Connection for WireGuardConnection {
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        let mut out_buffer = [0u8; 65536];
        match self.tun.encapsulate(packet, &mut out_buffer) {
            TunnResult::WriteToNetwork(encrypted) => {
                self.socket.send(encrypted).await.map_err(|e| {
                    log_warn!("Ошибка отправки пакета: {}", e);
                    VpnError::ConnectionError(format!("Не удалось отправить пакет: {}", e))
                })?;
                log_debug!("Пакет отправлен через WireGuard");
            }
            TunnResult::Err(e) => {
                log_warn!("Ошибка шифрования пакета: {:?}", e);
                return Err(VpnError::ProtocolError("Ошибка шифрования пакета".to_string()));
            }
            _ => {} // Игнорируем другие случаи для упрощения
        }
        Ok(())
    }

    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        let mut buffer = [0u8; 65536];
        let size = self.socket.recv(&mut buffer).await.map_err(|e| {
            log_warn!("Ошибка получения пакета: {}", e);
            VpnError::ConnectionError(format!("Не удалось получить пакет: {}", e))
        })?;

        let mut out_buffer = [0u8; 65536];
        match self.tun.decapsulate(None, &buffer[..size], &mut out_buffer) {
            TunnResult::Ready { plaintext, .. } => {
                log_debug!("Пакет получен через WireGuard");
                Ok(plaintext.to_vec())
            }
            TunnResult::Err(e) => {
                log_warn!("Ошибка расшифровки пакета: {:?}", e);
                Err(VpnError::ProtocolError("Ошибка расшифровки пакета".to_string()))
            }
            _ => Err(VpnError::ProtocolError("Пустой пакет".to_string()))
        }
    }

    async fn close(&mut self) -> Result<(), VpnError> {
        log_info!("Закрытие соединения WireGuard");
        self.socket.shutdown().await.map_err(|e| {
            log_warn!("Ошибка завершения соединения: {}", e);
            VpnError::ConnectionError(format!("Не удалось завершить соединение: {}", e))
        })?;
        Ok(())
    }
}
