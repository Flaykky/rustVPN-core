use crate::utils::error::VpnError;
use crate::config::model::ServerConfig;
use crate::connection::protocols::{Protocol, Connection};
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;
use std::time::Duration;
use futures::future::BoxFuture;

/// Состояние соединения
#[derive(Debug, Clone, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Error(String),
}

/// Менеджер соединений
pub struct ConnectionManager {
    current_connection: Arc<Mutex<Option<Box<dyn Connection + Send + Sync>>>>,
    state: Arc<RwLock<ConnectionState>>,
    retry_count: u32,
    retry_delay: Duration,
}

impl ConnectionManager {
    /// Создает новый менеджер соединений
    pub fn new() -> Self {
        Self {
            current_connection: Arc::new(Mutex::new(None)),
            state: Arc::new(RwLock::new(ConnectionState::Disconnected)),
            retry_count: 3,
            retry_delay: Duration::from_secs(5),
        }
    }

    /// Устанавливает новое соединение
    pub async fn connect(&self, server_config: &ServerConfig) -> Result<(), VpnError> {
        let mut state = self.state.write().await;
        *state = ConnectionState::Connecting;

        // Создаем протокол
        let protocol = ProtocolFactory::create(server_config)?;
        
        // Подключаемся
        match protocol.connect().await {
            Ok(conn) => {
                let mut conn_lock = self.current_connection.lock().unwrap();
                *conn_lock = Some(conn);
                *state = ConnectionState::Connected;
                Ok(())
            },
            Err(e) => {
                *state = ConnectionState::Error(e.to_string());
                Err(e)
            }
        }
    }

    /// Отправляет пакет через текущее соединение
    pub async fn send_packet(&self, packet: &[u8]) -> Result<(), VpnError> {
        let conn = self.current_connection.lock().unwrap()
            .as_mut()
            .ok_or(VpnError::ConnectionError("Нет активного соединения".to_string()))?;
        conn.send_packet(packet).await
    }

    /// Получает пакет через текущее соединение
    pub async fn receive_packet(&self) -> Result<Vec<u8>, VpnError> {
        let conn = self.current_connection.lock().unwrap()
            .as_mut()
            .ok_or(VpnError::ConnectionError("Нет активного соединения".to_string()))?;
        conn.receive_packet().await
    }

    /// Закрывает текущее соединение
    pub async fn disconnect(&self) -> Result<(), VpnError> {
        let mut conn = self.current_connection.lock().unwrap();
        if let Some(ref mut connection) = *conn {
            connection.close().await?;
        }
        *conn = None;
        let mut state = self.state.write().await;
        *state = ConnectionState::Disconnected;
        Ok(())
    }

    /// Возвращает текущее состояние соединения
    pub async fn get_state(&self) -> ConnectionState {
        self.state.read().await.clone()
    }

    /// Автоматически переподключается при ошибке
    pub async fn auto_reconnect<F>(&self, server_config: &ServerConfig, on_reconnect: F)
        where F: Fn() + Send + Sync + 'static
    {
        let mut retries = 0;
        let mut state = self.state.write().await;
        *state = ConnectionState::Reconnecting;

        while retries < self.retry_count {
            match self.connect(server_config).await {
                Ok(_) => {
                    *state = ConnectionState::Connected;
                    on_reconnect();
                    return;
                },
                Err(e) => {
                    log::warn!("Попытка переподключения {} из {}: {}", retries + 1, self.retry_count, e);
                    retries += 1;
                    tokio::time::sleep(self.retry_delay).await;
                }
            }
        }

        *state = ConnectionState::Error("Не удалось переподключиться".to_string());
    }

    /// Устанавливает максимальное количество попыток переподключения
    pub fn set_retry_count(&mut self, count: u32) {
        self.retry_count = count;
    }

    /// Устанавливает задержку между попытками переподключения
    pub fn set_retry_delay(&mut self, delay: Duration) {
        self.retry_delay = delay;
    }
}
