//! Модуль для глобального управления состоянием приложения.
//! Отвечает за:
//! - Хранение текущего состояния VPN (подключен, отключен и т.д.).
//! - Информацию о текущем подключении (сервер, протокол, статистика).
//! - Предоставление потокобезопасного доступа к состоянию.
//! - Уведомление подписчиков об изменениях состояния.

use crate::utils::logging::{log_debug, log_info, log_warn};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{RwLock, watch};
use std::collections::HashMap;
use std::time::SystemTime;

/// Основные состояния VPN-подключения.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VpnConnectionState {
    /// Приложение запущено, но VPN не активен.
    Disconnected,
    /// Идет процесс подключения.
    Connecting,
    /// VPN активен и работает.
    Connected,
    /// Идет процесс отключения.
    Disconnecting,
    /// Произошла ошибка подключения или работы.
    Error(String),
}

/// Тип протокола подключения.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionProtocol {
    Tcp,
    Udp,
    WireGuard,
    Shadowsocks,
    HttpProxy,
    Socks5,
    Quic,
    Plugin(String), // Для пользовательских плагинов
}

/// Информация о текущем подключении.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Тег сервера из конфигурации.
    pub server_tag: String,
    /// Используемый протокол.
    pub protocol: ConnectionProtocol,
    /// Время установления соединения.
    pub connected_since: Option<SystemTime>,
    /// Статистика: отправлено байт.
    pub bytes_sent: u64,
    /// Статистика: получено байт.
    pub bytes_received: u64,
    /// Дополнительные метаданные (например, IP сервера, порт).
    #[serde(flatten)]
    pub metadata: HashMap<String, String>,
}

impl ConnectionInfo {
    /// Создает новую информацию о подключении.
    pub fn new(server_tag: String, protocol: ConnectionProtocol) -> Self {
        Self {
            server_tag,
            protocol,
            connected_since: Some(SystemTime::now()),
            bytes_sent: 0,
            bytes_received: 0,
            metadata: HashMap::new(),
        }
    }

    /// Обновляет статистику отправленных байт.
    pub fn add_bytes_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
    }

    /// Обновляет статистику полученных байт.
    pub fn add_bytes_received(&mut self, bytes: u64) {
        self.bytes_received += bytes;
    }

    /// Добавляет метаданные.
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Полное состояние ядра VPN-приложения.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalState {
    /// Текущее состояние подключения.
    pub connection_state: VpnConnectionState,
    /// Информация о текущем подключении (если есть).
    pub connection_info: Option<ConnectionInfo>,
    /// Версия приложения.
    pub version: String,
    /// Дополнительные пользовательские данные.
    #[serde(flatten)]
    pub custom_data: HashMap<String, String>,
}

impl GlobalState {
    /// Создает начальное состояние приложения.
    pub fn new(version: String) -> Self {
        log_debug!("Инициализация GlobalState, версия: {}", version);
        Self {
            connection_state: VpnConnectionState::Disconnected,
            connection_info: None,
            version,
            custom_data: HashMap::new(),
        }
    }

    /// Проверяет, активно ли VPN-подключение.
    pub fn is_connected(&self) -> bool {
        matches!(self.connection_state, VpnConnectionState::Connected)
    }

    /// Проверяет, идет ли процесс подключения/отключения.
    pub fn is_transitioning(&self) -> bool {
        matches!(
            self.connection_state,
            VpnConnectionState::Connecting | VpnConnectionState::Disconnecting
        )
    }

    /// Получает время работы текущего подключения в секундах.
    pub fn connection_uptime(&self) -> Option<u64> {
        if let Some(ref info) = self.connection_info {
            if let Some(connected_since) = info.connected_since {
                if let Ok(duration) = connected_since.elapsed() {
                    return Some(duration.as_secs());
                }
            }
        }
        None
    }

    /// Добавляет пользовательские данные.
    pub fn add_custom_data(&mut self, key: String, value: String) {
        self.custom_data.insert(key, value);
    }
}

/// Менеджер глобального состояния приложения.
pub struct StateManager {
    /// Текущее состояние, защищенное RwLock для многопоточного доступа.
    state: Arc<RwLock<GlobalState>>,
    /// Канал для уведомления подписчиков об изменениях состояния.
    state_notifier: watch::Sender<GlobalState>,
}

impl StateManager {
    /// Создает новый менеджер состояния.
    ///
    /// # Аргументы
    /// * `version` - Версия приложения.
    pub fn new(version: String) -> Self {
        let initial_state = GlobalState::new(version);
        let (state_notifier, _) = watch::channel(initial_state.clone());
        
        log_info!("Создан StateManager, начальное состояние: {:?}", initial_state.connection_state);
        
        Self {
            state: Arc::new(RwLock::new(initial_state)),
            state_notifier,
        }
    }

    /// Получает текущее состояние (для чтения).
    pub async fn get_state(&self) -> GlobalState {
        self.state.read().await.clone()
    }

    /// Получает текущее состояние с блокировкой на запись.
    /// Используется, когда нужно изменить состояние.
    async fn get_state_mut(&self) -> tokio::sync::RwLockWriteGuard<'_, GlobalState> {
        self.state.write().await
    }

    /// Подписывается на уведомления об изменениях состояния.
    pub fn subscribe(&self) -> watch::Receiver<GlobalState> {
        self.state_notifier.subscribe()
    }

    /// Устанавливает новое состояние подключения.
    pub async fn set_connection_state(&self, new_state: VpnConnectionState) {
        log_debug!("Изменение состояния подключения: {:?}", new_state);
        
        {
            let mut state = self.get_state_mut().await;
            state.connection_state = new_state.clone();
            
            // Если состояние "Disconnected", очищаем информацию о подключении
            if new_state == VpnConnectionState::Disconnected {
                state.connection_info = None;
            }
        }
        
        // Уведомить подписчиков
        self.notify_state_change().await;
    }

    /// Устанавливает информацию о текущем подключении.
    pub async fn set_connection_info(&self, info: ConnectionInfo) {
        log_debug!("Обновление информации о подключении для сервера: {}", info.server_tag);
        
        {
            let mut state = self.get_state_mut().await;
            state.connection_info = Some(info);
        }
        
        self.notify_state_change().await;
    }

    /// Обновляет статистику отправленных байт.
    pub async fn add_bytes_sent(&self, bytes: u64) {
        let mut state = self.get_state_mut().await;
        if let Some(ref mut info) = state.connection_info {
            info.add_bytes_sent(bytes);
        }
    }

    /// Обновляет статистику полученных байт.
    pub async fn add_bytes_received(&self, bytes: u64) {
        let mut state = self.get_state_mut().await;
        if let Some(ref mut info) = state.connection_info {
            info.add_bytes_received(bytes);
        }
    }

    /// Добавляет метаданные к текущему подключению.
    pub async fn add_connection_metadata(&self, key: String, value: String) {
        let mut state = self.get_state_mut().await;
        if let Some(ref mut info) = state.connection_info {
            info.add_metadata(key, value);
        }
    }

    /// Добавляет пользовательские данные в глобальное состояние.
    pub async fn add_custom_data(&self, key: String, value: String) {
        log_debug!("Добавление пользовательских данных: {} = {}", key, value);
        {
            let mut state = self.get_state_mut().await;
            state.add_custom_data(key, value);
        }
        self.notify_state_change().await;
    }

    /// Сбрасывает состояние в "отключено".
    pub async fn reset_to_disconnected(&self) {
        log_info!("Сброс состояния в Disconnected");
        self.set_connection_state(VpnConnectionState::Disconnected).await;
    }

    /// Внутренний метод для уведомления подписчиков об изменении состояния.
    async fn notify_state_change(&self) {
        let current_state = self.state.read().await.clone();
        if let Err(e) = self.state_notifier.send(current_state) {
            log_warn!("Не удалось уведомить подписчиков об изменении состояния: {}", e);
        }
    }
}

// Реализация Default для удобства
impl Default for StateManager {
    fn default() -> Self {
        Self::new(env!("CARGO_PKG_VERSION").to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_state_manager_creation() {
        let manager = StateManager::new("1.0.0-test".to_string());
        let state = manager.get_state().await;
        assert_eq!(state.connection_state, VpnConnectionState::Disconnected);
        assert_eq!(state.version, "1.0.0-test");
    }

    #[tokio::test]
    async fn test_connection_state_transitions() {
        let manager = StateManager::new("1.0.0-test".to_string());
        
        // Подписываемся на изменения
        let mut receiver = manager.subscribe();
        
        // Изменяем состояние на Connecting
        manager.set_connection_state(VpnConnectionState::Connecting).await;
        let state = manager.get_state().await;
        assert_eq!(state.connection_state, VpnConnectionState::Connecting);
        
        // Проверяем уведомление
        let notified_state = timeout(Duration::from_millis(100), receiver.changed())
            .await
            .expect("Таймаут ожидания уведомления")
            .expect("Ошибка получения уведомления");
        assert_eq!(notified_state.connection_state, VpnConnectionState::Connecting);
        
        // Изменяем состояние на Connected
        let mut info = ConnectionInfo::new("test_server".to_string(), ConnectionProtocol::Tcp);
        info.add_metadata("server_ip".to_string(), "127.0.0.1".to_string());
        manager.set_connection_info(info).await;
        manager.set_connection_state(VpnConnectionState::Connected).await;
        
        let state = manager.get_state().await;
        assert_eq!(state.connection_state, VpnConnectionState::Connected);
        assert!(state.connection_info.is_some());
        assert_eq!(state.connection_info.as_ref().unwrap().server_tag, "test_server");
    }

    #[tokio::test]
    async fn test_connection_info_and_stats() {
        let manager = StateManager::new("1.0.0-test".to_string());
        
        let mut info = ConnectionInfo::new("stats_test".to_string(), ConnectionProtocol::Udp);
        info.add_bytes_sent(1024);
        info.add_bytes_received(2048);
        info.add_metadata("test_key".to_string(), "test_value".to_string());
        
        manager.set_connection_info(info).await;
        manager.set_connection_state(VpnConnectionState::Connected).await;
        
        // Обновляем статистику
        manager.add_bytes_sent(512).await;
        manager.add_bytes_received(1024).await;
        
        let state = manager.get_state().await;
        let info = state.connection_info.as_ref().unwrap();
        assert_eq!(info.bytes_sent, 1536);
        assert_eq!(info.bytes_received, 3072);
        assert_eq!(info.metadata.get("test_key"), Some(&"test_value".to_string()));
    }

    #[tokio::test]
    async fn test_reset_to_disconnected() {
        let manager = StateManager::new("1.0.0-test".to_string());
        
        let info = ConnectionInfo::new("to_be_reset".to_string(), ConnectionProtocol::Tcp);
        manager.set_connection_info(info).await;
        manager.set_connection_state(VpnConnectionState::Connected).await;
        
        assert!(manager.get_state().await.connection_info.is_some());
        
        manager.reset_to_disconnected().await;
        
        let state = manager.get_state().await;
        assert_eq!(state.connection_state, VpnConnectionState::Disconnected);
        assert!(state.connection_info.is_none());
    }

    #[tokio::test]
    async fn test_custom_data() {
        let manager = StateManager::new("1.0.0-test".to_string());
        
        manager.add_custom_data("user_id".to_string(), "12345".to_string()).await;
        manager.add_custom_data("session_token".to_string(), "abcde12345".to_string()).await;
        
        let state = manager.get_state().await;
        assert_eq!(state.custom_data.get("user_id"), Some(&"12345".to_string()));
        assert_eq!(state.custom_data.get("session_token"), Some(&"abcde12345".to_string()));
    }

    #[tokio::test]
    async fn test_connection_uptime() {
        let manager = StateManager::new("1.0.0-test".to_string());
        
        // Проверяем, что uptime None, когда нет подключения
        assert!(manager.get_state().await.connection_uptime().is_none());
        
        // Устанавливаем подключение
        let info = ConnectionInfo::new("uptime_test".to_string(), ConnectionProtocol::Tcp);
        manager.set_connection_info(info).await;
        manager.set_connection_state(VpnConnectionState::Connected).await;
        
        // Ждем немного
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Проверяем uptime
        let uptime = manager.get_state().await.connection_uptime().unwrap();
        assert!(uptime >= 0);
        // Не проверяем точное значение, так как это зависит от времени выполнения теста
    }
}
