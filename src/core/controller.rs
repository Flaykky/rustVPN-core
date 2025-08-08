//! Основной контроллер VPN-приложения.
//! Отвечает за:
//! - Инициализацию и управление подключениями.
//! - Координацию между различными компонентами (config, connection, obfuscation, encryption).
//! - Предоставление API для внешнего взаимодействия (CLI, GUI и т.д.).

use crate::utils::logging::{log_debug, log_info, log_warn, log_error};
use crate::utils::error::VpnError;
use crate::config::model::{Config, ServerConfig};
use crate::connection::protocols::{ProtocolFactory, Protocol, Connection};
// Предполагается, что ConnectionManager из предыдущего примера или аналогичный тип существует
// Если нет, можно использовать Protocol/Connection напрямую
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::sleep;

/// Состояние контроллера.
#[derive(Debug, Clone, PartialEq)]
pub enum ControllerState {
    Idle,
    Initializing,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
    Error(String),
}

/// Основной контроллер VPN-приложения.
pub struct VpnController {
    /// Текущее состояние контроллера.
    state: Arc<RwLock<ControllerState>>,
    /// Активное соединение (если есть).
    active_connection: Arc<Mutex<Option<Box<dyn Connection + Send + Sync>>>>,
    /// Загруженная конфигурация.
    config: Arc<RwLock<Option<Config>>>,
    /// Таймаут для операций подключения/отключения.
    operation_timeout: Duration,
}

impl VpnController {
    /// Создает новый экземпляр `VpnController`.
    pub fn new() -> Self {
        log_info!("Инициализация VpnController");
        Self {
            state: Arc::new(RwLock::new(ControllerState::Idle)),
            active_connection: Arc::new(Mutex::new(None)),
            config: Arc::new(RwLock::new(None)),
            operation_timeout: Duration::from_secs(30), // Таймаут по умолчанию 30 секунд
        }
    }

    /// Устанавливает таймаут для операций подключения/отключения.
    pub fn set_operation_timeout(&mut self, timeout: Duration) {
        self.operation_timeout = timeout;
        log_debug!("Установлен таймаут операций: {:?}", timeout);
    }

    /// Загружает конфигурацию в контроллер.
    pub async fn load_config(&self, config: Config) -> Result<(), VpnError> {
        log_info!("Загрузка конфигурации в контроллер");
        let mut config_guard = self.config.write().await;
        *config_guard = Some(config);
        log_debug!("Конфигурация успешно загружена");
        Ok(())
    }

    /// Получает список доступных серверов из загруженной конфигурации.
    pub async fn list_servers(&self) -> Result<Vec<String>, VpnError> {
        let config_guard = self.config.read().await;
        if let Some(ref config) = *config_guard {
            let server_names: Vec<String> = config.0.keys().cloned().collect();
            log_debug!("Получен список серверов: {:?}", server_names);
            Ok(server_names)
        } else {
            log_warn!("Конфигурация не загружена, невозможно получить список серверов");
            Err(VpnError::config_error("Конфигурация не загружена"))
        }
    }

    /// Подключается к указанному серверу по его тегу.
    pub async fn connect(&self, server_tag: &str) -> Result<(), VpnError> {
        log_info!("Попытка подключения к серверу: {}", server_tag);
        
        // 1. Проверить состояние
        {
            let current_state = self.state.read().await.clone();
            if current_state != ControllerState::Idle && current_state != ControllerState::Disconnected {
                log_warn!("Невозможно подключиться: контроллер находится в состоянии {:?}", current_state);
                return Err(VpnError::connection_error("Контроллер занят или уже подключен"));
            }
        }

        // 2. Установить состояние в Connecting
        {
            let mut state_guard = self.state.write().await;
            *state_guard = ControllerState::Connecting;
        }
        log_debug!("Состояние контроллера изменено на Connecting");

        // 3. Получить конфигурацию сервера
        let server_config = {
            let config_guard = self.config.read().await;
            if let Some(ref config) = *config_guard {
                config.0.get(server_tag).cloned()
                .ok_or_else(|| {
                    log_error!("Сервер с тегом '{}' не найден в конфигурации", server_tag);
                    VpnError::config_error(format!("Сервер '{}' не найден", server_tag))
                })?
            } else {
                log_error!("Конфигурация не загружена");
                return Err(VpnError::config_error("Конфигурация не загружена"));
            }
        };

        // 4. Создать протокол
        let protocol: Box<dyn Protocol<Connection = dyn Connection>> = ProtocolFactory::create(&server_config)
            .map_err(|e| {
                log_error!("Ошибка создания протокола для сервера '{}': {}", server_tag, e);
                // Вернуть в состояние Idle при ошибке создания протокола
                let state_clone = Arc::clone(&self.state);
                tokio::spawn(async move {
                    let mut state_guard = state_clone.write().await;
                    *state_guard = ControllerState::Error(format!("Ошибка создания протокола: {}", e));
                });
                e
            })?;

        // 5. Подключиться
        log_debug!("Создание подключения через протокол...");
        let connection = tokio::time::timeout(self.operation_timeout, protocol.connect())
            .await
            .map_err(|_| {
                log_error!("Таймаут при подключении к серверу '{}'", server_tag);
                VpnError::connection_error("Таймаут подключения")
            })?
            .map_err(|e| {
                log_error!("Ошибка подключения к серверу '{}': {}", server_tag, e);
                // Вернуть в состояние Error при ошибке подключения
                let state_clone = Arc::clone(&self.state);
                let error_msg = e.to_string();
                tokio::spawn(async move {
                    let mut state_guard = state_clone.write().await;
                    *state_guard = ControllerState::Error(error_msg);
                });
                e
            })?;

        // 6. Сохранить соединение и обновить состояние
        {
            let mut conn_guard = self.active_connection.lock().await;
            *conn_guard = Some(connection);
        }
        {
            let mut state_guard = self.state.write().await;
            *state_guard = ControllerState::Connected;
        }
        log_info!("Успешно подключено к серверу: {}", server_tag);
        Ok(())
    }

    /// Отключается от текущего сервера.
    pub async fn disconnect(&self) -> Result<(), VpnError> {
        log_info!("Попытка отключения от текущего сервера");
        
        // 1. Проверить состояние
        {
            let current_state = self.state.read().await.clone();
            if current_state != ControllerState::Connected {
                log_warn!("Невозможно отключиться: контроллер не в состоянии Connected (текущее состояние: {:?})", current_state);
                return Err(VpnError::connection_error("Нет активного подключения"));
            }
        }

        // 2. Установить состояние в Disconnecting
        {
            let mut state_guard = self.state.write().await;
            *state_guard = ControllerState::Disconnecting;
        }
        log_debug!("Состояние контроллера изменено на Disconnecting");

        // 3. Закрыть активное соединение
        let close_result = {
            let mut conn_guard = self.active_connection.lock().await;
            if let Some(mut connection) = conn_guard.take() {
                log_debug!("Закрытие активного соединения...");
                tokio::time::timeout(self.operation_timeout, connection.close())
                    .await
                    .map_err(|_| {
                        log_error!("Таймаут при закрытии соединения");
                        VpnError::connection_error("Таймаут закрытия соединения")
                    })?
                    .map_err(|e| {
                        log_error!("Ошибка закрытия соединения: {}", e);
                        e
                    })
            } else {
                log_warn!("Активное соединение отсутствует при попытке отключения");
                Ok(())
            }
        };

        // 4. Обновить состояние в зависимости от результата
        {
            let mut state_guard = self.state.write().await;
            match close_result {
                Ok(()) => {
                    *state_guard = ControllerState::Disconnected;
                    log_info!("Успешно отключено от сервера");
                }
                Err(e) => {
                    *state_guard = ControllerState::Error(format!("Ошибка отключения: {}", e));
                    log_error!("Не удалось корректно отключиться: {}", e);
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Отправляет пакет через активное соединение.
    pub async fn send_packet(&self, packet: &[u8]) -> Result<(), VpnError> {
        log_debug!("Отправка пакета размером {} байт", packet.len());
        
        let current_state = self.state.read().await.clone();
        if current_state != ControllerState::Connected {
            log_warn!("Невозможно отправить пакет: контроллер не подключен (состояние: {:?})", current_state);
            return Err(VpnError::connection_error("Нет активного подключения"));
        }

        let mut conn_guard = self.active_connection.lock().await;
        if let Some(ref mut connection) = *conn_guard {
            connection.send_packet(packet).await
                .map_err(|e| {
                    log_error!("Ошибка отправки пакета: {}", e);
                    // При ошибке отправки можно перейти в состояние Error
                    let state_clone = Arc::clone(&self.state);
                    let error_msg = e.to_string();
                    tokio::spawn(async move {
                        let mut state_guard = state_clone.write().await;
                        *state_guard = ControllerState::Error(error_msg);
                    });
                    e
                })
        } else {
            log_error!("Активное соединение отсутствует при попытке отправки пакета");
            Err(VpnError::connection_error("Активное соединение отсутствует"))
        }
    }

    /// Получает пакет через активное соединение.
    pub async fn receive_packet(&self) -> Result<Vec<u8>, VpnError> {
        log_debug!("Ожидание получения пакета...");
        
        let current_state = self.state.read().await.clone();
        if current_state != ControllerState::Connected {
            log_warn!("Невозможно получить пакет: контроллер не подключен (состояние: {:?})", current_state);
            return Err(VpnError::connection_error("Нет активного подключения"));
        }

        let mut conn_guard = self.active_connection.lock().await;
        if let Some(ref mut connection) = *conn_guard {
            connection.receive_packet().await
                .map_err(|e| {
                    log_error!("Ошибка получения пакета: {}", e);
                    // При ошибке получения можно перейти в состояние Error
                    let state_clone = Arc::clone(&self.state);
                    let error_msg = e.to_string();
                    tokio::spawn(async move {
                        let mut state_guard = state_clone.write().await;
                        *state_guard = ControllerState::Error(error_msg);
                    });
                    e
                })
        } else {
            log_error!("Активное соединение отсутствует при попытке получения пакета");
            Err(VpnError::connection_error("Активное соединение отсутствует"))
        }
    }

    /// Получает текущее состояние контроллера.
    pub async fn get_state(&self) -> ControllerState {
        self.state.read().await.clone()
    }

    /// Сбрасывает контроллер в начальное состояние (Idle).
    pub async fn reset(&self) -> Result<(), VpnError> {
        log_info!("Сброс контроллера в начальное состояние");
        
        // Если есть активное соединение, попытаться корректно закрыть его
        let current_state = self.state.read().await.clone();
        if current_state == ControllerState::Connected {
            log_debug!("Обнаружено активное соединение, выполняется отключение...");
            self.disconnect().await?;
            // Даем немного времени на завершение операции
            sleep(Duration::from_millis(100)).await;
        }
        
        // Очищаем активное соединение
        {
            let mut conn_guard = self.active_connection.lock().await;
            *conn_guard = None;
        }
        
        // Сбрасываем конфигурацию
        {
            let mut config_guard = self.config.write().await;
            *config_guard = None;
        }
        
        // Устанавливаем состояние Idle
        {
            let mut state_guard = self.state.write().await;
            *state_guard = ControllerState::Idle;
        }
        
        log_info!("Контроллер успешно сброшен");
        Ok(())
    }
}

// Реализация Default для удобства создания
impl Default for VpnController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::loader::ConfigLoader;
    use tokio::time::timeout;

    const TEST_CONFIG_STR: &str = r#"{
        "test_server": {
            "tag": "test_server",
            "protocol": "tcp",
            "server_ip": "127.0.0.1",
            "server_port": 8080
        }
    }"#;

    #[tokio::test]
    async fn test_controller_creation() {
        let controller = VpnController::new();
        let state = controller.get_state().await;
        assert_eq!(state, ControllerState::Idle);
    }

    #[tokio::test]
    async fn test_load_config() {
        let controller = VpnController::new();
        let config = ConfigLoader::load_from_json_str(TEST_CONFIG_STR).unwrap();
        let result = controller.load_config(config).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_list_servers() {
        let controller = VpnController::new();
        let config = ConfigLoader::load_from_json_str(TEST_CONFIG_STR).unwrap();
        controller.load_config(config).await.unwrap();
        let servers = controller.list_servers().await.unwrap();
        assert_eq!(servers, vec!["test_server"]);
    }

    #[tokio::test]
    async fn test_connect_disconnect_flow() {
        let controller = VpnController::new();
        // Для полноценного теста подключения нужен запущенный сервер
        // Здесь просто проверим логику состояний и ошибок
        
        // Попытка подключения без конфига
        let result = controller.connect("nonexistent").await;
        assert!(result.is_err());
        
        // Загрузим конфиг
        let config = ConfigLoader::load_from_json_str(TEST_CONFIG_STR).unwrap();
        controller.load_config(config).await.unwrap();
        
        // Попытка подключения к несуществующему серверу
        let result = controller.connect("nonexistent").await;
        assert!(result.is_err());
        
        // Попытка подключения к существующему серверу (но реального подключения не будет)
        // Это покажет, что логика работает, но физически подключение упадет с ошибкой
        let connect_result = timeout(Duration::from_secs(5), controller.connect("test_server")).await;
        // В любом случае, мы проверили, что метод вызывается корректно
        // Фактический результат зависит от доступности сервера
        match connect_result {
            Ok(Err(_)) => {
                // Ожидаем ошибку подключения, так как сервер 127.0.0.1:8080 не запущен
                let final_state = controller.get_state().await;
                // Состояние должно быть Error после неудачной попытки подключения
                match final_state {
                    ControllerState::Error(_) => {}, // ОК
                    _ => panic!("Ожидалось состояние Error после неудачного подключения, получено: {:?}", final_state)
                }
            },
            Ok(Ok(_)) => panic!("Неожиданный успешный результат подключения в тесте без реального сервера"),
            Err(_) => panic!("Таймаут при попытке подключения")
        }
    }

    #[tokio::test]
    async fn test_reset() {
        let controller = VpnController::new();
        let config = ConfigLoader::load_from_json_str(TEST_CONFIG_STR).unwrap();
        controller.load_config(config).await.unwrap();
        
        // Сброс в состоянии Idle
        let result = controller.reset().await;
        assert!(result.is_ok());
        let state = controller.get_state().await;
        assert_eq!(state, ControllerState::Idle);
        
        // Загрузим конфиг снова
        let config = ConfigLoader::load_from_json_str(TEST_CONFIG_STR).unwrap();
        controller.load_config(config).await.unwrap();
        
        // Имитируем подключение (без реального подключения)
        {
            let mut state_guard = controller.state.write().await;
            *state_guard = ControllerState::Connected;
        }
        
        // Сброс в состоянии Connected
        let result = controller.reset().await;
        assert!(result.is_ok());
        let state = controller.get_state().await;
        assert_eq!(state, ControllerState::Idle);
    }
}
