//! Модуль для управления жизненным циклом приложения.
//! Отвечает за:
//! - Инициализацию всех компонентов.
//! - Запуск основного цикла работы.
//! - Обработку сигналов ОС (SIGINT, SIGTERM) для graceful shutdown.
//! - Оркестрацию завершения работы всех подсистем.

use crate::utils::logging::{log_debug, log_info, log_warn, log_error};
use crate::utils::error::VpnError;
use crate::core::controller::VpnController;
use std::sync::Arc;
use tokio::sync::broadcast;
// Для обработки сигналов
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
#[cfg(windows)]
use tokio::signal::windows::{ctrl_c};
use std::future::Future;
use std::pin::Pin;

/// События жизненного цикла приложения.
#[derive(Debug, Clone)]
pub enum LifecycleEvent {
    /// Приложение запущено и готово к работе.
    Started,
    /// Получен сигнал остановки (например, SIGINT, SIGTERM).
    ShutdownSignal,
    /// Приложение остановлено.
    Stopped,
    /// Произошла критическая ошибка.
    Error(String),
}

/// Трейт для компонентов, которые могут быть запущены и остановлены.
#[async_trait::async_trait]
pub trait LifecycleComponent: Send + Sync {
    /// Запускает компонент.
    async fn start(&mut self) -> Result<(), VpnError>;
    /// Останавливает компонент.
    async fn stop(&mut self) -> Result<(), VpnError>;
}

/// Основной менеджер жизненного цикла приложения.
pub struct VpnLifecycle {
    /// Контроллер VPN.
    controller: Arc<VpnController>,
    /// Отправитель событий жизненного цикла.
    event_tx: broadcast::Sender<LifecycleEvent>,
    /// Получатель событий жизненного цикла.
    event_rx: broadcast::Receiver<LifecycleEvent>,
    /// Флаг, указывающий, что приложение запущено.
    is_running: bool,
}

impl VpnLifecycle {
    /// Создает новый экземпляр `VpnLifecycle`.
    pub fn new(controller: Arc<VpnController>) -> Self {
        log_info!("Инициализация VpnLifecycle");
        let (event_tx, event_rx) = broadcast::channel(16);
        Self {
            controller,
            event_tx,
            event_rx,
            is_running: false,
        }
    }

    /// Получает контроллер VPN.
    pub fn controller(&self) -> Arc<VpnController> {
        Arc::clone(&self.controller)
    }

    /// Получает отправителя событий жизненного цикла.
    pub fn event_sender(&self) -> broadcast::Sender<LifecycleEvent> {
        self.event_tx.clone()
    }

    /// Получает получателя событий жизненного цикла.
    pub fn event_receiver(&mut self) -> broadcast::Receiver<LifecycleEvent> {
        self.event_tx.subscribe()
    }

    /// Инициализирует приложение.
    pub async fn initialize(&mut self) -> Result<(), VpnError> {
        log_info!("Инициализация приложения...");
        // Здесь можно добавить инициализацию других компонентов
        // например, загрузку конфига, инициализацию логгера, плагинов и т.д.
        // Пока что просто помечаем, что инициализация прошла
        log_info!("Приложение инициализировано");
        Ok(())
    }

    /// Запускает основной цикл приложения.
    pub async fn run(&mut self) -> Result<(), VpnError> {
        log_info!("Запуск приложения...");
        
        if self.is_running {
            log_warn!("Приложение уже запущено");
            return Ok(());
        }

        // 1. Инициализация (если еще не была выполнена)
        if !self.is_running { // Это условие всегда true здесь, но оставим для ясности
            self.initialize().await?;
        }

        // 2. Установить флаг запуска
        self.is_running = true;

        // 3. Отправить событие "Started"
        if let Err(e) = self.event_tx.send(LifecycleEvent::Started) {
            log_warn!("Не удалось отправить событие Started: {}", e);
        }

        // 4. Запустить задачу для ожидания сигналов завершения
        let shutdown_tx = self.event_tx.clone();
        tokio::spawn(async move {
            Self::wait_for_shutdown_signal().await;
            log_info!("Получен сигнал завершения, инициируем остановку...");
            if let Err(e) = shutdown_tx.send(LifecycleEvent::ShutdownSignal) {
                log_error!("Не удалось отправить событие ShutdownSignal: {}", e);
            }
        });

        // 5. Основной цикл прослушивания событий
        log_info!("Приложение запущено и ожидает событий...");
        loop {
            // Клонируем receiver перед каждым await, чтобы избежать перемещения
            let mut event_rx = self.event_tx.subscribe();
            tokio::select! {
                event_result = event_rx.recv() => {
                    match event_result {
                        Ok(event) => {
                            match event {
                                LifecycleEvent::Started => {
                                    log_debug!("Получено событие: Started");
                                    // Ничего не делаем, это просто уведомление
                                },
                                LifecycleEvent::ShutdownSignal => {
                                    log_info!("Получен сигнал завершения, начинаем остановку...");
                                    break; // Выходим из цикла
                                },
                                LifecycleEvent::Stopped => {
                                    log_debug!("Получено событие: Stopped");
                                    break; // Выходим из цикла
                                },
                                LifecycleEvent::Error(msg) => {
                                    log_error!("Критическая ошибка: {}", msg);
                                    // Можно решить, завершать ли работу или продолжать
                                    // Пока что завершаем
                                    break;
                                },
                            }
                        },
                        Err(e) => {
                            log_error!("Ошибка получения события жизненного цикла: {}", e);
                            // Это может произойти, если все отправители закрыты
                            break;
                        }
                    }
                }
            }
        }

        // 6. Остановка приложения
        self.shutdown().await?;
        Ok(())
    }

    /// Останавливает приложение.
    pub async fn shutdown(&mut self) -> Result<(), VpnError> {
        log_info!("Остановка приложения...");
        
        if !self.is_running {
            log_warn!("Приложение не запущено или уже остановлено");
            return Ok(());
        }

        // 1. Установить флаг остановки
        self.is_running = false;

        // 2. Остановить контроллер (если он подключен)
        let controller_state = self.controller.get_state().await;
        if controller_state == crate::core::controller::ControllerState::Connected {
            log_debug!("Обнаружено активное подключение, выполняется отключение...");
            // Используем spawn, чтобы не блокировать shutdown, если connect повиснет
            let controller_clone = Arc::clone(&self.controller);
            let disconnect_handle = tokio::spawn(async move {
                controller_clone.disconnect().await
            });
            
            // Ограничиваем время на отключение
            match tokio::time::timeout(std::time::Duration::from_secs(10), disconnect_handle).await {
                Ok(result) => {
                    match result {
                        Ok(disconnect_result) => {
                            if let Err(e) = disconnect_result {
                                log_warn!("Ошибка при отключении контроллера: {}", e);
                            } else {
                                log_debug!("Контроллер успешно отключен");
                            }
                        },
                        Err(join_err) => {
                            log_error!("Ошибка в задаче отключения контроллера: {}", join_err);
                        }
                    }
                },
                Err(_) => {
                    log_error!("Таймаут при отключении контроллера");
                }
            }
        } else {
            log_debug!("Контроллер не подключен, пропуск отключения");
        }

        // 3. Здесь можно остановить другие компоненты
        // Например, плагины, обфускаторы и т.д., если они реализуют LifecycleComponent

        // 4. Отправить событие "Stopped"
        if let Err(e) = self.event_tx.send(LifecycleEvent::Stopped) {
            log_warn!("Не удалось отправить событие Stopped: {}", e);
        }

        log_info!("Приложение успешно остановлено");
        Ok(())
    }

    /// Асинхронно ожидает сигналы завершения работы ОС.
    async fn wait_for_shutdown_signal() {
        #[cfg(unix)]
        {
            let mut sigterm = signal(SignalKind::terminate())
                .expect("Не удалось зарегистрировать обработчик SIGTERM");
            let mut sigint = signal(SignalKind::interrupt())
                .expect("Не удалось зарегистрировать обработчик SIGINT");

            tokio::select! {
                _ = sigterm.recv() => {
                    log_info!("Получен сигнал SIGTERM");
                },
                _ = sigint.recv() => {
                    log_info!("Получен сигнал SIGINT (Ctrl+C)");
                }
            }
        }
        #[cfg(windows)]
        {
            ctrl_c().await.expect("Не удалось зарегистрировать обработчик Ctrl+C");
            log_info!("Получен сигнал Ctrl+C");
        }
    }
}

// Реализация LifecycleComponent для VpnController (если нужно)
#[async_trait::async_trait]
impl LifecycleComponent for VpnController {
    async fn start(&mut self) -> Result<(), VpnError> {
        log_debug!("Запуск VpnController (пустая операция)");
        // VpnController не имеет отдельного "стартового" метода, он активен по запросу
        // Эта реализация нужна только если VpnController должен быть частью списка компонентов
        Ok(())
    }

    async fn stop(&mut self) -> Result<(), VpnError> {
        log_debug!("Остановка VpnController");
        self.reset().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_lifecycle_creation() {
        let controller = Arc::new(VpnController::new());
        let lifecycle = VpnLifecycle::new(controller);
        assert!(!lifecycle.is_running);
    }

    #[tokio::test]
    async fn test_initialize() {
        let controller = Arc::new(VpnController::new());
        let mut lifecycle = VpnLifecycle::new(controller);
        let result = lifecycle.initialize().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_event_broadcasting() {
        let controller = Arc::new(VpnController::new());
        let mut lifecycle = VpnLifecycle::new(controller);
        
        let tx = lifecycle.event_sender();
        let mut rx1 = lifecycle.event_receiver();
        let mut rx2 = lifecycle.event_receiver();

        // Отправляем событие
        tx.send(LifecycleEvent::Started).unwrap();

        // Проверяем, что оба получателя получили событие
        let event1 = timeout(Duration::from_millis(100), rx1.recv()).await.unwrap().unwrap();
        let event2 = timeout(Duration::from_millis(100), rx2.recv()).await.unwrap().unwrap();

        assert_eq!(event1, LifecycleEvent::Started);
        assert_eq!(event2, LifecycleEvent::Started);
    }

    #[tokio::test]
    async fn test_shutdown_without_run() {
        let controller = Arc::new(VpnController::new());
        let mut lifecycle = VpnLifecycle::new(controller);
        // shutdown без запуска не должна вызывать ошибок
        let result = lifecycle.shutdown().await;
        assert!(result.is_ok());
    }

    // Тест run/shutdown требует более сложной настройки и эмуляции сигналов,
    // что затруднительно в автоматических тестах.
    // Его можно протестировать вручную или с помощью интеграционных тестов.
}
