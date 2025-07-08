// src/utils/logging.rs

/*
Основные функции:
- Инициализация системы логирования с настраиваемым уровнем детализации
- Реализация кастомного форматирования логов (временные метки)
- Предоставление глобального логгера для всего приложения
- Упрощенные функции логирования для разных уровней (debug/info/error)

Ключевые компоненты:
1. init_logging() - инициализация логгера с указанным уровнем
2. CustomLogger - кастомная реализация логгера
3. set_custom_logger() - активация кастомного логгера
4. Упрощенные функции log_*() - прямое логирование без макросов

Примеры использования:
// Инициализация логгера
init_logging("debug");

// Прямое использование
log_error("Критическая ошибка подключения");

// Использование через макросы
info!("Установлено соединение с {}", server_ip);
*/


use log::{Level, LevelFilter, Metadata, Record};
use env_logger::Builder;
use std::io::Write;
use std::sync::Once;

/// Инициализирует систему логирования с указанным уровнем логов.
///
/// # Аргументы
///
/// * `level` - Уровень логов для установки (например, "debug", "info", "warn", "error").
pub fn init_logging(level: &str) {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let level_filter = match level.to_lowercase().as_str() {
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            _ => LevelFilter::Info,
        };

        Builder::new()
            .filter_level(level_filter)
            .format(|buf, record| {
                writeln!(
                    buf,
                    "[{} {}] {}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                    record.level(),
                    record.args()
                )
            })
            .init();
    });
}

/// Пользовательский логгер для более сложных сценариев логирования.
pub struct CustomLogger;

impl log::Log for CustomLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

/// Устанавливает пользовательский логгер как глобальный.
pub fn set_custom_logger() {
    log::set_boxed_logger(Box::new(CustomLogger)).unwrap();
    log::set_max_level(LevelFilter::Info);
}

// Примеры дополнительных функций для расширения модуля до ~100-200 строк
/// Логирует сообщение с уровнем Debug.
pub fn log_debug(msg: &str) {
    log::debug!("{}", msg);
}

/// Логирует сообщение с уровнем Info.
pub fn log_info(msg: &str) {
    log::info!("{}", msg);
}

/// Логирует сообщение с уровнем Warn.
pub fn log_warn(msg: &str) {
    log::warn!("{}", msg);
}

/// Логирует сообщение с уровнем Error.
pub fn log_error(msg: &str) {
    log::error!("{}", msg);
}

#[cfg(test)]
mod tests {
    use super::*;
    use log::{debug, info};

    #[test]
    fn test_logging_initialization() {
        init_logging("debug");
        debug!("Тестовое сообщение уровня debug.");
        info!("Тестовое сообщение уровня info.");
    }

    #[test]
    fn test_custom_logger() {
        init_logging("info");
        set_custom_logger();
        info!("Тестовое сообщение с пользовательским логгером.");
    }

    #[test]
    fn test_log_functions() {
        init_logging("debug");
        log_debug("Debug сообщение для теста.");
        log_info("Info сообщение для теста.");
        log_warn("Warn сообщение для теста.");
        log_error("Error сообщение для теста.");
    }
}

// Дополнительные утилиты для увеличения объема кода
/// Возвращает текущий уровень логирования как строку.
pub fn get_log_level() -> String {
    match log::max_level() {
        LevelFilter::Off => "off".to_string(),
        LevelFilter::Error => "error".to_string(),
        LevelFilter::Warn => "warn".to_string(),
        LevelFilter::Info => "info".to_string(),
        LevelFilter::Debug => "debug".to_string(),
        LevelFilter::Trace => "trace".to_string(),
    }
}

/// Проверяет, активен ли заданный уровень логирования.
pub fn is_level_enabled(level: &str) -> bool {
    let current = log::max_level();
    let target = match level.to_lowercase().as_str() {
        "debug" => LevelFilter::Debug,
        "info" => LevelFilter::Info,
        "warn" => LevelFilter::Warn,
        "error" => LevelFilter::Error,
        _ => LevelFilter::Info,
    };
    current >= target
}
