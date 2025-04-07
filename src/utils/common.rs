// src/utils/common.rs

use std::net::{IpAddr, SocketAddr};
use chrono::Local;
use uuid::Uuid;
use anyhow::{Result, anyhow};

/// Уровни логирования
#[derive(Debug, PartialEq, PartialOrd)]
pub enum LogLevel {
    Error = 1,
    Warning,
    Info,
}

/// Глобальный уровень логирования
pub const LOG_LEVEL: LogLevel = {
    if cfg!(debug_assertions) {
        LogLevel::Info
    } else {
        LogLevel::Error
    }
};

/// Макрос логирования
#[macro_export]
macro_rules! log {
    ($level:expr, $($arg:tt)*) => {{
        if $level <= &$crate::utils::common::LOG_LEVEL {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            let level_str = match $level {
                LogLevel::Error => "ERROR",
                LogLevel::Warning => "WARNING",
                LogLevel::Info => "INFO",
            };
            eprintln!("[{}] [{}] {}", timestamp, level_str, format!($($arg)*));
        }
    }};
}

// Константы
pub const BUFFER_SIZE: usize = 1024;
pub const MAX_IP_LENGTH: usize = 16;

/// Конфигурация сервера
#[derive(Debug, Clone)]
pub struct ServerConfig {
    ip: String,
    port: u16,
}

impl ServerConfig {
    pub fn new(ip: &str, port: u16) -> Result<Self> {
        if !Self::is_valid_ip(ip) {
            return Err(anyhow!("Invalid IP address"));
        }
        Ok(Self {
            ip: ip.to_string(),
            port,
        })
    }

    pub fn socket_addr(&self) -> SocketAddr {
        format!("{}:{}", self.ip, self.port).parse().unwrap()
    }

    fn is_valid_ip(ip: &str) -> bool {
        ip.parse::<IpAddr>().is_ok()
    }
}

/// Генерация UUID v4
pub fn generate_uuid() -> String {
    Uuid::new_v4().to_hyphenated().to_string()
}

/// Форматирование строки с переменными аргументами
pub fn format_string(format: &str, args: std::fmt::Arguments) -> String {
    format!("{}", args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config() {
        let config = ServerConfig::new("127.0.0.1", 8080).unwrap();
        assert_eq!(config.ip, "127.0.0.1");
        assert_eq!(config.port, 8080);
    }

    #[test]
    fn test_uuid_generation() {
        let uuid = generate_uuid();
        assert_eq!(uuid.len(), 36);
    }
}