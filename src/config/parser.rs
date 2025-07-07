use crate::utils::error::VpnError;
use crate::config::model::{VpnClientConfig, ServerConfig};
use serde_json::Value;
use std::fs;
use std::path::Path;

/// Парсит конфигурационный файл в структуру VpnClientConfig
pub fn parse_config<P: AsRef<Path>>(path: P) -> Result<VpnClientConfig, VpnError> {
    let content = fs::read_to_string(path.as_ref()).map_err(|e| {
        VpnError::ConfigError(format!("Не удалось прочитать конфигурационный файл: {}", e))
    })?;

    let json: Value = serde_json::from_str(&content).map_err(|e| {
        VpnError::ConfigError(format!("Ошибка парсинга JSON: {}", e))
    })?;

    let config: VpnClientConfig = serde_json::from_value(json).map_err(|e| {
        VpnError::ConfigError(format!("Ошибка десериализации конфигурации: {}", e))
    })?;

    config.validate().map_err(|e| {
        VpnError::ConfigError(format!("Ошибка валидации конфигурации: {}", e))
    })?;

    Ok(config)
}

/// Парсит JSON-строку в структуру VpnClientConfig
pub fn parse_config_from_str(content: &str) -> Result<VpnClientConfig, VpnError> {
    let json: Value = serde_json::from_str(content).map_err(|e| {
        VpnError::ConfigError(format!("Ошибка парсинга JSON: {}", e))
    })?;

    let config: VpnClientConfig = serde_json::from_value(json).map_err(|e| {
        VpnError::ConfigError(format!("Ошибка десериализации конфигурации: {}", e))
    })?;

    config.validate().map_err(|e| {
        VpnError::ConfigError(format!("Ошибка валидации конфигурации: {}", e))
    })?;

    Ok(config)
}

/// Проверяет, является ли строка допустимым IP-адресом
pub fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

/// Проверяет, является ли порт допустимым (1-65535)
pub fn is_valid_port(port: u16) -> bool {
    port >= 1 && port <= 65535
}

/// Проверяет, является ли строка допустимым CIDR
pub fn is_valid_cidr(cidr: &str) -> bool {
    cidr.parse::<ipnetwork::IpNetwork>().is_ok()
}
