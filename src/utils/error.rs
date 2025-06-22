// src/utils/error.rs

use thiserror::Error;

/// Пользовательский тип ошибок для ядра VPN проекта.
#[derive(Error, Debug)]
pub enum VpnError {
    /// Ошибка, связанная с проблемами конфигурации.
    #[error("Ошибка конфигурации: {0}")]
    ConfigError(String),
    /// Ошибка, связанная с проблемами подключения.
    #[error("Ошибка подключения: {0}")]
    ConnectionError(String),
    /// Ошибка, связанная с проблемами протокола.
    #[error("Ошибка протокола: {0}")]
    ProtocolError(String),
    /// Ошибка, связанная с техниками обфускации.
    #[error("Ошибка обфускации: {0}")]
    ObfuscationError(String),
    /// Ошибка, связанная с проблемами шифрования.
    #[error("Ошибка шифрования: {0}")]
    EncryptionError(String),
    /// Ошибка, связанная с проблемами туннелирования.
    #[error("Ошибка туннелирования: {0}")]
    TunnelingError(String),
    /// Ошибка, связанная с взаимодействием CLI.
    #[error("Ошибка CLI: {0}")]
    CliError(String),
    /// Ошибка, связанная с загрузкой или выполнением плагина.
    #[error("Ошибка плагина: {0}")]
    PluginError(String),
    /// Неизвестная или неуказанная ошибка.
    #[error("Неизвестная ошибка")]
    Unknown,
}

impl VpnError {
    /// Создает новую ошибку `ConfigError` с заданным сообщением.
    pub fn config_error(msg: impl Into<String>) -> Self {
        VpnError::ConfigError(msg.into())
    }

    /// Создает новую ошибку `ConnectionError` с заданным сообщением.
    pub fn connection_error(msg: impl Into<String>) -> Self {
        VpnError::ConnectionError(msg.into())
    }

    /// Создает новую ошибку `ProtocolError` с заданным сообщением.
    pub fn protocol_error(msg: impl Into<String>) -> Self {
        VpnError::ProtocolError(msg.into())
    }

    /// Создает новую ошибку `ObfuscationError` с заданным сообщением.
    pub fn obfuscation_error(msg: impl Into<String>) -> Self {
        VpnError::ObfuscationError(msg.into())
    }

    /// Создает новую ошибку `EncryptionError` с заданным сообщением.
    pub fn encryption_error(msg: impl Into<String>) -> Self {
        VpnError::EncryptionError(msg.into())
    }

    /// Создает новую ошибку `TunnelingError` с заданным сообщением.
    pub fn tunneling_error(msg: impl Into<String>) -> Self {
        VpnError::TunnelingError(msg.into())
    }

    /// Создает новую ошибку `CliError` с заданным сообщением.
    pub fn cli_error(msg: impl Into<String>) -> Self {
        VpnError::CliError(msg.into())
    }

    /// Создает новую ошибку `PluginError` с заданным сообщением.
    pub fn plugin_error(msg: impl Into<String>) -> Self {
        VpnError::PluginError(msg.into())
    }
}

// Преобразование std::io::Error в VpnError::ConnectionError
impl From<std::io::Error> for VpnError {
    fn from(err: std::io::Error) -> Self {
        VpnError::ConnectionError(err.to_string())
    }
}

// Преобразование serde_json::Error в VpnError::ConfigError
impl From<serde_json::Error> for VpnError {
    fn from(err: serde_json::Error) -> Self {
        VpnError::ConfigError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_messages() {
        let config_err = VpnError::config_error("Неверная конфигурация");
        assert_eq!(config_err.to_string(), "Ошибка конфигурации: Неверная конфигурация");

        let conn_err = VpnError::connection_error("Подключение не удалось");
        assert_eq!(conn_err.to_string(), "Ошибка подключения: Подключение не удалось");

        let protocol_err = VpnError::protocol_error("Неподдерживаемый протокол");
        assert_eq!(protocol_err.to_string(), "Ошибка протокола: Неподдерживаемый протокол");

        let obfuscation_err = VpnError::obfuscation_error("Обфускация не удалась");
        assert_eq!(obfuscation_err.to_string(), "Ошибка обфускации: Обфускация не удалась");

        let encryption_err = VpnError::encryption_error("Неверный ключ шифрования");
        assert_eq!(encryption_err.to_string(), "Ошибка шифрования: Неверный ключ шифрования");

        let tunneling_err = VpnError::tunneling_error("Настройка туннеля не удалась");
        assert_eq!(tunneling_err.to_string(), "Ошибка туннелирования: Настройка туннеля не удалась");

        let cli_err = VpnError::cli_error("Неверный аргумент CLI");
        assert_eq!(cli_err.to_string(), "Ошибка CLI: Неверный аргумент CLI");

        let plugin_err = VpnError::plugin_error("Плагин не найден");
        assert_eq!(plugin_err.to_string(), "Ошибка плагина: Плагин не найден");

        let unknown_err = VpnError::Unknown;
        assert_eq!(unknown_err.to_string(), "Неизвестная ошибка");
    }
}
