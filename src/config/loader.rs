//! Модуль для загрузки и парсинга конфигурационных файлов.
//! Поддерживает JSON и может быть расширен для TOML и других форматов.

use crate::utils::logging::{log_debug, log_info, log_warn, log_error};
use crate::utils::error::VpnError;
use crate::config::model::{Config, ServerConfig}; // Предполагается, что Config - это HashMap<String, ServerConfig> или подобная структура
use std::path::Path;
use std::fs::File;
use std::io::Read;
use serde_json;

/// Поддерживаемые форматы конфигурационных файлов.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Json,
    // Toml, // Можно добавить позже
    // Yaml, // Можно добавить позже
}

impl ConfigFormat {
    /// Определяет формат по расширению файла.
    pub fn from_extension<P: AsRef<Path>>(path: P) -> Result<Self, VpnError> {
        let path = path.as_ref();
        let extension = path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| ext.to_lowercase())
            .unwrap_or_default();

        match extension.as_str() {
            "json" => Ok(ConfigFormat::Json),
            // "toml" => Ok(ConfigFormat::Toml),
            _ => {
                log_warn!("Не удалось определить формат конфига по расширению '{}'. Используется JSON по умолчанию.", extension);
                Ok(ConfigFormat::Json) // По умолчанию
            }
        }
    }
}

/// Загрузчик конфигураций.
pub struct ConfigLoader;

impl ConfigLoader {
    /// Загружает конфигурацию из файла.
    ///
    /// # Аргументы
    /// * `path` - Путь к конфигурационному файлу.
    ///
    /// # Возвращает
    /// * `Result<Config, VpnError>` - Загруженная конфигурация или ошибка.
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Config, VpnError> {
        let path_ref = path.as_ref();
        log_info!("Загрузка конфигурации из файла: {:?}", path_ref);

        if !path_ref.exists() {
            log_error!("Файл конфигурации не найден: {:?}", path_ref);
            return Err(VpnError::config_error(format!("Файл конфигурации не найден: {:?}", path_ref)));
        }

        let format = ConfigFormat::from_extension(&path)?;
        log_debug!("Определён формат конфига: {:?}", format);

        let mut file = File::open(&path)
            .map_err(|e| {
                log_error!("Ошибка открытия файла {:?}: {}", path_ref, e);
                VpnError::config_error(format!("Не удалось открыть файл конфигурации: {}", e))
            })?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| {
                log_error!("Ошибка чтения файла {:?}: {}", path_ref, e);
                VpnError::config_error(format!("Не удалось прочитать файл конфигурации: {}", e))
            })?;

        match format {
            ConfigFormat::Json => Self::parse_json(&contents),
            // ConfigFormat::Toml => Self::parse_toml(&contents),
        }
    }

    /// Загружает конфигурацию из строки JSON.
    ///
    /// # Аргументы
    /// * `json_str` - Строка с JSON-конфигурацией.
    ///
    /// # Возвращает
    /// * `Result<Config, VpnError>` - Загруженная конфигурация или ошибка.
    pub fn load_from_json_str(json_str: &str) -> Result<Config, VpnError> {
        log_debug!("Парсинг конфигурации из JSON-строки");
        Self::parse_json(json_str)
    }

    /// Парсит конфигурацию из строки JSON.
    fn parse_json(json_str: &str) -> Result<Config, VpnError> {
        let parsed: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| {
                log_error!("Ошибка парсинга JSON: {}", e);
                VpnError::config_error(format!("Ошибка парсинга JSON конфигурации: {}", e))
            })?;

        log_debug!("JSON успешно распарсен, проверка структуры...");

        // Ожидаем, что корневой элемент - объект (map)
        let obj = parsed.as_object()
            .ok_or_else(|| {
                log_error!("Конфигурация должна быть JSON-объектом (map) на верхнем уровне.");
                VpnError::config_error("Конфигурация должна быть JSON-объектом (map) на верхнем уровне.")
            })?;

        let mut config_map = std::collections::HashMap::new();

        for (tag, value) in obj {
            log_debug!("Парсинг сервера с тегом: {}", tag);
            let mut server_config: ServerConfig = serde_json::from_value(value.clone())
                .map_err(|e| {
                    log_error!("Ошибка парсинга сервера '{}': {}", tag, e);
                    VpnError::config_error(format!("Ошибка парсинга сервера '{}': {}", tag, e))
                })?;
            
            // Устанавливаем тег, так как он ключ в объекте, а не поле в ServerConfig
            server_config.tag = tag.clone(); 
            
            // Здесь можно добавить дополнительную валидацию server_config
            // Например, проверить protocol, обязательные поля и т.д.
            // validate_server_config(&server_config)?; // Функция validate_server_config должна быть определена
            
            config_map.insert(tag.clone(), server_config);
        }

        log_info!("Конфигурация успешно загружена. Загружено {} серверов.", config_map.len());
        Ok(Config(config_map)) // Предполагается, что Config - это просто обёртка вокруг HashMap
    }

    // /// Парсит конфигурацию из строки TOML.
    // /// (Закомментировано, так как TOML не в зависимостях по умолчанию)
    // #[cfg(feature = "toml")]
    // fn parse_toml(toml_str: &str) -> Result<Config, VpnError> {
    //     // Реализация парсинга TOML
    //     // let config: Config = toml::from_str(toml_str)
    //     //     .map_err(|e| VpnError::ConfigError(format!("Ошибка парсинга TOML конфигурации: {}", e)))?;
    //     // Ok(config)
    //     unimplemented!("Парсинг TOML пока не реализован")
    // }

    // /// Парсит конфигурацию из строки TOML.
    // #[cfg(not(feature = "toml"))]
    // fn parse_toml(_toml_str: &str) -> Result<Config, VpnError> {
    //     Err(VpnError::ConfigError("Поддержка TOML не включена в сборку.".to_string()))
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const TEST_JSON_CONFIG: &str = r#"{
        "server1": {
            "protocol": "wireguard",
            "server_ip": "192.168.1.1",
            "server_port": 51820,
            "wireguard_private_key": "private_key_1",
            "wireguard_public_key": "public_key_1"
        },
        "server2": {
            "protocol": "shadowsocks",
            "server_ip": "192.168.2.1",
            "server_port": 8388,
            "password": "password123",
            "method": "aes-256-gcm"
        }
    }"#;

    #[test]
    fn test_load_from_json_str() {
        let config_result = ConfigLoader::load_from_json_str(TEST_JSON_CONFIG);
        assert!(config_result.is_ok(), "Ошибка загрузки из JSON строки: {:?}", config_result.err());
        let config = config_result.unwrap();
        assert_eq!(config.0.len(), 2, "Должно быть загружено 2 сервера");
        assert!(config.0.contains_key("server1"));
        assert!(config.0.contains_key("server2"));
    }

    #[test]
    fn test_load_from_file_json() {
        let mut tmp_file = NamedTempFile::new().unwrap();
        tmp_file.write_all(TEST_JSON_CONFIG.as_bytes()).unwrap();

        let config_result = ConfigLoader::load_from_file(tmp_file.path());
        assert!(config_result.is_ok(), "Ошибка загрузки из JSON файла: {:?}", config_result.err());
        let config = config_result.unwrap();
        assert_eq!(config.0.len(), 2);
    }

    #[test]
    fn test_format_from_extension() {
        assert_eq!(ConfigFormat::from_extension("config.json").unwrap(), ConfigFormat::Json);
        assert_eq!(ConfigFormat::from_extension("config.JSON").unwrap(), ConfigFormat::Json);
        // assert_eq!(ConfigFormat::from_extension("config.toml").unwrap(), ConfigFormat::Toml);
        assert_eq!(ConfigFormat::from_extension("config.unknown").unwrap(), ConfigFormat::Json); // По умолчанию
        assert_eq!(ConfigFormat::from_extension("config").unwrap(), ConfigFormat::Json); // Без расширения
    }

    #[test]
    fn test_load_from_nonexistent_file() {
        let result = ConfigLoader::load_from_file("/path/that/does/not/exist.conf");
        assert!(result.is_err());
        match result.unwrap_err() {
            VpnError::ConfigError(_) => {}, // Ожидаем ошибку конфигурации
            _ => panic!("Ожидалась ошибка ConfigError"),
        }
    }

    #[test]
    fn test_load_from_invalid_json() {
        let invalid_json = r#"{ "server1": { "protocol": "wireguard", "server_ip": 123 } }"#; // server_ip должен быть строкой
        let result = ConfigLoader::load_from_json_str(invalid_json);
        assert!(result.is_err());
         match result.unwrap_err() {
            VpnError::ConfigError(_) => {}, // Ожидаем ошибку конфигурации из-за невалидного JSON
            _ => panic!("Ожидалась ошибка ConfigError из-за невалидного JSON"),
        }
    }
}
