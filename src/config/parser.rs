use crate::config::model::{ServerConfig, ProtocolConfig};
use crate::utils::error::VpnError;
use std::path::Path;
use std::fs;
use serde_json::Value;
use std::collections::HashMap;

/// Парсит конфигурационный файл
pub fn parse_config<P: AsRef<Path>>(path: P) -> Result<Vec<ServerConfig>, VpnError> {
    let content = fs::read_to_string(path.as_ref()).map_err(|e| {
        VpnError::ConfigError(format!("Не удалось прочитать файл: {}", e))
    })?;

    let json: Value = serde_json::from_str(&content).map_err(|e| {
        VpnError::ConfigError(format!("Ошибка парсинга JSON: {}", e))
    })?;

    let servers = match json.as_object() {
        Some(obj) => {
            let mut list = Vec::new();
            for (tag, value) in obj {
                let mut server: ServerConfig = serde_json::from_value(value.clone()).map_err(|e| {
                    VpnError::ConfigError(format!("Ошибка парсинга {}: {}", tag, e))
                })?;
                server.tag = tag.clone();
                server.validate()?;
                list.push(server);
            }
            list
        }
        None => return Err(VpnError::ConfigError("Неверный формат конфига".to_string())),
    };

    Ok(servers)
}

/// Парсит JSON-объект в HashMap для плагинов
pub fn parse_plugin_config(config: &HashMap<String, String>) -> Result<HashMap<String, String>, VpnError> {
    if config.is_empty() {
        return Err(VpnError::ConfigError("Пустая конфигурация плагина".to_string()));
    }
    Ok(config.clone())
}

/// Проверяет валидность IP-адреса
fn validate_ip(ip: &str) -> Result<IpAddr, VpnError> {
    ip.parse::<IpAddr>().map_err(|_| {
        VpnError::ConfigError(format!("Неверный IP-адрес: {}", ip))
    })
}

/// Проверяет валидность порта (1-65535)
fn validate_port(port: u16) -> Result<(), VpnError> {
    if port == 0 || port > 65535 {
        return Err(VpnError::ConfigError("Неверный порт".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{ServerConfig, ProtocolConfig};

    #[test]
    fn test_parse_valid_config() {
        let config_str = r#"
        {
            "server1": {
                "protocol": "wireguard",
                "server_ip": "1.1.1.1",
                "server_port": 51820,
                "wireguard_private_key": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIg2fZOk7hKQ=",
                "wireguard_public_key": "xTIBA5rboUvnH4htodDoEj3WZ+barGBCQHbR47hTHA=",
                "ipv6": false,
                "mtu": 1420,
                "custom_tags": ["geo-de", "no-logs"],
                "advanced_routing": {
                    "dns": ["1.1.1.1", "1.0.0.1"],
                    "routes": [
                        {"destination": "0.0.0.0/0", "gateway": "10.0.0.1"},
                        {"destination": "10.0.0.0/8", "gateway": "10.0.0.1"}
                    ]
                },
                "obfuscation": {
                    "type": "shadowsocks-over-wireguard",
                    "method": "aes-256-gcm",
                    "password": "s3cretPass",
                    "plugin_options": {
                        "mode": "udp_and_tcp"
                    }
                }
            }
        }"#;

        let json: Value = serde_json::from_str(config_str).unwrap();
        let servers = match json.as_object() {
            Some(obj) => {
                let mut server_list = Vec::new();
                for (tag, value) in obj {
                    let mut server: ServerConfig = serde_json::from_value(value.clone()).unwrap();
                    server.tag = tag.clone();
                    server.validate().unwrap();
                    server_list.push(server);
                }
                server_list
            }
            None => panic!("Неверный формат конфигурации"),
        };

        assert_eq!(servers.len(), 1);
        let server = &servers[0];
        assert_eq!(server.tag, "server1");
        assert!(matches!(server.protocol, ProtocolConfig::Wireguard(_)));
    }
}
