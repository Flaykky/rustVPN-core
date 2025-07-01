use crate::utils::error::VpnError;
use crate::config::model::{ServerConfig, ProtocolConfig};
use serde_json::Value;
use std::fs;
use std::path::Path;

pub fn parse_config<P: AsRef<Path>>(path: P) -> Result<Vec<ServerConfig>, VpnError> {
    let content = fs::read_to_string(path.as_ref()).map_err(|e| {
        VpnError::ConfigError(format!("Не удалось прочитать файл конфигурации: {}", e))
    })?;

    let json: Value = serde_json::from_str(&content).map_err(|e| {
        VpnError::ConfigError(format!("Ошибка парсинга JSON: {}", e))
    })?;

    let servers = match json.as_object() {
        Some(obj) => {
            let mut server_list = Vec::new();
            for (tag, value) in obj {
                let mut server: ServerConfig = serde_json::from_value(value.clone()).map_err(|e| {
                    VpnError::ConfigError(format!("Ошибка парсинга сервера {}: {}", tag, e))
                })?;
                server.tag = tag.clone();
                validate_server_config(&server)?;
                server_list.push(server);
            }
            server_list
        }
        None => return Err(VpnError::ConfigError("Неверный формат конфигурации".to_string())),
    };

    Ok(servers)
}

fn validate_server_config(config: &ServerConfig) -> Result<(), VpnError> {
    match &config.config {
        ProtocolConfig::Wireguard(wg) => {
            wg.server_ip.parse::<IpAddr>().map_err(|e| {
                VpnError::ConfigError(format!("Неверный IP-адрес сервера WireGuard: {}", e))
            })?;
            if wg.wireguard_private_key.is_empty() || wg.wireguard_public_key.is_empty() {
                return Err(VpnError::ConfigError("Отсутствуют ключи WireGuard".to_string()));
            }
        }
        ProtocolConfig::Shadowsocks(ss) => {
            ss.server_ip.parse::<IpAddr>().map_err(|e| {
                VpnError::ConfigError(format!("Неверный IP-адрес сервера Shadowsocks: {}", e))
            })?;
            if ss.password.is_empty() || ss.method.is_empty() {
                return Err(VpnError::ConfigError("Отсутствует пароль или метод шифрования для Shadowsocks".to_string()));
            }
        }
        ProtocolConfig::Http(http) => {
            http.proxy_ip.parse::<IpAddr>().map_err(|e| {
                VpnError::ConfigError(format!("Неверный IP-адрес HTTP-прокси: {}", e))
            })?;
        }
        ProtocolConfig::Socks5(socks) => {
            socks.proxy_ip.parse::<IpAddr>().map_err(|e| {
                VpnError::ConfigError(format!("Неверный IP-адрес SOCKS5-прокси: {}", e))
            })?;
        }
    }
    Ok(())
}
