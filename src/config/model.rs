use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::collections::HashMap;
use crate::utils::error::VpnError;

/// Основная конфигурация сервера
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub tag: String,
    #[serde(flatten)]
    pub protocol: ProtocolConfig,
}

/// Все поддерживаемые типы протоколов
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum ProtocolConfig {
    Wireguard(WireguardConfig),
    Shadowsocks(ShadowsocksConfig),
    HttpProxy(HttpProxyConfig),
    Socks5(Socks5Config),
    Plugin(PluginConfig),
}

// === PROTOCOL CONFIGURATIONS ===

/// Конфигурация для WireGuard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardConfig {
    pub server_ip: String,
    pub server_port: u16,
    pub wireguard_private_key: String,
    pub wireguard_public_key: String,
    #[serde(default = "default_ipv6")]
    pub ipv6: bool,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    #[serde(default)]
    pub obfuscation: Option<ObfuscationConfig>,
    #[serde(default)]
    pub advanced_routing: Option<AdvancedRoutingConfig>,
    #[serde(default)]
    pub custom_tags: Vec<String>,
}

/// Конфигурация для Shadowsocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksConfig {
    pub server_ip: String,
    pub server_port: u16,
    pub method: String,
    pub password: String,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub plugin_opts: Option<String>,
    #[serde(default)]
    pub obfuscation: Option<ObfuscationConfig>,
    #[serde(default)]
    pub advanced_routing: Option<AdvancedRoutingConfig>,
    #[serde(default)]
    pub custom_tags: Vec<String>,
}

/// Конфигурация для HTTP прокси
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProxyConfig {
    pub proxy_ip: String,
    pub proxy_port: u16,
    pub target_ip: String,
    pub target_port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub advanced_routing: Option<AdvancedRoutingConfig>,
    #[serde(default)]
    pub custom_tags: Vec<String>,
}

/// Конфигурация для SOCKS5 прокси
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    pub proxy_ip: String,
    pub proxy_port: u16,
    pub target_ip: String,
    pub target_port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub advanced_routing: Option<AdvancedRoutingConfig>,
    #[serde(default)]
    pub custom_tags: Vec<String>,
}

/// Конфигурация для пользовательских плагинов
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub plugin_type: String,
    pub plugin_config: HashMap<String, String>,
    #[serde(default)]
    pub advanced_routing: Option<AdvancedRoutingConfig>,
    #[serde(default)]
    pub custom_tags: Vec<String>,
}

// === OBFUSCATION CONFIG ===

/// Поддерживаемые типы обфускации
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ObfuscationType {
    #[serde(rename = "shadowsocks-over-wireguard")]
    ShadowsocksOverWireguard,
    #[serde(rename = "fragmentation")]
    Fragmentation,
    #[serde(rename = "masquerade")]
    Masquerade,
    #[serde(rename = "custom-plugin")]
    CustomPlugin,
}

/// Конфигурация обфускации
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationConfig {
    #[serde(rename = "type")]
    pub obfuscation_type: ObfuscationType,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub plugin_options: Option<HashMap<String, String>>,
}

// === ADVANCED ROUTING ===

/// Расширенные настройки маршрутизации
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedRoutingConfig {
    #[serde(default)]
    pub dns: Option<Vec<String>>,
    #[serde(default)]
    pub routes: Option<Vec<Route>>,
    #[serde(default)]
    pub split_tunnel: Option<bool>,
    #[serde(default)]
    pub exclude_apps: Option<Vec<String>>,
}

/// Единичный маршрут
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub destination: String,
    pub gateway: String,
    #[serde(default)]
    pub interface: Option<String>,
}

// === VALIDATION ===

impl ServerConfig {
    /// Валидирует конфигурацию сервера
    pub fn validate(&self) -> Result<(), VpnError> {
        match &self.protocol {
            ProtocolConfig::Wireguard(cfg) => cfg.validate()?,
            ProtocolConfig::Shadowsocks(cfg) => cfg.validate()?,
            ProtocolConfig::HttpProxy(cfg) => cfg.validate()?,
            ProtocolConfig::Socks5(cfg) => cfg.validate()?,
            ProtocolConfig::Plugin(cfg) => cfg.validate()?,
        }
        Ok(())
    }
}

impl WireguardConfig {
    fn validate(&self) -> Result<(), VpnError> {
        if self.server_ip.parse::<IpAddr>().is_err() {
            return Err(VpnError::ConfigError(format!("Неверный IP-адрес: {}", self.server_ip)));
        }
        if self.server_port == 0 || self.server_port > 65535 {
            return Err(VpnError::ConfigError("Неверный порт сервера".to_string()));
        }
        if self.wireguard_private_key.is_empty() || self.wireguard_public_key.is_empty() {
            return Err(VpnError::ConfigError("Отсутствует ключ WireGuard".to_string()));
        }
        Ok(())
    }
}

impl ShadowsocksConfig {
    fn validate(&self) -> Result<(), VpnError> {
        if self.server_ip.parse::<IpAddr>().is_err() {
            return Err(VpnError::ConfigError(format!("Неверный IP-адрес: {}", self.server_ip)));
        }
        if self.server_port == 0 || self.server_port > 65535 {
            return Err(VpnError::ConfigError("Неверный порт сервера".to_string()));
        }
        if self.password.is_empty() || self.method.is_empty() {
            return Err(VpnError::ConfigError("Отсутствует метод или пароль".to_string()));
        }
        Ok(())
    }
}

impl HttpProxyConfig {
    fn validate(&self) -> Result<(), VpnError> {
        if self.proxy_ip.parse::<IpAddr>().is_err() {
            return Err(VpnError::ConfigError(format!("Неверный IP-адрес прокси: {}", self.proxy_ip)));
        }
        if self.proxy_port == 0 || self.proxy_port > 65535 {
            return Err(VpnError::ConfigError("Неверный порт прокси".to_string()));
        }
        Ok(())
    }
}

impl Socks5Config {
    fn validate(&self) -> Result<(), VpnError> {
        if self.proxy_ip.parse::<IpAddr>().is_err() {
            return Err(VpnError::ConfigError(format!("Неверный IP-адрес прокси: {}", self.proxy_ip)));
        }
        if self.proxy_port == 0 || self.proxy_port > 65535 {
            return Err(VpnError::ConfigError("Неверный порт прокси".to_string()));
        }
        Ok(())
    }
}

impl PluginConfig {
    fn validate(&self) -> Result<(), VpnError> {
        if self.plugin_type.is_empty() {
            return Err(VpnError::ConfigError("Отсутствует тип плагина".to_string()));
        }
        if self.plugin_config.is_empty() {
            return Err(VpnError::ConfigError("Пустая конфигурация плагина".to_string()));
        }
        Ok(())
    }
}

// === DEFAULT VALUES ===

fn default_ipv6() -> bool { false }
fn default_mtu() -> u32 { 1420 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wireguard_config_validation() {
        let config = WireguardConfig {
            server_ip: "1.1.1.1".to_string(),
            server_port: 51820,
            wireguard_private_key: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIg2fZOk7hKQ=".to_string(),
            wireguard_public_key: "xTIBA5rboUvnH4htodDoEj3WZ+barGBCQHbR47hTHA=".to_string(),
            ipv6: false,
            mtu: 1420,
            obfuscation: None,
            advanced_routing: None,
            custom_tags: vec!["geo-de".to_string(), "no-logs".to_string()],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_wireguard_config() {
        let config = WireguardConfig {
            server_ip: "invalid-ip".to_string(),
            server_port: 0,
            wireguard_private_key: "".to_string(),
            wireguard_public_key: "".to_string(),
            ipv6: false,
            mtu: 1420,
            obfuscation: None,
            advanced_routing: None,
            custom_tags: vec![],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_shadowsocks_config_validation() {
        let config = ShadowsocksConfig {
            server_ip: "8.8.8.8".to_string(),
            server_port: 8388,
            method: "aes-256-gcm".to_string(),
            password: "password123".to_string(),
            plugin: None,
            plugin_opts: None,
            obfuscation: None,
            advanced_routing: None,
            custom_tags: vec!["multi-hop-entry".to_string()],
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_shadowsocks_config() {
        let config = ShadowsocksConfig {
            server_ip: "invalid-ip".to_string(),
            server_port: 0,
            method: "".to_string(),
            password: "".to_string(),
            plugin: None,
            plugin_opts: None,
            obfuscation: None,
            advanced_routing: None,
            custom_tags: vec![],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_route_config() {
        let route = Route {
            destination: "0.0.0.0/0".to_string(),
            gateway: "10.0.0.1".to_string(),
            interface: Some("tun0".to_string()),
        };
        assert!(route.destination.parse::<ipnetwork::IpNetwork>().is_ok());
    }
}
