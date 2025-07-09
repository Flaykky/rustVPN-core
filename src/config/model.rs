use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::collections::HashMap;
use ipnetwork::IpNetwork;
use std::str::FromStr;

/// Типы поддерживаемых протоколов
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolType {
    Wireguard,
    Shadowsocks,
    Http,
    Socks5,
    Openvpn,
    Plugin(String),
}

/// Типы обфускации
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationConfig {
    #[serde(rename = "type")]
    pub obfuscation_type: String,
    pub method: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub plugin_options: HashMap<String, String>,
}

/// Настройки маршрутизации
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteConfig {
    pub destination: String,
    pub gateway: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedRoutingConfig {
    pub dns: Vec<String>,
    pub routes: Vec<RouteConfig>,
}

/// Базовая конфигурация сервера
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub tag: String,
    pub protocol: ProtocolType,
    pub in_ip: Option<String>,
    pub out_ip: Option<String>,
    pub server_ip: Option<String>,
    pub server_port: Option<u16>,
    pub tun_interface_name: Option<String>,
    pub tun_interface_address: Option<String>,
    pub wireguard_private_key: Option<String>,
    pub wireguard_public_key: Option<String>,
    pub ipv6: Option<bool>,
    pub mtu: Option<u32>,
    pub obfuscation: Option<ObfuscationConfig>,
    pub advanced_routing: Option<AdvancedRoutingConfig>,
    pub custom_tags: Option<Vec<String>>,
}

/// Конфигурация для WireGuard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfig {
    #[serde(rename = "server_ip")]
    pub endpoint_ip: String,
    #[serde(rename = "server_port")]
    pub endpoint_port: u16,
    pub wireguard_private_key: String,
    pub wireguard_public_key: String,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub ipv6: Option<bool>,
    #[serde(default)]
    pub obfuscation: Option<ObfuscationConfig>,
}

impl WireGuardConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.endpoint_ip.parse::<IpAddr>().is_err() {
            return Err("Неверный IP-адрес сервера WireGuard".to_string());
        }
        if self.endpoint_port == 0  self.endpoint_port > 65535 {
            return Err("Неверный порт сервера WireGuard".to_string());
        }
        if self.wireguard_private_key.is_empty()  self.wireguard_public_key.is_empty() {
            return Err("Отсутствуют ключи WireGuard".to_string());
        }
        Ok(())
    }
}

/// Конфигурация для Shadowsocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksConfig {
    #[serde(rename = "server_ip")]
    pub server_ip: String,
    #[serde(rename = "server_port")]
    pub server_port: u16,
    pub password: String,
    pub method: String,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub plugin_opts: Option<HashMap<String, String>>,
}

impl ShadowsocksConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.server_ip.parse::<IpAddr>().is_err() {
            return Err("Неверный IP-адрес сервера Shadowsocks".to_string());
        }
        if self.server_port == 0  self.server_port > 65535 {
            return Err("Неверный порт сервера Shadowsocks".to_string());
        }
        if self.password.is_empty()  self.method.is_empty() {
            return Err("Отсутствует пароль или метод шифрования".to_string());
        }
        Ok(())
    }
}

/// Конфигурация прокси (HTTP/SOCKS5)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(rename = "proxy_ip")]
    pub proxy_ip: String,
    #[serde(rename = "proxy_port")]
    pub proxy_port: u16,
    #[serde(rename = "server_ip")]
    pub target_ip: String,
    #[serde(rename = "server_port")]
    pub target_port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl ProxyConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.proxy_ip.parse::<IpAddr>().is_err() {
            return Err("Неверный IP-адрес прокси".to_string());
        }
        if self.proxy_port == 0  self.proxy_port > 65535 {
            return Err("Неверный порт прокси".to_string());
        }
        if self.target_ip.parse::<IpAddr>().is_err() {
            return Err("Неверный целевой IP".to_string());
        }
        if self.target_port == 0  self.target_port > 65535 {
            return Err("Неверный целевой порт".to_string());
        }
        Ok(())
    }
}

/// Полная конфигурация WireGuard (формат .conf)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConfConfig {
    #[serde(rename = "Interface")]
    pub interface: InterfaceSection,
    #[serde(rename = "Peer")]
    pub peer: PeerSection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceSection {
    pub private_key: Option<String>,
    pub address: Option<String>,
    pub dns: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSection {
    pub public_key: Option<String>,
    pub allowed_ips: Option<String>,
    pub endpoint: Option<String>,
}

impl WireGuardConfConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.interface.private_key.is_none() {
            return Err("Отсутствует приватный ключ в секции [Interface]".to_string());
        }
        if self.peer.public_key.is_none() {
            return Err("Отсутствует публичный ключ в секции [Peer]".to_string());
        }
        if self.peer.endpoint.is_none() {
            return Err("Отсутствует endpoint в секции [Peer]".to_string());
        }
        Ok(())
    }
}

/// Перечисление для всех типов конфигураций
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum ProtocolConfig {
    Wireguard(WireGuardConfig),
    Shadowsocks(ShadowsocksConfig),
    Http(ProxyConfig),
    Socks5(ProxyConfig),
    Openvpn {
        #[serde(rename = "server_ip")]
        server_ip: String,
        #[serde(rename = "server_port")]
        server_port: u16,
        pub auth_user: Option<String>,
        pub auth_pass: Option<String>,
        pub tls_auth: Option<String>,
        pub cipher: Option<String>,
    },
    Plugin {
        #[serde(rename = "plugin_type")]
        plugin_type: String,
        #[serde(rename = "plugin_config")]
        plugin_config: HashMap<String, String>,
    },
}

/// Основная структура конфига
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(flatten)]
    pub servers: HashMap<String, ServerConfig>,
}

/// Поддержка WireGuard .conf формата
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardConf {
    #[serde(rename = "Interface")]
    pub interface: InterfaceSection,
    #[serde(rename = "Peer")]
    pub peer: PeerSection,
}

