use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub tag: String,
    pub protocol: String,
    #[serde(flatten)]
    pub config: ProtocolConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum ProtocolConfig {
    Wireguard(WireguardConfig),
    Shadowsocks(ShadowsocksConfig),
    Http(HttpProxyConfig),
    Socks5(Socks5ProxyConfig),
    // Добавьте другие протоколы по мере необходимости
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardConfig {
    pub server_ip: String,
    pub server_port: u16,
    pub wireguard_private_key: String,
    pub wireguard_public_key: String,
    #[serde(default = "default_ipv6")]
    pub ipv6: bool,
    #[serde(default = "default_sni_obfuscation")]
    pub sni_obfuscation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksConfig {
    pub server_ip: String,
    pub server_port: u16,
    pub password: String,
    pub method: String,
    #[serde(default = "default_plugin")]
    pub plugin: Option<String>,
    #[serde(default = "default_plugin_opts")]
    pub plugin_opts: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProxyConfig {
    pub proxy_ip: String,
    pub proxy_port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5ProxyConfig {
    pub proxy_ip: String,
    pub proxy_port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

// Утилиты для дефолтных значений
fn default_ipv6() -> bool { false }
fn default_sni_obfuscation() -> bool { false }
fn default_plugin() -> Option<String> { None }
fn default_plugin_opts() -> Option<String> { None }
