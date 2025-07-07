use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::collections::HashMap;
use crate::utils::common::{is_valid_ip, is_valid_port, is_valid_cidr};

/// Основная конфигурация клиента VPN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnClientConfig {
    /// Список серверов
    pub servers: HashMap<String, ServerConfig>,
    
    /// Глобальные настройки
    #[serde(default)]
    pub global: GlobalSettings,
    
    /// Настройки по умолчанию для подключения
    #[serde(default)]
    pub defaults: DefaultConnectionSettings,
}

/// Глобальные настройки клиента
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GlobalSettings {
    /// Уровень логирования
    #[serde(default = "default_log_level")]
    pub log_level: String,
    
    /// Использовать системные настройки DNS
    #[serde(default)]
    pub use_system_dns: bool,
    
    /// Путь к пользовательским правилам DNS
    #[serde(default)]
    pub dns_config_path: Option<String>,
    
    /// Использовать балансировку между серверами
    #[serde(default)]
    pub enable_load_balancing: bool,
    
    /// Разрешить использование плагинов
    #[serde(default)]
    pub allow_plugins: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

/// Настройки по умолчанию для подключения
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DefaultConnectionSettings {
    /// Тип используемого протокола по умолчанию
    #[serde(default = "default_protocol")]
    pub protocol: String,
    
    /// Использовать TCP вместо UDP по умолчанию
    #[serde(default)]
    pub prefer_tcp: bool,
    
    /// Таймаут подключения по умолчанию (в секундах)
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout: u64,
    
    /// Максимальное количество попыток подключения
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    
    /// Интервал между попытками подключения (в секундах)
    #[serde(default = "default_retry_interval")]
    pub retry_interval: u64,
}

fn default_protocol() -> String {
    "wireguard".to_string()
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_max_retries() -> u32 {
    3
}

fn default_retry_interval() -> u64 {
    5
}

/// Основная конфигурация сервера
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase")]
pub enum ServerConfig {
    Wireguard(WireguardServerConfig),
    Shadowsocks(ShadowsocksServerConfig),
    Openvpn(OpenvpnServerConfig),
    Http(HttpProxyConfig),
    Socks5(Socks5ProxyConfig),
}

/// Конфигурация сервера WireGuard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardServerConfig {
    /// Внутренний IP-адрес сервера
    pub in_ip: String,
    
    /// Внешний IP-адрес сервера
    pub out_ip: String,
    
    /// Порт сервера
    pub server_port: u16,
    
    /// Приватный ключ сервера
    pub wireguard_private_key: String,
    
    /// Публичный ключ сервера
    pub wireguard_public_key: String,
    
    /// Поддержка IPv6
    #[serde(default = "default_false")]
    pub ipv6: bool,
    
    /// MTU для подключения
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    
    /// Настройки обфускации
    #[serde(default)]
    pub obfuscation: Option<ObfuscationConfig>,
    
    /// Расширенные настройки маршрутизации
    #[serde(default)]
    pub advanced_routing: Option<RoutingConfig>,
    
    /// Пользовательские метки
    #[serde(default)]
    pub custom_tags: Vec<String>,
}

/// Конфигурация сервера Shadowsocks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowsocksServerConfig {
    /// IP-адрес сервера
    pub server_ip: String,
    
    /// Порт сервера
    pub server_port: u16,
    
    /// Пароль для подключения
    pub password: String,
    
    /// Метод шифрования
    pub method: String,
    
    /// Настройки плагина (например, v2ray-plugin)
    #[serde(default)]
    pub plugin_options: Option<PluginOptions>,
    
    /// Настройки обфускации
    #[serde(default)]
    pub obfuscation: Option<ObfuscationConfig>,
    
    /// Расширенные настройки маршрутизации
    #[serde(default)]
    pub advanced_routing: Option<RoutingConfig>,
    
    /// Пользовательские метки
    #[serde(default)]
    pub custom_tags: Vec<String>,
}

/// Конфигурация сервера OpenVPN
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenvpnServerConfig {
    /// IP-адрес сервера
    pub server_ip: String,
    
    /// Порт сервера
    pub server_port: u16,
    
    /// Путь к файлу конфигурации OpenVPN
    pub config_file: String,
    
    /// Имя пользователя для подключения
    pub username: Option<String>,
    
    /// Пароль пользователя
    pub password: Option<String>,
    
    /// Расширенные настройки маршрутизации
    #[serde(default)]
    pub advanced_routing: Option<RoutingConfig>,
    
    /// Пользовательские метки
    #[serde(default)]
    pub custom_tags: Vec<String>,
}

/// Конфигурация HTTP прокси
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProxyConfig {
    /// IP-адрес прокси
    pub proxy_ip: String,
    
    /// Порт прокси
    pub proxy_port: u16,
    
    /// Целевой IP-адрес
    pub target_ip: String,
    
    /// Целевой порт
    pub target_port: u16,
    
    /// Имя пользователя (если требуется)
    pub username: Option<String>,
    
    /// Пароль (если требуется)
    pub password: Option<String>,
    
    /// Расширенные настройки маршрутизации
    #[serde(default)]
    pub advanced_routing: Option<RoutingConfig>,
    
    /// Пользовательские метки
    #[serde(default)]
    pub custom_tags: Vec<String>,
}

/// Конфигурация SOCKS5 прокси
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5ProxyConfig {
    /// IP-адрес прокси
    pub proxy_ip: String,
    
    /// Порт прокси
    pub proxy_port: u16,
    
    /// Целевой IP-адрес
    pub target_ip: String,
    
    /// Целевой порт
    pub target_port: u16,
    
    /// Имя пользователя (если требуется)
    pub username: Option<String>,
    
    /// Пароль (если требуется)
    pub password: Option<String>,
    
    /// Расширенные настройки маршрутизации
    #[serde(default)]
    pub advanced_routing: Option<RoutingConfig>,
    
    /// Пользовательские метки
    #[serde(default)]
    pub custom_tags: Vec<String>,
}

/// Настройки обфускации
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObfuscationConfig {
    /// Тип обфускации
    pub type_: String,
    
    /// Метод шифрования (для Shadowsocks и других)
    #[serde(default)]
    pub method: Option<String>,
    
    /// Пароль (для Shadowsocks и других)
    #[serde(default)]
    pub password: Option<String>,
    
    /// Дополнительные опции плагина
    #[serde(default)]
    pub plugin_options: Option<PluginOptions>,
}

/// Дополнительные опции плагинов
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginOptions {
    /// Режим работы (tcp_and_udp, tcp_only и т.д.)
    #[serde(default = "default_plugin_mode")]
    pub mode: String,
    
    /// Хост для маскировки
    #[serde(default)]
    pub host: Option<String>,
    
    /// TLS версия
    #[serde(default)]
    pub tls_version: Option<String>,
    
    /// Сертификат CA
    #[serde(default)]
    pub ca_cert: Option<String>,
    
    /// Дополнительные аргументы
    #[serde(default)]
    pub args: Vec<String>,
}

fn default_plugin_mode() -> String {
    "tcp_and_udp".to_string()
}

/// Расширенные настройки маршрутизации
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// DNS серверы
    #[serde(default)]
    pub dns: Vec<String>,
    
    /// Статические маршруты
    #[serde(default)]
    pub routes: Vec<RouteEntry>,
    
    /// Белый список разрешенных адресов
    #[serde(default)]
    pub allow_list: Option<Vec<String>>,
    
    /// Черный список запрещенных адресов
    #[serde(default)]
    pub block_list: Option<Vec<String>>,
    
    /// Настройки автоматической балансировки
    #[serde(default)]
    pub balancer: Option<BalancerSettings>,
}

/// Конфигурация маршрута
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    /// Целевой CIDR
    pub destination: String,
    
    /// Шлюз
    pub gateway: String,
    
    /// Приоритет маршрута
    #[serde(default)]
    pub priority: Option<u8>,
    
    /// Метка интерфейса
    #[serde(default)]
    pub interface: Option<String>,
}

/// Настройки балансировки нагрузки
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalancerSettings {
    /// Максимальное время RTT для серверов
    #[serde(default = "default_max_rtt")]
    pub max_server_rtt: u64,
    
    /// Интервал проверки серверов
    #[serde(default = "default_check_interval")]
    pub check_interval: u64,
    
    /// Интервал проверки лучшего сервера
    #[serde(default)]
    pub check_best_interval: Option<u64>,
    
    /// Максимальное количество рабочих потоков
    #[serde(default = "default_worker_count")]
    pub worker_count: usize,
}

fn default_max_rtt() -> u64 {
    5
}

fn default_check_interval() -> u64 {
    10
}

fn default_worker_count() -> usize {
    10
}

/// Типы поддерживаемых протоколов
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolType {
    Tcp,
    Udp,
    WireGuard,
    Shadowsocks,
    OpenVpn,
    HttpProxy,
    Socks5,
    Plugin(String),
}

/// Интерфейс для валидации конфигураций
pub trait Validatable {
    fn validate(&self) -> Result<(), String>;
}

impl Validatable for VpnClientConfig {
    fn validate(&self) -> Result<(), String> {
        // Проверяем все серверы
        for (name, server) in &self.servers {
            server.validate().map_err(|e| format!("Сервер {}: {}", name, e))?;
        }
        
        // Проверяем глобальные настройки
        if !["debug", "info", "warn", "error"].contains(&self.global.log_level.as_str()) {
            return Err("Недопустимый уровень логирования".to_string());
        }
        
        Ok(())
    }
}

impl Validatable for ServerConfig {
    fn validate(&self) -> Result<(), String> {
        match self {
            ServerConfig::Wireguard(cfg) => cfg.validate(),
            ServerConfig::Shadowsocks(cfg) => cfg.validate(),
            ServerConfig::Openvpn(cfg) => cfg.validate(),
            ServerConfig::Http(cfg) => cfg.validate(),
            ServerConfig::Socks5(cfg) => cfg.validate(),
        }
    }
}

impl Validatable for WireguardServerConfig {
    fn validate(&self) -> Result<(), String> {
        if !is_valid_ip(&self.in_ip) {
            return Err(format!("Недопустимый внутренний IP-адрес: {}", self.in_ip));
        }
        
        if !is_valid_ip(&self.out_ip) {
            return Err(format!("Недопустимый внешний IP-адрес: {}", self.out_ip));
        }
        
        if !is_valid_port(self.server_port) {
            return Err(format!("Недопустимый порт сервера: {}", self.server_port));
        }
        
        if self.wireguard_private_key.is_empty() {
            return Err("Приватный ключ WireGuard не может быть пустым".to_string());
        }
        
        if self.wireguard_public_key.is_empty() {
            return Err("Публичный ключ WireGuard не может быть пустым".to_string());
        }
        
        if let Some(ref obfuscation) = self.obfuscation {
            obfuscation.validate()?;
        }
        
        if let Some(ref routing) = self.advanced_routing {
            routing.validate()?;
        }
        
        Ok(())
    }
}

impl Validatable for ShadowsocksServerConfig {
    fn validate(&self) -> Result<(), String> {
        if !is_valid_ip(&self.server_ip) {
            return Err(format!("Недопустимый IP-адрес сервера: {}", self.server_ip));
        }
        
        if !is_valid_port(self.server_port) {
            return Err(format!("Недопустимый порт сервера: {}", self.server_port));
        }
        
        if self.password.is_empty() {
            return Err("Пароль не может быть пустым".to_string());
        }
        
        if self.method.is_empty() {
            return Err("Метод шифрования не может быть пустым".to_string());
        }
        
        if let Some(ref obfuscation) = self.obfuscation {
            obfuscation.validate()?;
        }
        
        if let Some(ref routing) = self.advanced_routing {
            routing.validate()?;
        }
        
        Ok(())
    }
}

impl Validatable for OpenvpnServerConfig {
    fn validate(&self) -> Result<(), String> {
        if !is_valid_ip(&self.server_ip) {
            return Err(format!("Недопустимый IP-адрес сервера: {}", self.server_ip));
        }
        
        if !is_valid_port(self.server_port) {
            return Err(format!("Недопустимый порт сервера: {}", self.server_port));
        }
        
        if self.config_file.is_empty() {
            return Err("Путь к конфигурации OpenVPN не может быть пустым".to_string());
        }
        
        if let Some(ref routing) = self.advanced_routing {
            routing.validate()?;
        }
        
        Ok(())
    }
}

impl Validatable for HttpProxyConfig {
    fn validate(&self) -> Result<(), String> {
        if !is_valid_ip(&self.proxy_ip) {
            return Err(format!("Недопустимый IP-адрес прокси: {}", self.proxy_ip));
        }
        
        if !is_valid_port(self.proxy_port) {
            return Err(format!("Недопустимый порт прокси: {}", self.proxy_port));
        }
        
        if !is_valid_ip(&self.target_ip) {
            return Err(format!("Недопустимый целевой IP-адрес: {}", self.target_ip));
        }
        
        if !is_valid_port(self.target_port) {
            return Err(format!("Недопустимый целевой порт: {}", self.target_port));
        }
        
        if let Some(ref routing) = self.advanced_routing {
            routing.validate()?;
        }
        
        Ok(())
    }
}

impl Validatable for Socks5ProxyConfig {
    fn validate(&self) -> Result<(), String> {
        if !is_valid_ip(&self.proxy_ip) {
            return Err(format!("Недопустимый IP-адрес прокси: {}", self.proxy_ip));
        }
        
        if !is_valid_port(self.proxy_port) {
            return Err(format!("Недопустимый порт прокси: {}", self.proxy_port));
        }
        
        if !is_valid_ip(&self.target_ip) {
            return Err(format!("Недопустимый целевой IP-адрес: {}", self.target_ip));
        }
        
        if !is_valid_port(self.target_port) {
            return Err(format!("Недопустимый целевой порт: {}", self.target_port));
        }
        
        if let Some(ref routing) = self.advanced_routing {
            routing.validate()?;
        }
        
        Ok(())
    }
}

impl Validatable for ObfuscationConfig {
    fn validate(&self) -> Result<(), String> {
        if !["shadowsocks-over-wireguard", "dpi-bypass", "fragmentation", "timing"].contains(&self.type_.as_str()) {
            return Err(format!("Неподдерживаемый тип обфускации: {}", self.type_));
        }
        
        if self.type_ == "shadowsocks-over-wireguard" && (self.method.is_none() || self.password.is_none()) {
            return Err("Для Shadowsocks-over-WireGuard требуются метод и пароль".to_string());
        }
        
        if let Some(ref plugin) = self.plugin_options {
            plugin.validate()?;
        }
        
        Ok(())
    }
}

impl Validatable for PluginOptions {
    fn validate(&self) -> Result<(), String> {
        if !["tcp_only", "tcp_and_udp", "udp_only"].contains(&self.mode.as_str()) {
            return Err(format!("Неподдерживаемый режим плагина: {}", self.mode));
        }
        
        Ok(())
    }
}

impl Validatable for RoutingConfig {
    fn validate(&self) -> Result<(), String> {
        // Проверяем DNS
        for dns in &self.dns {
            if !is_valid_ip(dns) {
                return Err(format!("Недопустимый DNS сервер: {}", dns));
            }
        }
        
        // Проверяем маршруты
        for route in &self.routes {
            if !is_valid_cidr(&route.destination) {
                return Err(format!("Недопустимый CIDR маршрута: {}", route.destination));
            }
            
            if !is_valid_ip(&route.gateway) {
                return Err(format!("Недопустимый шлюз маршрута: {}", route.gateway));
            }
        }
        
        Ok(())
    }
}

// Вспомогательные функции
fn default_false() -> bool {
    false
}

fn default_true() -> bool {
    true
}

fn default_mtu() -> u16 {
    1420
}

fn default_empty_string() -> String {
    String::new()
}
