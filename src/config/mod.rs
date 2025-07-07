pub mod model;
pub mod parser;

pub use model::{
    VpnClientConfig, 
    ServerConfig, 
    WireguardServerConfig,
    ShadowsocksServerConfig,
    OpenvpnServerConfig,
    HttpProxyConfig,
    Socks5ProxyConfig,
    ObfuscationConfig,
    PluginOptions,
    RoutingConfig,
    RouteEntry,
    BalancerSettings,
    ProtocolType,
    Validatable,
};

pub use parser::{parse_config, parse_config_from_str, is_valid_ip, is_valid_port, is_valid_cidr};
