// src/utils/config.rs

use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::Path,
};
use anyhow::{Result, Context};
use crate::utils::logging::{log, LogLevel};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub protocol: String,
    pub server: String,
    pub port: u16,
    pub login: String,
    pub password: String,
    pub country: Option<String>,
    pub city: Option<String>,
    pub use_udp: bool,
    pub enable_dpi: bool,
    pub enable_udp_over_tcp: bool,
    pub wireguard_private_key: Option<String>,
    pub wireguard_peer_public_key: Option<String>,
    pub dns_server: Option<String>,
    pub proxy_type: Option<String>,
}

impl ServerConfig {
    pub fn socket_addr(&self) -> SocketAddr {
        format!("{}:{}", self.server, self.port)
            .parse()
            .expect("Invalid socket address")
    }

    pub fn validate(&self) -> Result<()> {
        if !self.server.parse::<IpAddr>().is_ok() {
            anyhow::bail!("Invalid server IP: {}", self.server);
        }
        if self.port == 0 || self.port > 65535 {
            anyhow::bail!("Invalid port: {}", self.port);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub servers: Vec<ServerConfig>,
    pub default_server: Option<usize>,
    pub log_level: Option<LogLevel>,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file = File::open(&path)
            .with_context(|| format!("Failed to open config file: {}", path.as_ref().display()))?;
        
        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .context("Failed to read config file")?;
        
        let mut config: Self = serde_json::from_str(&contents)
            .context("Failed to parse config JSON")?;
        
        for server in &config.servers {
            server.validate()?;
        }
        
        log!(LogLevel::Info, "Loaded configuration from {}", path.as_ref().display());
        Ok(config)
    }

    pub fn get_active_server(&self) -> Option<&ServerConfig> {
        self.default_server
            .and_then(|index| self.servers.get(index))
            .or_else(|| self.servers.first())
    }
}

pub fn parse_cmd_args() -> clap::ArgMatches {
    clap::App::new("vpn-client")
        .version("0.1")
        .author("Your Name <you@example.com>")
        .about("Cross-platform VPN client")
        .arg(clap::Arg::with_name("config")
            .short('c')
            .long("config")
            .value_name("FILE")
            .about("Sets a custom config file")
            .default_value("config.json"))
        .arg(clap::Arg::with_name("server")
            .short('s')
            .long("server")
            .value_name("INDEX")
            .about("Select server by index"))
        .arg(clap::Arg::with_name("dpi")
            .short('d')
            .long("dpi")
            .about("Enable DPI bypass"))
        .arg(clap::Arg::with_name("uot")
            .short('u')
            .long("udp-over-tcp")
            .about("Enable UDP over TCP"))
        .get_matches()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let valid_config = ServerConfig {
            protocol: "wireguard".into(),
            server: "192.168.1.1".into(),
            port: 51820,
            login: "user".into(),
            password: "pass".into(),
            use_udp: true,
            enable_dpi: false,
            enable_udp_over_tcp: false,
            ..Default::default()
        };
        assert!(valid_config.validate().is_ok());

        let invalid_config = ServerConfig {
            server: "invalid_ip".into(),
            port: 70000,
            ..valid_config.clone()
        };
        assert!(invalid_config.validate().is_err());
        
    }
}