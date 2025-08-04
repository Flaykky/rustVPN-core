use crate::config::model::{Config, ProtocolConfig, ServerConfig, WireGuardConf, WireGuardConfConfig};
use crate::utils::error::VpnError;
use crate::utils::common::{is_valid_ip, is_valid_port, is_valid_cidr};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::net::{IpAddr, SocketAddr};
use std::collections::HashMap;

/// Parses a WireGuard .conf file
pub fn parse_wireguard_conf<P: AsRef<Path>>(path: P) -> Result<WireGuardConfConfig, VpnError> {
    let content = fs::read_to_string(path.as_ref()).map_err(|e| {
        VpnError::ConfigError(format!("Failed to read WireGuard .conf: {}", e))
    })?;

    let mut interface = InterfaceSection {
        private_key: None,
        address: None,
        dns: None,
    };
    let mut peer = PeerSection {
        public_key: None,
        allowed_ips: None,
        endpoint: None,
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let parts: Vec<&str> = line.split('=').collect();
        if parts.len() != 2 {
            continue;
        }

        let key = parts[0].trim();
        let value = parts[1].trim();

        match key {
            "PrivateKey" => interface.private_key = Some(value.to_string()),
            "Address" => interface.address = Some(value.to_string()),
            "DNS" => interface.dns = Some(value.to_string()),
            "PublicKey" => peer.public_key = Some(value.to_string()),
            "AllowedIPs" => peer.allowed_ips = Some(value.to_string()),
            "Endpoint" => peer.endpoint = Some(value.to_string()),
            _ => {}
        }
    }

    if interface.private_key.is_none() || peer.public_key.is_none() || peer.endpoint.is_none() {
        return Err(VpnError::ConfigError("Missing fields in WireGuard .conf".to_string()));
    }

    Ok(WireGuardConfConfig { interface, peer })
}

/// Parses a regular JSON config
pub fn parse_config<P: AsRef<Path>>(path: P) -> Result<Vec<ServerConfig>, VpnError> {
    let content = fs::read_to_string(path.as_ref()).map_err(|e| {
        VpnError::ConfigError(format!("Failed to read configuration file: {}", e))
    })?;

    let json: Value = serde_json::from_str(&content).map_err(|e| {
        VpnError::ConfigError(format!("JSON parsing error: {}", e))
    })?;

    let servers = match json.as_object() {
        Some(obj) => {
            let mut server_list = Vec::new();
            for (tag, value) in obj {
                let mut server: ServerConfig = serde_json::from_value(value.clone()).map_err(|e| {
                    VpnError::ConfigError(format!("Server parsing error {}: {}", tag, e))
                })?;
                server.tag = tag.clone();
                validate_server_config(&server)?;
                server_list.push(server);
            }
            server_list
        }
        None => return Err(VpnError::ConfigError("Invalid configuration format".to_string())),
    };

    Ok(servers)
}

/// Validates a server by its protocol
fn validate_server_config(config: &ServerConfig) -> Result<(), VpnError> {
    match &config.protocol {
        ProtocolType::Wireguard => {
            let wg = WireGuardConfig {
                endpoint_ip: config.server_ip.clone().ok_or_else(|| {
                    VpnError::ConfigError("Missing server_ip for WireGuard".to_string())
                })?,
                endpoint_port: config.server_port.ok_or_else(|| {
                    VpnError::ConfigError("Missing server_port for WireGuard".to_string())
                })?,
                wireguard_private_key: config.wireguard_private_key.clone().ok_or_else(|| {
                    VpnError::ConfigError("Missing wireguard_private_key".to_string())
                })?,
                wireguard_public_key: config.wireguard_public_key.clone().ok_or_else(|| {
                    VpnError::ConfigError("Missing wireguard_public_key".to_string())
                })?,
                mtu: config.mtu,
                ipv6: config.ipv6,
                obfuscation: config.obfuscation.clone(),
            };
            wg.validate()?;
        }
        ProtocolType::Shadowsocks => {
            let ss = ShadowsocksConfig {
                server_ip: config.server_ip.clone().ok_or_else( {
                    VpnError::ConfigError("Missing server_ip for Shadowsocks".to_string())
                })?,
                server_port: config.server_port.ok_or_else( {
                    VpnError::ConfigError("Missing server_port for Shadowsocks".to_string())
                })?,
                password: config.password.clone().ok_or_else( {
                    VpnError::ConfigError("Missing password for Shadowsocks".to_string())
                })?,
                method: config.method.clone().ok_or_else( {
                    VpnError::ConfigError("Missing method for Shadowsocks".to_string())
                })?,
                plugin: config.plugin.clone(),
                plugin_opts: config.plugin_opts.clone(),
            };
            ss.validate()?;
        }
        ProtocolType::Http | ProtocolType::Socks5 => {
            let proxy = ProxyConfig {
                proxy_ip: config.proxy_ip.clone().ok_or_else( {
                    VpnError::ConfigError("Missing proxy_ip for proxy".to_string())
                })?,
                proxy_port: config.proxy_port.ok_or_else( {
                    VpnError::ConfigError("Missing proxy_port for proxy".to_string())
                })?,
                target_ip: config.server_ip.clone().ok_or_else( {
                    VpnError::ConfigError("Missing server_ip for proxy".to_string())
                })?,
                target_port: config.server_port.ok_or_else(|| {
                    VpnError::ConfigError("Missing server_port for proxy".to_string())
                })?,
                username: config.username.clone(),
                password: config.password.clone(),
            };
            proxy.validate()?;
        }
        ProtocolType::Openvpn => {
            // You can add validation for OpenVPN here
        }
        ProtocolType::Plugin(plugin_name) => {
            // You can add validation for plugins here
        }
    }
    Ok(())
}
