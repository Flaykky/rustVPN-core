/*
main features:
- Shadowsocks struct:
    • new(server_ip, server_port, password, method, tun_name, tun_addr)
      – валидирует IP, порт, метод шифрования и параметры TUN;
- Protocol impl for Shadowsocks:
    • connect() -> ShadowsocksConnection
      – формирует ServerConfig и LocalConfig для TUN‑режима;
      – собирает глобальную Config и запускает run_local() в фоне;
- ShadowsocksConnection struct:
    • send_packet / receive_packet
      – не поддерживаются в TUN‑режиме (возвращают ошибку);
    • close()
      – заглушка (всегда Ok);

examples:
// Инициализация клиента:
let ss = Shadowsocks::new(
    "1.2.3.4",       // server_ip
    8388,            // server_port
    "your_passwd",   // password
    "aes-256-gcm",   // method
    "tun0",          // tun_interface_name
    "10.0.0.1/24",   // tun_interface_address
)?;

// Подключение (запускает клиент в фоне):
let mut conn = ss.connect().await?;

// В TUN‑режиме отправка/прием пакетов не поддерживаются
// conn.send_packet(&packet).await.unwrap_err();
*/



use shadowsocks::config::{Config, LocalConfig, ServerConfig};
use shadowsocks::run_local;
use crate::utils::logging::{log_debug, log_info, log_warn};
use crate::utils::error::VpnError;
use std::net::SocketAddr;
use super::{Protocol, Connection};

pub struct Shadowsocks {
    server_ip: String,
    server_port: u16,
    password: String,
    method: String,
    tun_interface_name: String,
    tun_interface_address: String,
}

impl Shadowsocks {
    pub fn new(
        server_ip: &str,
        server_port: u16,
        password: &str,
        method: &str,
        tun_interface_name: &str,
        tun_interface_address: &str,
    ) -> Result<Self, VpnError> {
        log_info!("Initializing Shadowsocks with server {}:{}", server_ip, server_port);

        // Check server IP
        server_ip.parse::<std::net::IpAddr>().map_err(|e| {
            log_warn!("Invalid server IP address: {}", e);
            VpnError::ConfigError(format!("Invalid server IP address: {}", e))
        })?;

        // Check encryption method
        if !["aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-256-gcm"].contains(&method) {
            log_warn!("Unsupported encryption method: {}", method);
            return Err(VpnError::ConfigError(format!("Unsupported encryption method: {}", method)));
        }

        // Check TUN parameters
        if tun_interface_name.is_empty() {
            return Err(VpnError::ConfigError("TUN interface name cannot be empty".to_string()));
        }

        if tun_interface_address.is_empty() {
            return Err(VpnError::ConfigError("TUN interface address cannot be empty".to_string()));
        }

        Ok(Self {
            server_ip: server_ip.to_string(),
            server_port,
            password: password.to_string(),
            method: method.to_string(),
            tun_interface_name: tun_interface_name.to_string(),
            tun_interface_address: tun_interface_address.to_string(),
        })
    }
}

#[async_trait::async_trait]
impl Protocol for Shadowsocks {
    type Connection = ShadowsocksConnection;

    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        log_info!("Configuring Shadowsocks connection with TUN interface");

        // Create server address
        let server_addr = SocketAddr::new(
            self.server_ip.parse().map_err(|e| {
                log_warn!("Invalid server IP address: {}", e);
                VpnError::ConfigError(format!("Invalid server IP address: {}", e))
            })?,
            self.server_port,
        );

        // Create server configuration
        let server_config = ServerConfig {
            address: server_addr,
            method: self.method.parse().map_err(|e| {
                log_warn!("Invalid encryption method: {}", e);
                VpnError::ConfigError(format!("Invalid encryption method: {}", e))
            })?,
            password: Some(self.password.clone()),
            ..Default::default()
        };

        // Create local configuration for TUN
        let local_config = LocalConfig {
            protocol: shadowsocks::config::ProtocolType::Tun,
            tun_interface_name: Some(self.tun_interface_name.clone()),
            tun_interface_address: Some(self.tun_interface_address.clone()),
            local_address: Some("0.0.0.0".to_string()),
            local_port: None,
            outbound_udp_ip: None,
            outbound_udp_port: None,
            plugin: None,
            plugin_opts: None,
            manager_address: None,
            acl: None,
            dns: None,
            mode: shadowsocks::config::Mode::TcpUdp,
            no_delay: true,
            fast_open: false,
            reuse_port: false,
            ipv6_first: false,
        };

        // Global configuration
        let config = Config {
            local: vec![local_config],
            server: vec![server_config],
            manager_address: None,
            manager_port: None,
            local_address: None,
            no_delay: true,
            fast_open: false,
            reuse_port: false,
            ipv6_first: false,
            mode: shadowsocks::config::Mode::TcpUdp,
        };

        // Start Shadowsocks in a separate task
        tokio::spawn(async move {
            log_info!("Starting Shadowsocks client in TUN mode");
            if let Err(e) = run_local(config).await {
                log_warn!("Error in run_local: {}", e);
            }
        });

        log_info!("Shadowsocks connection setup completed");
        Ok(ShadowsocksConnection {})
    }
}

pub struct ShadowsocksConnection {}

#[async_trait::async_trait]
impl Connection for ShadowsocksConnection {
    async fn send_packet(&mut self, _packet: &[u8]) -> Result<(), VpnError> {
        log_debug!("TUN mode: send_packet is not supported");
        Err(VpnError::ConnectionError("TUN mode: send_packet is not supported".to_string()))
    }

    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        log_debug!("TUN mode: receive_packet is not supported");
        Err(VpnError::ConnectionError("TUN mode: receive_packet is not supported".to_string()))
    }

    async fn close(&mut self) -> Result<(), VpnError> {
        log_info!("TUN mode: Closing connection is not supported");
        Ok(())
    }
}
