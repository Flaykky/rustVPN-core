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
        log_info!("Инициализация Shadowsocks с сервером {}:{}", server_ip, server_port);

        // Проверка IP
        server_ip.parse::<std::net::IpAddr>().map_err(|e| {
            log_warn!("Некорректный IP-адрес сервера: {}", e);
            VpnError::ConfigError(format!("Некорректный IP-адрес сервера: {}", e))
        })?;

        // Проверка метода шифрования
        if !["aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-256-gcm"].contains(&method) {
            log_warn!("Неподдерживаемый метод шифрования: {}", method);
            return Err(VpnError::ConfigError(format!("Неподдерживаемый метод шифрования: {}", method)));
        }

        // Проверка TUN-параметров
        if tun_interface_name.is_empty() {
            return Err(VpnError::ConfigError("Имя TUN-интерфейса не может быть пустым".to_string()));
        }

        if tun_interface_address.is_empty() {
            return Err(VpnError::ConfigError("Адрес TUN-интерфейса не может быть пустым".to_string()));
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
        log_info!("Настройка соединения Shadowsocks с TUN-интерфейсом");

        // Создание адреса сервера
        let server_addr = SocketAddr::new(
            self.server_ip.parse().map_err(|e| {
                log_warn!("Некорректный IP-адрес сервера: {}", e);
                VpnError::ConfigError(format!("Некорректный IP-адрес сервера: {}", e))
            })?,
            self.server_port,
        );

        // Создание конфигурации сервера
        let server_config = ServerConfig {
            address: server_addr,
            method: self.method.parse().map_err(|e| {
                log_warn!("Неверный метод шифрования: {}", e);
                VpnError::ConfigError(format!("Неверный метод шифрования: {}", e))
            })?,
            password: Some(self.password.clone()),
            ..Default::default()
        };

        // Создание локальной конфигурации для TUN
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

        // Общая конфигурация
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

        // Запуск Shadowsocks в отдельной задаче
        tokio::spawn(async move {
            log_info!("Запуск Shadowsocks клиента в режиме TUN");
            if let Err(e) = run_local(config).await {
                log_warn!("Ошибка в run_local: {}", e);
            }
        });

        log_info!("Настройка соединения Shadowsocks завершена");
        Ok(ShadowsocksConnection {})
    }
}

pub struct ShadowsocksConnection {}

#[async_trait::async_trait]
impl Connection for ShadowsocksConnection {
    async fn send_packet(&mut self, _packet: &[u8]) -> Result<(), VpnError> {
        log_debug!("TUN-режим: send_packet не поддерживается");
        Err(VpnError::ConnectionError("TUN-режим: send_packet не поддерживается".to_string()))
    }

    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        log_debug!("TUN-режим: receive_packet не поддерживается");
        Err(VpnError::ConnectionError("TUN-режим: receive_packet не поддерживается".to_string()))
    }

    async fn close(&mut self) -> Result<(), VpnError> {
        log_info!("TUN-режим: Закрытие соединения не поддерживается");
        Ok(())
    }
}
