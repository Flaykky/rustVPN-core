pub mod proxy;
pub mod wireguard;
pub mod shadowsocks;
pub mod basic_tcp;
pub mod basic_udp;

// Экспортируем основные интерфейсы
pub use proxy::{HttpProxy, Socks5Proxy};
pub use wireguard::WireGuard;
pub use shadowsocks::Shadowsocks;
pub use basic_tcp::BasicTcp;
pub use basic_udp::BasicUdp;

// Общий trait для всех протоколов
pub trait Protocol {
    type Connection: Connection;
    fn connect(&self) -> Pin<Box<dyn Future<Output = Result<Self::Connection, VpnError>> + Send + '_>>;
}

// Общий trait для всех типов соединений
#[async_trait::async_trait]
pub trait Connection: Send + Sync {
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError>;
    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError>;
    async fn close(&mut self) -> Result<(), VpnError>;
}

// Перечисление для поддерживаемых протоколов
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolType {
    Tcp,
    Udp,
    WireGuard,
    Shadowsocks,
    HttpProxy,
    Socks5,
}

// Фабрика протоколов
pub struct ProtocolFactory;

impl ProtocolFactory {
    pub fn create(config: &ServerConfig) -> Result<Box<dyn Protocol<Connection = dyn Connection>>, VpnError> {
        match config.config {
            ProtocolConfig::Wireguard(ref wg) => Ok(Box::new(WireGuard::new(wg.clone())?)),
            ProtocolConfig::Shadowsocks(ref ss) => Ok(Box::new(Shadowsocks::new(ss.clone())?)),
            ProtocolConfig::Http(ref http) => Ok(Box::new(HttpProxy::new(
                &http.proxy_ip, 
                http.proxy_port, 
                &config.server_ip, 
                config.server_port
            )?)),
            ProtocolConfig::Socks5(ref socks) => Ok(Box::new(Socks5Proxy::new(
                &socks.proxy_ip, 
                socks.proxy_port, 
                &config.server_ip, 
                config.server_port,
                socks.username.clone(),
                socks.password.clone()
            )?)),
        }
    }
}
