use crate::utils::logging::{log_debug, log_info, log_warn};
use crate::utils::error::VpnError;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use super::super::super::super::super::{Protocol, Connection};

/// Represents an HTTPS proxy connection configuration.
pub struct HttpsProxy {
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
}

impl HttpsProxy {
    /// Creates a new HttpsProxy instance with the given proxy and target addresses.
    pub fn new(proxy_ip: &str, proxy_port: u16, target_ip: &str, target_port: u16) -> Result<Self, VpnError> {
        log_info!("Initializing HTTPS proxy: {}:{} -> {}:{}", proxy_ip, proxy_port, target_ip, target_port);

        // Parse proxy address
        let proxy_addr = format!("{}:{}", proxy_ip, proxy_port)
            .parse::<SocketAddr>()
            .map_err(|e| {
                log_warn!("Invalid proxy address {}:{}", proxy_ip, proxy_port);
                VpnError::ConfigError(format!("Invalid proxy address: {}", e))
            })?;

        // Parse target address
        let target_addr = format!("{}:{}", target_ip, target_port)
            .parse::<SocketAddr>()
            .map_err(|e| {
                log_warn!("Invalid target address {}:{}", target_ip, target_port);
                VpnError::ConfigError(format!("Invalid target address: {}", e))
            })?;

        log_info!("HTTPS proxy successfully initialized");
        Ok(Self { proxy_addr, target_addr })
    }
}

#[async_trait::async_trait]
impl Protocol for HttpsProxy {
    type Connection = HttpsProxyConnection;

    /// Establishes a connection to the HTTPS proxy and performs the CONNECT handshake.
    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        log_info!("Attempting to connect to HTTPS proxy: {}", self.proxy_addr);

        // Connect to the proxy server
        let mut stream = TcpStream::connect(self.proxy_addr).await
            .map_err(|e| {
                log_warn!("Failed to connect to HTTPS proxy {}: {}", self.proxy_addr, e);
                VpnError::ConnectionError(format!("Failed to connect to proxy: {}", e))
            })?;

        // Prepare the CONNECT request for the target address
        log_debug!("Creating CONNECT request for {}", self.target_addr);
        let host = self.target_addr.ip().to_string();
        let port = self.target_addr.port();
        let request = format!("CONNECT {}:{} HTTP/1.1\r\nHost: {}\r\n\r\n", host, port, host);

        // Send the CONNECT request to the proxy
        log_debug!("Sending CONNECT request: {:?}", request);
        stream.write_all(request.as_bytes()).await
            .map_err(|e| {
                log_warn!("Failed to send CONNECT request to proxy {}: {}", self.proxy_addr, e);
                VpnError::ConnectionError(format!("Failed to send CONNECT request: {}", e))
            })?;

        // Read the response from the proxy
        let mut buffer = [0u8; 1024];
        let n = stream.read(&mut buffer).await
            .map_err(|e| {
                log_warn!("Failed to receive response from proxy {}: {}", self.proxy_addr, e);
                VpnError::ConnectionError(format!("Failed to read proxy response: {}", e))
            })?;

        let response = String::from_utf8_lossy(&buffer[..n]);
        log_debug!("Received response from proxy: {}", response);

        // Check if the proxy accepted the CONNECT request
        if !response.starts_with("HTTP/1.1 200") {
            log_warn!("Proxy {} rejected CONNECT request", self.proxy_addr);
            return Err(VpnError::ConnectionError(format!("Proxy rejected CONNECT request: {}", response)));
        }

        log_info!("Successfully established connection through HTTPS proxy {}", self.proxy_addr);
        Ok(HttpsProxyConnection { stream })
    }
}

/// Represents an active connection through an HTTPS proxy.
pub struct HttpsProxyConnection {
    stream: TcpStream,
}

#[async_trait::async_trait]
impl Connection for HttpsProxyConnection {
    /// Sends a packet of data through the HTTPS proxy connection.
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        log_debug!("Sending {} bytes through HTTPS proxy", packet.len());
        self.stream.write_all(packet).await
            .map_err(|e| {
                log_warn!("Failed to send data through HTTPS proxy: {}", e);
                VpnError::ConnectionError(format!("Failed to send data through HTTPS proxy: {}", e))
            })
    }

    /// Receives a packet of data from the HTTPS proxy connection.
    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        // Allocate a large buffer for incoming data
        let mut buffer = vec![0u8; 65535];
        let n = self.stream.read(&mut buffer).await
            .map_err(|e| {
                log_warn!("Failed to receive data through HTTPS proxy: {}", e);
                VpnError::ConnectionError(format!("Failed to receive data through HTTPS proxy: {}", e))
            })?;

        buffer.truncate(n);
        log_debug!("Received packet of {} bytes through HTTPS proxy", n);
        Ok(buffer)
    }

    /// Closes the HTTPS proxy connection gracefully.
    async fn close(&mut self) -> Result<(), VpnError> {
        log_info!("Closing connection to HTTPS proxy");
        self.stream.shutdown().await
            .map_err(|e| {
                log_warn!("Failed to properly close connection to HTTPS proxy: {}", e);
                VpnError::ConnectionError(format!("Failed to properly close connection: {}", e))
            })
    }
}
