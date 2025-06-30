use crate::utils::logging::{log_debug, log_info, log_warn};
use crate::utils::error::VpnError;
use tokio::net::UdpSocket;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use boringtun::noise::{Tunn, TunnConfig, TunnResult};
use std::net::SocketAddr;
use super::{Protocol, Connection};
use tokio::net::lookup_host;
use base64::Engine;

/// Configuration for WireGuard protocol
pub struct WireGuardConfig {
    private_key: String,
    peer_public_key: String,
    endpoint: String,
}

impl WireGuardConfig {
    pub fn new(private_key: &str, peer_public_key: &str, endpoint: &str) -> Self {
        Self {
            private_key: private_key.to_string(),
            peer_public_key: peer_public_key.to_string(),
            endpoint: endpoint.to_string(),
        }
    }
}

/// WireGuard protocol implementation
pub struct WireGuard {
    config: WireGuardConfig,
}

impl WireGuard {
    /// Creates a new WireGuard instance with the given configuration
    pub fn new(config: WireGuardConfig) -> Result<Self, VpnError> {
        log_info!("Initializing WireGuard with endpoint {}", config.endpoint);
        if config.private_key.is_empty() || config.peer_public_key.is_empty() || config.endpoint.is_empty() {
            log_warn!("Invalid WireGuard configuration: empty fields");
            return Err(VpnError::ConfigError("Invalid WireGuard configuration".to_string()));
        }
        Ok(Self { config })
    }
}

#[async_trait::async_trait]
impl Protocol for WireGuard {
    type Connection = WireGuardConnection;

    /// Establishes a connection to the WireGuard peer
    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        log_info!("Connecting to WireGuard peer at {}", self.config.endpoint);
        
        // Decode private key from base64
        let private_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.config.private_key)
            .map_err(|e| {
                log_warn!("Failed to decode private key: {}", e);
                VpnError::ConfigError(format!("Invalid private key format: {}", e))
            })?;

        // Decode peer public key from base64
        let public_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.config.peer_public_key)
            .map_err(|e| {
                log_warn!("Failed to decode public key: {}", e);
                VpnError::ConfigError(format!("Invalid public key format: {}", e))
            })?;

        // Resolve DNS for the endpoint
        let endpoint_str = self.config.endpoint.clone();
        let mut addrs = lookup_host(endpoint_str).await.map_err(|e| {
            log_warn!("DNS resolution error for {}: {}", self.config.endpoint, e);
            VpnError::ConfigError(format!("Failed to resolve address: {}", e))
        })?;

        let endpoint = addrs.next().ok_or_else(|| {
            log_warn!("No address found for {}", self.config.endpoint);
            VpnError::ConfigError("No address found for endpoint".to_string())
        })?;

        // Bind UDP socket to a local address
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(|e| {
            log_warn!("Failed to bind UDP socket: {}", e);
            VpnError::ConnectionError(format!("Failed to bind socket: {}", e))
        })?;

        // Initialize WireGuard tunnel configuration
        let tunn_config = TunnConfig {
            private_key: Some(private_key_bytes),
            peer_public_key: Some(public_key_bytes),
            index: 0,
            seq_number: 0,
            remote_endpoint: Some(endpoint),
            preshared_key: None,
            platform_impl: Default::default(),
        };

        // Create the WireGuard tunnel
        let tun = Tunn::new(tunn_config).map_err(|e| {
            log_warn!("Failed to initialize tunnel: {:?}", e);
            VpnError::ConnectionError("Failed to initialize tunnel".to_string())
        })?;

        log_info!("Successfully connected to WireGuard peer at {}", self.config.endpoint);
        Ok(WireGuardConnection { tun, socket })
    }
}

/// Represents an active WireGuard connection
pub struct WireGuardConnection {
    tun: Tunn,
    socket: UdpSocket,
}

#[async_trait::async_trait]
impl Connection for WireGuardConnection {
    /// Encrypts and sends a packet through the WireGuard tunnel
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        let mut out_buffer = [0u8; 65536];
        match self.tun.encapsulate(packet, &mut out_buffer) {
            TunnResult::WriteToNetwork(encrypted) => {
                // Send the encrypted packet over UDP
                self.socket.send(encrypted).await.map_err(|e| {
                    log_warn!("Failed to send packet: {}", e);
                    VpnError::ConnectionError(format!("Failed to send packet: {}", e))
                })?;
                log_debug!("Packet sent via WireGuard");
            }
            TunnResult::Err(e) => {
                log_warn!("Packet encryption error: {:?}", e);
                return Err(VpnError::ProtocolError("Packet encryption error".to_string()));
            }
            _ => {} // Ignore other cases for simplicity
        }
        Ok(())
    }

    /// Receives and decrypts a packet from the WireGuard tunnel
    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        let mut buffer = [0u8; 65536];
        // Receive encrypted packet from UDP socket
        let size = self.socket.recv(&mut buffer).await.map_err(|e| {
            log_warn!("Failed to receive packet: {}", e);
            VpnError::ConnectionError(format!("Failed to receive packet: {}", e))
        })?;

        let mut out_buffer = [0u8; 65536];
        // Decrypt the received packet
        match self.tun.decapsulate(None, &buffer[..size], &mut out_buffer) {
            TunnResult::Ready { plaintext, .. } => {
                log_debug!("Packet received via WireGuard");
                Ok(plaintext.to_vec())
            }
            TunnResult::Err(e) => {
                log_warn!("Packet decryption error: {:?}", e);
                Err(VpnError::ProtocolError("Packet decryption error".to_string()))
            }
            _ => Err(VpnError::ProtocolError("Empty packet".to_string()))
        }
    }

    /// Closes the WireGuard connection and shuts down the UDP socket
    async fn close(&mut self) -> Result<(), VpnError> {
        log_info!("Closing WireGuard connection");
        self.socket.shutdown().await.map_err(|e| {
            log_warn!("Failed to close connection: {}", e);
            VpnError::ConnectionError(format!("Failed to close connection: {}", e))
        })?;
        Ok(())
    }
}
