use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::utils::config::Config;
use crate::utils::logging::Logger;
use crate::utils::error::VPNError;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct TcpConnection {
    config: Arc<Config>,
    logger: Logger,
}

impl TcpConnection {
    pub fn new(config: Arc<Config>, logger: Logger) -> Self {
        TcpConnection { config, logger }
    }

    pub async fn start_server(&self) -> Result<(), VPNError> {
        let addr = self.config.tcp_server_address.parse::<SocketAddr>()?;
        let listener = TcpListener::bind(&addr).await?;
        self.logger.info(format!("TCP server listening on {}", addr));

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            self.logger.info(format!("Accepted connection from {}", peer_addr));
            tokio::spawn(self.handle_client(stream));
        }
    }

    async fn handle_client(&self, mut stream: TcpStream) {
        let mut buffer = [0; 1024];
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    self.logger.info("Connection closed by client");
                    break;
                }
                Ok(n) => {
                    let data = &buffer[..n];
                    self.logger.debug(format!("Received {} bytes", n));
                    if let Err(e) = stream.write_all(data).await {
                        self.logger.error(format!("Failed to write to stream: {}", e));
                        break;
                    }
                }
                Err(e) => {
                    self.logger.error(format!("Failed to read from stream: {}", e));
                    break;
                }
            }
        }
    }

    pub async fn connect_to_server(&self) -> Result<TcpStream, VPNError> {
        let addr = self.config.tcp_server_address.parse::<SocketAddr>()?;
        let stream = TcpStream::connect(&addr).await?;
        self.logger.info(format!("Connected to TCP server at {}", addr));
        Ok(stream)
    }
}