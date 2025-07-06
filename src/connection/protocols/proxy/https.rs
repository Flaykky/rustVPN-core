use crate::utils::logging::{log_debug, log_info, log_warn};
use crate::utils::error::VpnError;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::net::SocketAddr;
use super::super::super::super::super::{Protocol, Connection};

pub struct HttpsProxy {
    proxy_addr: SocketAddr,
    target_addr: SocketAddr,
}

impl HttpsProxy {
    pub fn new(proxy_ip: &str, proxy_port: u16, target_ip: &str, target_port: u16) -> Result<Self, VpnError> {
        log_info!("Инициализация HTTPS прокси: {}:{} -> {}:{}", proxy_ip, proxy_port, target_ip, target_port);

        let proxy_addr = format!("{}:{}", proxy_ip, proxy_port)
            .parse::<SocketAddr>()
            .map_err(|e| {
                log_warn!("Некорректный адрес прокси {}:{}", proxy_ip, proxy_port);
                VpnError::ConfigError(format!("Неверный адрес прокси: {}", e))
            })?;

        let target_addr = format!("{}:{}", target_ip, target_port)
            .parse::<SocketAddr>()
            .map_err(|e| {
                log_warn!("Некорректный адрес цели {}:{}", target_ip, target_port);
                VpnError::ConfigError(format!("Неверный адрес цели: {}", e))
            })?;

        log_info!("HTTPS прокси успешно инициализирован");
        Ok(Self { proxy_addr, target_addr })
    }
}

#[async_trait::async_trait]
impl Protocol for HttpsProxy {
    type Connection = HttpsProxyConnection;

    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        log_info!("Попытка подключения к HTTPS прокси: {}", self.proxy_addr);

        let mut stream = TcpStream::connect(self.proxy_addr).await
            .map_err(|e| {
                log_warn!("Не удалось подключиться к HTTPS прокси {}: {}", self.proxy_addr, e);
                VpnError::ConnectionError(format!("Не удалось подключиться к прокси: {}", e))
            })?;

        log_debug!("Создание CONNECT-запроса для {}", self.target_addr);
        let host = self.target_addr.ip().to_string();
        let port = self.target_addr.port();
        let request = format!("CONNECT {}:{} HTTP/1.1\r\nHost: {}\r\n\r\n", host, port, host);

        log_debug!("Отправка CONNECT-запроса: {:?}", request);
        stream.write_all(request.as_bytes()).await
            .map_err(|e| {
                log_warn!("Не удалось отправить CONNECT-запрос к прокси {}: {}", self.proxy_addr, e);
                VpnError::ConnectionError(format!("Не удалось отправить CONNECT-запрос: {}", e))
            })?;

        let mut buffer = [0u8; 1024];
        let n = stream.read(&mut buffer).await
            .map_err(|e| {
                log_warn!("Не удалось получить ответ от прокси {}: {}", self.proxy_addr, e);
                VpnError::ConnectionError(format!("Не удалось прочитать ответ прокси: {}", e))
            })?;

        let response = String::from_utf8_lossy(&buffer[..n]);
        log_debug!("Получен ответ от прокси: {}", response);

        if !response.starts_with("HTTP/1.1 200") {
            log_warn!("Прокси {} отклонил CONNECT-запрос", self.proxy_addr);
            return Err(VpnError::ConnectionError(format!("Прокси отклонил CONNECT-запрос: {}", response)));
        }

        log_info!("Успешно установлено соединение через HTTPS прокси {}", self.proxy_addr);
        Ok(HttpsProxyConnection { stream })
    }
}

pub struct HttpsProxyConnection {
    stream: TcpStream,
}

#[async_trait::async_trait]
impl Connection for HttpsProxyConnection {
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        log_debug!("Отправка {} байт через HTTPS прокси", packet.len());
        self.stream.write_all(packet).await
            .map_err(|e| {
                log_warn!("Не удалось отправить данные через HTTPS прокси: {}", e);
                VpnError::ConnectionError(format!("Не удалось отправить данные через HTTPS-прокси: {}", e))
            })
    }

    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        let mut buffer = vec![0u8; 65535]; // Буфер на случай больших пакетов
        let n = self.stream.read(&mut buffer).await
            .map_err(|e| {
                log_warn!("Не удалось получить данные через HTTPS прокси: {}", e);
                VpnError::ConnectionError(format!("Не удалось получить данные через HTTPS-прокси: {}", e))
            })?;

        buffer.truncate(n);
        log_debug!("Получен пакет размером {} байт через HTTPS прокси", n);
        Ok(buffer)
    }

    async fn close(&mut self) -> Result<(), VpnError> {
        log_info!("Закрытие соединения с HTTPS прокси");
        self.stream.shutdown().await
            .map_err(|e| {
                log_warn!("Не удалось корректно закрыть соединение с HTTPS прокси: {}", e);
                VpnError::ConnectionError(format!("Не удалось корректно закрыть соединение: {}", e))
            })
    }
}
