//! Реализация базового QUIC транспорта для VPN.
//! Использует библиотеку `quinn`.

use crate::utils::error::VpnError;
use crate::utils::logging::{log_debug, log_info, log_warn};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;

// Quinn использует tokio
use quinn::{Endpoint, ClientConfig, ServerConfig, TransportConfig, crypto::rustls::QuicServerConfig};
use rustls::{Certificate, PrivateKey, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Представляет конфигурацию для базового QUIC сервера или клиента.
pub struct QuicConfig {
    /// Адрес, на котором будет слушать сервер или к которому будет подключаться клиент.
    pub bind_addr: SocketAddr,
    /// Адрес сервера (для клиента).
    pub server_addr: Option<SocketAddr>,
    /// Если `true`, запускает сервер. Иначе клиент.
    pub is_server: bool,
    /// Самоподписанный сертификат (для тестов/демонстрации).
    /// В реальном приложении следует использовать настоящие сертификаты.
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
}

impl QuicConfig {
    /// Создает конфигурацию для клиента.
    pub fn client(server_ip: &str, server_port: u16, local_ip: &str, local_port: u16) -> Result<Self, VpnError> {
        let server_addr = format!("{}:{}", server_ip, server_port)
            .to_socket_addrs()
            .map_err(|e| VpnError::config_error(format!("Неверный адрес сервера: {}", e)))?
            .next()
            .ok_or_else(|| VpnError::config_error("Не удалось разрешить адрес сервера".to_string()))?;

        let bind_addr = format!("{}:{}", local_ip, local_port)
            .parse()
            .map_err(|e| VpnError::config_error(format!("Неверный локальный адрес: {}", e)))?;

        Ok(Self {
            bind_addr,
            server_addr: Some(server_addr),
            is_server: false,
            cert_pem: None,
            key_pem: None,
        })
    }

    /// Создает конфигурацию для сервера.
    pub fn server(bind_ip: &str, bind_port: u16) -> Result<Self, VpnError> {
        let bind_addr = format!("{}:{}", bind_ip, bind_port)
            .parse()
            .map_err(|e| VpnError::config_error(format!("Неверный адрес привязки сервера: {}", e)))?;

        Ok(Self {
            bind_addr,
            server_addr: None,
            is_server: true,
            cert_pem: None,
            key_pem: None,
        })
    }
}

/// Основная структура для базового QUIC транспорта.
pub struct BasicQuic {
    config: QuicConfig,
    endpoint: Option<Endpoint>, // Endpoint будет создан в `connect` или `listen`
}

impl BasicQuic {
    /// Создает новый экземпляр `BasicQuic`.
    pub fn new(config: QuicConfig) -> Result<Self, VpnError> {
        log_info!("Инициализация базового QUIC транспорта. Роль: {}", if config.is_server { "Сервер" } else { "Клиент" });
        // Валидация конфигурации
        if config.is_server && config.server_addr.is_some() {
            log_warn!("Для сервера адрес сервера не требуется, он будет проигнорирован.");
        }
        if !config.is_server && config.server_addr.is_none() {
            return Err(VpnError::config_error("Для клиента необходимо указать адрес сервера.".to_string()));
        }
        Ok(Self { config, endpoint: None })
    }

    /// Создает конфигурацию клиента Quinn с отключенной проверкой сертификатов.
    /// ⚠️ ТОЛЬКО ДЛЯ ТЕСТИРОВАНИЯ! В реальном приложении используйте проверку.
    fn create_client_config(&self) -> Result<ClientConfig, VpnError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();

        // Отключение проверки сертификатов для тестов (НЕ ДЕЛАЙТЕ ТАК В ПРОДАКШЕНЕ!)
        // client_crypto.dangerous().set_certificate_verifier(Arc::new(danger::NoServerVerification));

        let mut client_config = ClientConfig::new(Arc::new(client_crypto));
        let mut transport_config = TransportConfig::default();
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(10_000)))); // 10 сек
        client_config.transport_config(Arc::new(transport_config));
        
        Ok(client_config)
    }

    /// Создает конфигурацию сервера Quinn с самоподписанным сертификатом.
    fn create_server_config(&self) -> Result<ServerConfig, VpnError> {
        // Для демонстрации генерируем самоподписанный сертификат
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| VpnError::config_error(format!("Ошибка генерации сертификата: {}", e)))?;
        let cert_der = cert.serialize_der().unwrap();
        let priv_key = PrivateKey(cert.serialize_private_key_der());

        let server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(vec![Certificate(cert_der)], priv_key)
            .map_err(|e| VpnError::config_error(format!("Ошибка настройки TLS сервера: {}", e)))?;

        let mut server_config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
        let mut transport_config = TransportConfig::default();
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(10_000)))); // 10 сек
        server_config.transport = Arc::new(transport_config);

        Ok(server_config)
    }
}

#[async_trait::async_trait]
impl super::Protocol for BasicQuic {
    type Connection = BasicQuicConnection;

    /// Устанавливает QUIC соединение (для клиента) или начинает слушать (для сервера).
    async fn connect(&self) -> Result<Self::Connection, VpnError> {
        log_info!("Попытка установки QUIC соединения...");

        if self.config.is_server {
            // Для сервера создаем Endpoint в режиме сервера
            let server_config = self.create_server_config()?;
            let endpoint = Endpoint::server(server_config, self.config.bind_addr)
                .map_err(|e| VpnError::connection_error(format!("Не удалось запустить QUIC сервер: {}", e)))?;

            log_info!("QUIC сервер запущен на {}", self.config.bind_addr);
            return Ok(BasicQuicConnection { endpoint: Arc::new(endpoint), connection: None, stream: None });
        } else {
            // Для клиента создаем Endpoint в режиме клиента и подключаемся
            let client_config = self.create_client_config()?;
            let mut endpoint = Endpoint::client(self.config.bind_addr)
                .map_err(|e| VpnError::connection_error(format!("Не удалось создать клиентский QUIC endpoint: {}", e)))?;
            endpoint.set_default_client_config(client_config);

            let server_addr = self.config.server_addr.unwrap(); // Уже проверено в new()
            
            // Пытаемся подключиться
            let connection = endpoint
                .connect(server_addr, "localhost") // "localhost" должно совпадать с SAN сертификата
                .map_err(|e| VpnError::connection_error(format!("Не удалось инициировать QUIC подключение: {}", e)))?
                .await
                .map_err(|e| VpnError::connection_error(format!("Не удалось установить QUIC подключение: {}", e)))?;

            log_info!("Установлено QUIC подключение к {}", server_addr);
            Ok(BasicQuicConnection { endpoint: Arc::new(endpoint), connection: Some(connection), stream: None })
        }
    }
}

/// Структура для управления QUIC соединением.
pub struct BasicQuicConnection {
    endpoint: Arc<Endpoint>,
    connection: Option<quinn::Connection>,
    stream: Option<quinn::SendStream>, // Можно расширить для хранения RecvStream
}

#[async_trait::async_trait]
impl super::Connection for BasicQuicConnection {
    /// Отправляет пакет через QUIC stream.
    async fn send_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        log_debug!("Отправка пакета размером {} байт через QUIC", packet.len());

        // Если соединение серверное, нужно сначала получить входящее соединение
        if self.connection.is_none() {
            // Предполагаем, что это сервер, ждем входящего соединения
            // В реальном сервере это должно быть в цикле или фоновой задаче
            log_info!("Ожидание входящего QUIC соединения...");
            let incoming_conn = self.endpoint.accept().await
                .ok_or_else(|| VpnError::connection_error("QUIC сервер: входящее соединение не получено".to_string()))?;
            let conn = incoming_conn.await
                .map_err(|e| VpnError::connection_error(format!("Ошибка принятия входящего QUIC соединения: {}", e)))?;
            log_info!("Принято входящее QUIC соединение");
            self.connection = Some(conn);
        }

        // Если stream еще не открыт, открываем новый
        if self.stream.is_none() {
            let conn = self.connection.as_ref().unwrap(); // Уже проверено
            let (send, _recv) = conn
                .open_bi()
                .await
                .map_err(|e| VpnError::connection_error(format!("Ошибка открытия QUIC stream: {}", e)))?;
            self.stream = Some(send);
            log_debug!("Открыт новый двунаправленный QUIC stream");
        }

        let stream = self.stream.as_mut().unwrap();
        stream.write_all(&(packet.len() as u32).to_be_bytes()).await
            .map_err(|e| VpnError::connection_error(format!("Ошибка отправки длины пакета через QUIC: {}", e)))?;
        stream.write_all(packet).await
            .map_err(|e| VpnError::connection_error(format!("Ошибка отправки пакета через QUIC: {}", e)))?;
        stream.flush().await
            .map_err(|e| VpnError::connection_error(format!("Ошибка сброса буфера QUIC: {}", e)))?;

        log_info!("Пакет размером {} байт успешно отправлен через QUIC", packet.len());
        Ok(())
    }

    /// Получает пакет через QUIC stream.
    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        log_debug!("Ожидание получения пакета через QUIC...");

        // Если соединение серверное и еще не принято, принимаем
        if self.connection.is_none() {
            log_info!("Ожидание входящего QUIC соединения для получения пакета...");
            let incoming_conn = self.endpoint.accept().await
                .ok_or_else(|| VpnError::connection_error("QUIC сервер: входящее соединение не получено".to_string()))?;
            let conn = incoming_conn.await
                .map_err(|e| VpnError::connection_error(format!("Ошибка принятия входящего QUIC соединения: {}", e)))?;
            log_info!("Принято входящее QUIC соединение для получения пакета");
            self.connection = Some(conn);
        }

        // Открываем новый stream для чтения (или используем существующий, если логика требует)
        // Для простоты откроем новый при каждом вызове
        let conn = self.connection.as_ref().unwrap();
        let (_send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| VpnError::connection_error(format!("Ошибка принятия QUIC stream: {}", e)))?;

        let mut len_buf = [0u8; 4];
        recv.read_exact(&mut len_buf).await
            .map_err(|e| VpnError::connection_error(format!("Ошибка чтения длины пакета через QUIC: {}", e)))?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 65535 {
            return Err(VpnError::protocol_error("Слишком большой пакет через QUIC".to_string()));
        }

        let mut packet = vec![0u8; len];
        recv.read_exact(&mut packet).await
            .map_err(|e| VpnError::connection_error(format!("Ошибка чтения пакета через QUIC: {}", e)))?;

        log_debug!("Получен пакет размером {} байт через QUIC", len);
        Ok(packet)
    }

    /// Закрывает QUIC соединение.
    async fn close(&mut self) -> Result<(), VpnError> {
        log_info!("Закрытие QUIC соединения...");
        if let Some(conn) = self.connection.take() {
            conn.close(0u32.into(), b"VPN connection closed");
        }
        // Endpoint будет закрыт при дропе, если он больше не нужен
        log_info!("QUIC соединение закрыто");
        Ok(())
    }
}

// Модуль для отключения проверки сертификатов (только для тестов!)
// #[cfg(test)]
// mod danger {
//     use rustls::client::ServerCertVerified;
//     use rustls::{Certificate, ServerName};
//     use std::time::SystemTime;
//
//     pub struct NoServerVerification;
//
//     impl rustls::client::ServerCertVerifier for NoServerVerification {
//         fn verify_server_cert(
//             &self,
//             _end_entity: &Certificate,
//             _intermediates: &[Certificate],
//             _server_name: &ServerName,
//             _scts: &mut dyn Iterator<Item = &[u8]>,
//             _ocsp_response: &[u8],
//             _now: SystemTime,
//         ) -> Result<ServerCertVerified, rustls::Error> {
//             Ok(ServerCertVerified::assertion())
//         }
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[tokio::test]
    async fn test_quic_client_server() {
        let server_config = QuicConfig::server("127.0.0.1", 0).unwrap();
        let mut server_proto = BasicQuic::new(server_config).unwrap();
        let server_conn_fut = server_proto.connect();

        // Получаем адрес, на котором сервер начал слушать
        let server_endpoint = timeout(Duration::from_secs(1), async {
            server_conn_fut.await.unwrap()
        }).await.unwrap();
        let server_addr = server_endpoint.endpoint.local_addr().unwrap();

        let client_config = QuicConfig::client("127.0.0.1", server_addr.port(), "127.0.0.1", 0).unwrap();
        let client_proto = BasicQuic::new(client_config).unwrap();
        let mut client_conn = client_proto.connect().await.unwrap();

        // Отправляем пакет от клиента
        let test_data = b"Hello, QUIC VPN!";
        client_conn.send_packet(test_data).await.unwrap();

        // Сервер получает пакет
        let mut server_conn_for_recv = server_endpoint; // Клонируем для получения
        let received_data = timeout(Duration::from_secs(2), server_conn_for_recv.receive_packet()).await.unwrap().unwrap();
        assert_eq!(received_data, test_data);

        client_conn.close().await.unwrap();
        server_conn_for_recv.close().await.unwrap();
    }
}
