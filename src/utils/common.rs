use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::fs::File;
use std::io::{self, Read};
use std::str::FromStr;
use rand::{self, Rng};
use base64::{Engine as _, engine::general_purpose};
use hex;
use sha2::{Digest, Sha256};

/// Пользовательская ошибка для утилит VPN.
#[derive(Debug)]
pub enum VpnError {
    ConfigError(String),
    IoError(String),
    DecodeError(String),
    NetworkError(String),
    ParseError(String),
    Unknown(String),
}

impl std::fmt::Display for VpnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpnError::ConfigError(msg) => write!(f, "Ошибка конфигурации: {}", msg),
            VpnError::IoError(msg) => write!(f, "Ошибка ввода-вывода: {}", msg),
            VpnError::DecodeError(msg) => write!(f, "Ошибка декодирования: {}", msg),
            VpnError::NetworkError(msg) => write!(f, "Сетевая ошибка: {}", msg),
            VpnError::ParseError(msg) => write!(f, "Ошибка разбора: {}", msg),
            VpnError::Unknown(msg) => write!(f, "Неизвестная ошибка: {}", msg),
        }
    }
}

impl std::error::Error for VpnError {}

// ----------------------
// ВАЛИДАЦИЯ И РАЗБОР
// ----------------------

/// Проверяет, является ли строка допустимым IP-адресом (IPv4 или IPv6).
pub fn is_valid_ip(ip: &str) -> bool {
    IpAddr::from_str(ip).is_ok()
}

/// Проверяет, является ли строка допустимым портом (1–65535).
pub fn is_valid_port(port: u16) -> bool {
    port >= 1 && port <= 65535
}

/// Проверяет, является ли строка допустимым CIDR-адресом.
pub fn is_valid_cidr(cidr: &str) -> bool {
    cidr.parse::<ipnetwork::IpNetwork>().is_ok()
}

/// Проверяет, является ли строка допустимым SocketAddr.
pub fn is_valid_socket_addr(addr: &str) -> bool {
    SocketAddr::from_str(addr).is_ok()
}

// ----------------------
// КОДИРОВАНИЕ И ХЭШИ
// ----------------------

/// Кодирует данные в Base64.
pub fn encode_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Декодирует строку Base64 в байты.
pub fn decode_base64(data: &str) -> Result<Vec<u8>, VpnError> {
    general_purpose::STANDARD.decode(data)
        .map_err(|e| VpnError::DecodeError(format!("Ошибка декодирования Base64: {}", e)))
}

/// Преобразует байты в шестнадцатеричную строку.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Преобразует шестнадцатеричную строку в байты.
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, VpnError> {
    hex::decode(hex)
        .map_err(|e| VpnError::DecodeError(format!("Ошибка декодирования HEX: {}", e)))
}

/// Вычисляет SHA-256 хэш от данных.
pub fn sha256_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    bytes_to_hex(&result)
}

// ----------------------
// ГЕНЕРАЦИЯ И СЛУЧАЙНОСТЬ
// ----------------------

/// Генерирует случайную строку заданной длины.
pub fn generate_random_string(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        .chars()
        .collect();
    (0..length)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

/// Генерирует случайный пароль заданной длины.
pub fn generate_password(length: usize) -> String {
    generate_random_string(length)
}

// ----------------------
// РАБОТА С ФАЙЛАМИ
// ----------------------

/// Читает содержимое файла в строку.
pub fn read_file_to_string(path: &str) -> Result<String, VpnError> {
    let mut file = File::open(path)
        .map_err(|e| VpnError::IoError(format!("Не удалось открыть файл {}: {}", path, e)))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| VpnError::IoError(format!("Не удалось прочитать файл {}: {}", path, e)))?;
    Ok(contents)
}

// ----------------------
// СЕТЕВЫЕ УТИЛИТЫ
// ----------------------

/// Парсит строку в `SocketAddr`.
pub fn parse_socket_addr(addr: &str) -> Result<SocketAddr, VpnError> {
    addr.parse::<SocketAddr>()
        .map_err(|e| VpnError::ParseError(format!("Недопустимый адрес {}: {}", addr, e)))
}

/// Валидирует и возвращает `SocketAddr`.
pub fn validate_socket_addr(ip: &str, port: u16) -> Result<SocketAddr, VpnError> {
    if !is_valid_ip(ip) {
        return Err(VpnError::ParseError(format!("Недопустимый IP-адрес: {}", ip)));
    }
    if !is_valid_port(port) {
        return Err(VpnError::ParseError(format!("Недопустимый порт: {}", port)));
    }
    Ok(SocketAddr::new(ip.parse().unwrap(), port))
}

// ----------------------
// ТЕСТЫ
// ----------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_ip() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("2001:0db8::1"));
        assert!(!is_valid_ip("invalid_ip"));
    }

    #[test]
    fn test_is_valid_port() {
        assert!(is_valid_port(80));
        assert!(!is_valid_port(0));
        assert!(!is_valid_port(65536));
    }

    #[test]
    fn test_is_valid_cidr() {
        assert!(is_valid_cidr("192.168.0.0/24"));
        assert!(is_valid_cidr("2001:db8::/32"));
        assert!(!is_valid_cidr("192.168.1.1/33"));
    }

    #[test]
    fn test_encode_decode_base64() {
        let data = b"Test data";
        let encoded = encode_base64(data);
        assert_eq!(encoded, "VGVzdCBkYXRh");
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
        assert!(decode_base64("invalid").is_err());
    }

    #[test]
    fn test_bytes_to_hex() {
        let data = b"VPN";
        let hex_str = bytes_to_hex(data);
        assert_eq!(hex_str, "56504e");
    }

    #[test]
    fn test_hex_to_bytes() {
        let hex_str = "56504e";
        let bytes = hex_to_bytes(hex_str).unwrap();
        assert_eq!(bytes, b"VPN");
        assert!(hex_to_bytes("invalid").is_err());
    }

    #[test]
    fn test_sha256_hash() {
        let hash = sha256_hash(b"hello");
        assert_eq!(hash, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9826");
    }

    #[test]
    fn test_generate_random_string() {
        let length = 8;
        let random_str = generate_random_string(length);
        assert_eq!(random_str.len(), length);
        let another_str = generate_random_string(length);
        assert_ne!(random_str, another_str);
    }

    #[test]
    fn test_read_file_to_string() {
        let path = "Cargo.toml";
        if Path::new(path).exists() {
            let contents = read_file_to_string(path).unwrap();
            assert!(!contents.is_empty());
        }
        assert!(read_file_to_string("non_existent_file.txt").is_err());
    }

    #[test]
    fn test_parse_socket_addr() {
        assert!(parse_socket_addr("127.0.0.1:8080").is_ok());
        assert!(parse_socket_addr("[::1]:8080").is_ok());
        assert!(parse_socket_addr("invalid:port").is_err());
    }

    #[test]
    fn test_validate_socket_addr() {
        assert!(validate_socket_addr("192.168.1.1", 8080).is_ok());
        assert!(validate_socket_addr("invalid", 8080).is_err());
        assert!(validate_socket_addr("192.168.1.1", 0).is_err());
    }
}
