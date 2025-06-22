// src/utils/common.rs

use std::net::IpAddr;
use std::path::Path;
use std::fs::File;
use std::io::{self, Read};
use rand::{self, Rng};
use base64::{Engine as _, engine::general_purpose};
use hex;

/// Пользовательская ошибка для утилит VPN.
#[derive(Debug)]
pub enum VpnError {
    ConfigError(String),
    Unknown(String),
}

impl std::fmt::Display for VpnError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpnError::ConfigError(msg) => write!(f, "Ошибка конфигурации: {}", msg),
            VpnError::Unknown(msg) => write!(f, "Неизвестная ошибка: {}", msg),
        }
    }
}

impl std::error::Error for VpnError {}

/// Проверяет, является ли строка допустимым IP-адресом (IPv4 или IPv6).
pub fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<IpAddr>().is_ok()
}

/// Кодирует данные в Base64.
pub fn encode_base64(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

/// Декодирует строку Base64 в байты.
pub fn decode_base64(data: &str) -> Result<Vec<u8>, VpnError> {
    general_purpose::STANDARD
        .decode(data)
        .map_err(|e| VpnError::ConfigError(format!("Ошибка декодирования Base64: {}", e)))
}

/// Преобразует байты в шестнадцатеричную строку.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

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

/// Читает содержимое файла в строку.
pub fn read_file_to_string(path: &str) -> Result<String, VpnError> {
    let mut file = File::open(path)
        .map_err(|e| VpnError::ConfigError(format!("Не удалось открыть файл {}: {}", path, e)))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .map_err(|e| VpnError::ConfigError(format!("Не удалось прочитать файл {}: {}", path, e)))?;
    Ok(contents)
}

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
    fn test_encode_base64() {
        let data = b"Test data";
        let encoded = encode_base64(data);
        assert_eq!(encoded, "VGVzdCBkYXRh");
    }

    #[test]
    fn test_decode_base64() {
        let encoded = "VGVzdCBkYXRh";
        let decoded = decode_base64(encoded).unwrap();
        assert_eq!(decoded, b"Test data");
        assert!(decode_base64("invalid").is_err());
    }

    #[test]
    fn test_bytes_to_hex() {
        let data = b"VPN";
        let hex_str = bytes_to_hex(data);
        assert_eq!(hex_str, "56504e");
    }

    #[test]
    fn test_generate_random_string() {
        let length = 8;
        let random_str = generate_random_string(length);
        assert_eq!(random_str.len(), length);
        let another_str = generate_random_string(length);
        assert_ne!(random_str, another_str); // Проверяем, что строки разные
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
}
