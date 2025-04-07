// src/utils/utils.rs

use std::{
    fs,
    io::{self, Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
    ffi::OsStr,
};
use rand::{Rng, distributions::Alphanumeric};
use anyhow::{Result, Context};
use chrono::Local;

/// Проверка пустой строки
pub fn is_empty(s: &Option<&str>) -> bool {
    s.map_or(true, |s| s.trim().is_empty())
}

/// Валидация IP-адреса
pub fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// Безопасное чтение файла
pub fn read_file<P: AsRef<Path>>(path: P) -> Result<String> {
    fs::read_to_string(&path)
        .with_context(|| format!("Failed to read file: {}", path.as_ref().display()))
}

/// Запись в файл
pub fn write_file<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, content: C) -> Result<()> {
    fs::write(&path, content)
        .with_context(|| format!("Failed to write file: {}", path.as_ref().display()))
}

/// Генерация случайной строки
pub fn generate_random_string(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

/// Генерация случайного IV
pub fn generate_iv(size: usize) -> Vec<u8> {
    (0..size).map(|_| rand::random::<u8>()).collect()
}

/// Форматирование времени
pub fn format_timestamp(ts: SystemTime) -> String {
    let datetime = ts.into();
    Local.timestamp(datetime.secs, datetime.nanos).format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Создание директории
pub fn create_dir<P: AsRef<Path>>(path: P) -> Result<()> {
    fs::create_dir_all(&path)
        .or_else(|e| if e.kind() == io::ErrorKind::AlreadyExists { Ok(()) } else { Err(e) })
        .with_context(|| format!("Failed to create directory: {}", path.as_ref().display()))
}

/// Проверка прав доступа
pub fn check_permissions<P: AsRef<Path>>(path: P) -> bool {
    match fs::metadata(&path) {
        Ok(metadata) => {
            let perms = metadata.permissions();
            perms.readable().unwrap_or(false) && perms.writable().unwrap_or(false)
        }
        Err(_) => false,
    }
}

/// Обрезка пробелов
pub fn trim(s: &str) -> &str {
    s.trim()
}

/// Проверка существования файла
pub fn file_exists<P: AsRef<Path>>(path: P) -> bool {
    Path::new(path.as_ref()).exists()
}

/// Преобразование в нижний регистр
pub fn to_lowercase(s: &str) -> String {
    s.to_lowercase()
}

/// Получение временной метки
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_string() {
        let s = generate_random_string(16);
        assert_eq!(s.len(), 16);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_trim() {
        assert_eq!(trim("  test  "), "test");
        assert_eq!(trim("\t\n\rtest\t\n\r"), "test");
    }

    #[test]
    fn test_valid_ip() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("2001:db8::1"));
        assert!(!is_valid_ip("invalid.ip"));
    
    }
}