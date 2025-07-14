use argon2::Config;
use crate::utils::error::VpnError;
use crate::utils::logging::{log_debug, log_info};

/// Генерирует ключ из пароля с использованием Argon2
pub fn derive_key(password: &str, salt: &[u8], length: usize) -> Result<Vec<u8>, VpnError> {
    log_info!("Генерация ключа через Argon2");
    let config = Config::default();
    argon2::hash_encoded(password.as_bytes(), salt, &config)
        .map_err(|e| VpnError::EncryptionError(e.to_string()))
}

/// Генерирует случайный ключ заданной длины
pub fn generate_random_key(length: usize) -> Result<Vec<u8>, VpnError> {
    log_debug!("Генерация случайного ключа длиной {} байт", length);
    let mut key = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut key);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::common::encode_base64;

    #[test]
    fn test_derive_key() {
        let password = "mysecretpassword";
        let salt = b"saltsalt";
        let key = derive_key(password, salt, 32).unwrap();
        assert_eq!(key.len(), 32);
        println!("Сгенерированный ключ: {}", encode_base64(&key));
    }

    #[test]
    fn test_generate_random_key() {
        let key = generate_random_key(32).unwrap();
        assert_eq!(key.len(), 32);
        let key2 = generate_random_key(32).unwrap();
        assert_ne!(key, key2); // Ключи должны быть разными
    }
}
