use crate::utils::error::VpnError;
use crate::utils::logging::{log_info, log_warn};
use crate::encryption::key::store::KeyStore;
use crate::encryption::key::kdf::generate_random_key;

/// Менеджер для управления ключами
pub struct KeyManager {
    store: KeyStore,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            store: KeyStore::new(),
        }
    }

    /// Генерирует и сохраняет ключ
    pub fn generate_key(&mut self, name: &str, method: &str, tags: Vec<String>) -> Result<(), VpnError> {
        log_info!("Генерация ключа {}", name);
        let key_size = match method {
            "aes-128-gcm" => 16,
            "aes-256-gcm" => 32,
            "chacha20-ietf-poly1305" => 32,
            "2022-blake3-aes-256-gcm" => 64, // SIP022: 64-байтный ключ
            _ => return Err(VpnError::EncryptionError(EncryptionError::InvalidMethod(method.to_string()))),
        };
        let key = generate_random_key(key_size)?;
        self.store.add_key(name, key, None, tags);
        Ok(())
    }

    /// Получает ключ по имени
    pub fn get_key(&self, name: &str) -> Result<Vec<u8>, VpnError> {
        self.store.get_key(name).map(|k| k.to_vec())
    }

    /// Очищает истёкшие ключи
    pub fn clear_expired_keys(&mut self) {
        self.store.clear_expired();
    }

    /// Устанавливает ключ по умолчанию
    pub fn set_default_key(&mut self, name: &str) -> Result<(), VpnError> {
        self.store.set_default(name)
    }
}
