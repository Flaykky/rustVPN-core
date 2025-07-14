use crate::encryption::key::store::{KeyStore, StoredKey};
use crate::encryption::key::kdf::{derive_key, generate_random_key};
use crate::utils::error::VpnError;
use crate::utils::logging::{log_debug, log_info, log_warn};
use std::time::{SystemTime, Duration};

/// Менеджер для управления ключами шифрования
pub struct KeyManager {
    store: KeyStore,
}

impl KeyManager {
    /// Создает новый менеджер ключей
    pub fn new() -> Self {
        Self {
            store: KeyStore::new(),
        }
    }

    /// Генерирует и сохраняет ключ по указанному методу
    pub fn generate_key(&mut self, name: &str, method: &str, tags: Vec<String>) -> Result<(), VpnError> {
        log_info!("Генерация ключа '{}' с методом '{}'", name, method);

        let key_size = match method {
            "aes-128-gcm" => 16,
            "aes-256-gcm" => 32,
            "chacha20-ietf-poly1305" => 32,
            "2022-blake3-aes-256-gcm" => 64, // SIP022
            _ => {
                log_warn!("Неподдерживаемый метод шифрования '{}'", method);
                return Err(VpnError::EncryptionError(format!("Неподдерживаемый метод: {}", method)));
            }
        };

        let key = generate_random_key(key_size)?;
        self.store.add_key(name.to_string(), key, None, tags);
        log_debug!("Ключ '{}' успешно сгенерирован", name);
        Ok(())
    }

    /// Генерирует ключ на основе пароля (KDF)
    pub fn generate_key_from_password(
        &mut self,
        name: &str,
        password: &str,
        salt: &[u8],
        method: &str,
        tags: Vec<String>,
    ) -> Result<(), VpnError> {
        log_info!("Генерация ключа '{}' из пароля", name);

        let derived_key = derive_key(password, salt, method)?;
        self.store.add_key(name.to_string(), derived_key, None, tags);
        log_debug!("Ключ '{}' сгенерирован через KDF", name);
        Ok(())
    }

    /// Получает ключ по имени
    pub fn get_key(&self, name: &str) -> Result<Vec<u8>, VpnError> {
        log_debug!("Получение ключа '{}'", name);
        self.store.get_key(name).map(|k| k.to_vec())
    }

    /// Получает все ключи с заданным тегом
    pub fn get_keys_by_tag(&self, tag: &str) -> Vec<(String, Vec<u8>)> {
        self.store.get_keys_by_tag(tag)
    }

    /// Очищает истёкшие ключи
    pub fn clear_expired_keys(&mut self) {
        log_info!("Очистка истёкших ключей");
        self.store.clear_expired();
    }

    /// Устанавливает ключ по умолчанию
    pub fn set_default_key(&mut self, name: &str) -> Result<(), VpnError> {
        log_info!("Установка ключа '{}' как по умолчанию", name);
        self.store.set_default(name)
    }

    /// Устанавливает TTL для ключа
    pub fn set_key_ttl(&mut self, name: &str, ttl: u64) -> Result<(), VpnError> {
        log_debug!("Установка TTL={} для ключа '{}'", ttl, name);
        self.store.set_key_ttl(name, Some(Duration::from_secs(ttl)))
    }

    /// Удаляет ключ по имени
    pub fn remove_key(&mut self, name: &str) -> Result<(), VpnError> {
        log_warn!("Удаление ключа '{}'", name);
        self.store.remove_key(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::common::generate_random_string;

    #[tokio::test]
    async fn test_key_manager() {
        let mut km = KeyManager::new();
        let key_name = generate_random_string(10);
        let password = "mysecretpassword";
        let salt = b"saltsalt";

        // Тест: генерация случайного ключа
        km.generate_key(&key_name, "chacha20-ietf-poly1305", vec!["test".into()]);
        let key = km.get_key(&key_name).unwrap();
        assert_eq!(key.len(), 32);

        // Тест: генерация ключа из пароля
        let derived_key = km.generate_key_from_password("derived", password, salt, "aes-256-gcm", vec!["kdf".into()]);
        assert!(derived_key.is_ok());

        // Тест: получение ключей по тегу
        let keys = km.get_keys_by_tag("test");
        assert_eq!(keys.len(), 1);

        // Тест: установка TTL
        km.set_key_ttl(&key_name, 1).unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        km.clear_expired_keys();
        assert!(km.get_key(&key_name).is_err());
    }
}
