use std::collections::HashMap;
use std::time::{SystemTime, Duration};
use crate::utils::error::VpnError;
use crate::utils::logging::{log_info, log_warn};

/// Хранилище для временных ключей
pub struct KeyStore {
    keys: HashMap<String, StoredKey>,
    default: Option<String>,
}

struct StoredKey {
    key: Vec<u8>,
    expires_at: Option<SystemTime>,
    tags: Vec<String>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
            default: None,
        }
    }

    /// Добавляет ключ в хранилище
    pub fn add_key(&mut self, name: &str, key: Vec<u8>, ttl: Option<u64>, tags: Vec<String>) {
        log_info!("Добавление ключа {} в хранилище", name);
        let expires_at = ttl.map(|t| SystemTime::now() + Duration::from_secs(t));
        self.keys.insert(name.to_string(), StoredKey { key, expires_at, tags });
    }

    /// Получает ключ по имени
    pub fn get_key(&self, name: &str) -> Result<&[u8], VpnError> {
        let key = self.keys.get(name).ok_or_else(|| {
            log_warn!("Ключ {} не найден", name);
            VpnError::EncryptionError("Ключ не найден".to_string())
        })?;

        if let Some(expiry) = key.expires_at {
            if SystemTime::now() > expiry {
                return Err(VpnError::EncryptionError("Ключ истёк".to_string()));
            }
        }

        Ok(&key.key)
    }

    /// Устанавливает ключ по умолчанию
    pub fn set_default(&mut self, name: &str) -> Result<(), VpnError> {
        if !self.keys.contains_key(name) {
            return Err(VpnError::EncryptionError("Ключ не найден".to_string()));
        }
        self.default = Some(name.to_string());
        log_info!("Ключ {} установлен как основной", name);
        Ok(())
    }

    /// Очищает истёкшие ключи
    pub fn clear_expired(&mut self) {
        log_info!("Очистка истёкших ключей");
        self.keys.retain(|_, key| {
            key.expires_at.map_or(true, |exp| SystemTime::now() < exp)
        });
    }
}
