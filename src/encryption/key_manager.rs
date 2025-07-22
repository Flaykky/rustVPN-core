use crate::utils::error::VpnError;
use crate::encryption::traits::AeadCipher;
use crate::encryption::cipher::CipherFactory;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Thread-safe storage for cryptographic keys
#[derive(Default)]
pub struct KeyManager {
    keys: Mutex<HashMap<String, Vec<u8>>>,
}

impl KeyManager {
    /// Creates a new key manager
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Adds a key to the manager
    pub fn add_key(&self, name: &str, key: Vec<u8>) {
        self.keys.lock().unwrap().insert(name.to_string(), key);
    }

    /// Retrieves a key by name
    pub fn get_key(&self, name: &str) -> Result<Vec<u8>, VpnError> {
        self.keys
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .ok_or_else(|| VpnError::EncryptionError("Key not found".to_string()))
    }

    /// Creates a cipher from a stored key
    pub fn create_aead(
        &self,
        name: &str,
        method: &str,
    ) -> Result<Box<dyn AeadCipher + Send + Sync>, VpnError> {
        let key = self.get_key(name)?;
        CipherFactory::create_aead(method, &key)
    }

    /// Checks if a key exists
    pub fn has_key(&self, name: &str) -> bool {
        self.keys.lock().unwrap().contains_key(name)
    }

    /// Removes a key
    pub fn remove_key(&self, name: &str) -> Result<(), VpnError> {
        self.keys
            .lock()
            .unwrap()
            .remove(name)
            .ok_or_else(|| VpnError::EncryptionError("Key not found".to_string()))?;
        Ok(())
    }

    /// Clears all keys
    pub fn clear(&self) {
        self.keys.lock().unwrap().clear();
    }
}
