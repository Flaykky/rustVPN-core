use openssl::{
    ec::{EcGroup, EcKey},
    nid::Nid,
    pkey::PKey,
    error::ErrorStack,
};
use rand::{RngCore, thread_rng};
use zeroize::Zeroize;
use std::sync::{Mutex, Arc};
use anyhow::{Result, anyhow};

/// Контекст для PFS на основе ECDH
pub struct PFSContext {
    local_key: EcKey,
    shared_secret: Mutex<Option<Vec<u8>>>,
    curve: Nid,
}

impl PFSContext {
    /// Создание нового контекста
    pub fn new() -> Result<Self> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let local_key = EcKey::generate(&group)?;
        
        Ok(Self {
            local_key,
            shared_secret: Mutex::new(None),
            curve: Nid::X9_62_PRIME256V1,
        })
    }

    /// Получение публичного ключа в DER-формате
    pub fn public_key_der(&self) -> Result<Vec<u8>> {
        let pkey = PKey::from_ec_key(self.local_key.clone())?;
        Ok(pkey.public_key_to_der()?)
    }

    /// Вычисление общего секрета
    pub fn compute_shared_secret(&self, peer_der: &[u8]) -> Result<Vec<u8>> {
        let peer_pkey = PKey::public_key_from_der(peer_der)?;
        let peer_key = peer_pkey.ec_key()?;
        
        let mut shared_secret = vec![0u8; 32];
        let len = self.local_key.compute_key(&peer_key, &mut shared_secret)?;
        shared_secret.truncate(len);
        
        // Сохраняем секрет в защищенном буфере
        let mut guard = self.shared_secret.lock().unwrap();
        *guard = Some(shared_secret.clone());
        
        Ok(shared_secret)
    }

    /// Получение текущего общего секрета
    pub fn get_shared_secret(&self) -> Option<Vec<u8>> {
        self.shared_secret.lock().unwrap().clone()
    }

    /// Генерация новых эфемерных ключей
    pub fn rotate_keys(&mut self) -> Result<()> {
        let group = EcGroup::from_curve_name(self.curve)?;
        self.local_key = EcKey::generate(&group)?;
        
        // Очистка старого секрета
        let mut guard = self.shared_secret.lock().unwrap();
        if let Some(ref mut secret) = *guard {
            secret.zeroize();
        }
        *guard = None;
        
        Ok(())
    }
}

impl Drop for PFSContext {
    fn drop(&mut self) {
        // Безопасное удаление ключей
        self.local_key.zeroize();
        if let Some(ref mut secret) = *self.shared_secret.lock().unwrap() {
            secret.zeroize();
        }
    }
}