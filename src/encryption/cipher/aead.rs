use chacha20poly1305::{
    aead::{Aead, NewAead},
    XChaCha20Poly1305, KeyInit, Key, Nonce
};
use rand::RngCore;

/// AEAD-шифрование
pub struct AeadEncryptor {
    cipher: XChaCha20Poly1305,
    key: Key,
}

impl AeadEncryptor {
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 32 {
            return Err(EncryptionError::InvalidKey);
        }
        let mut key_buf = Key::default();
        key_buf.copy_from_slice(key);
        Ok(Self {
            cipher: XChaCha20Poly1305::new(&key_buf),
            key: key_buf,
        })
    }

    /// Генерирует случайный nonce
    pub fn generate_nonce(&self) -> Vec<u8> {
        let mut nonce = Nonce::default();
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce.to_vec()
    }
}

impl super::AeadCipher for AeadEncryptor {
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.encrypt(nonce, data).map_err(|_| {
            EncryptionError::EncryptionFailed("Ошибка шифрования AEAD".to_string())
        })
    }

    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.decrypt(nonce, data).map_err(|_| {
            EncryptionError::DecryptionFailed("Ошибка расшифровки AEAD".to_string())
        })
    }
}