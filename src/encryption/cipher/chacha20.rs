use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::XChaCha20Poly1305;
use crate::utils::logging::{log_debug, log_info};

pub struct ChaCha20Cipher {
    cipher: XChaCha20Poly1305,
    key: [u8; 32],
}

impl ChaCha20Cipher {
    pub fn new(key: &[u8]) -> Result<Self, String> {
        if key.len() != 32 {
            return Err("Неверная длина ключа для ChaCha20-Poly1305".to_string());
        }
        let mut key_buf = [0u8; 32];
        key_buf.copy_from_slice(key);
        log_info!("Создан шифр ChaCha20-Poly1305");
        Ok(Self {
            cipher: XChaCha20Poly1305::new(&key_buf.into()),
            key: key_buf,
        })
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        log_debug!("Шифрование ChaCha20-Poly1305");
        let mut rng = rand::thread_rng();
        let mut nonce = [0u8; 24];
        rng.fill_bytes(&mut nonce);
        let encrypted = self.cipher.encrypt(&nonce.into(), data).map_err(|e| e.to_string())?;
        Ok([nonce.to_vec(), encrypted].concat())
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 24 {
            return Err("Неверная длина данных для расшифровки".to_string());
        }
        let nonce = &data[..24];
        let cipher_text = &data[24..];
        self.cipher.decrypt(nonce.into(), cipher_text).map_err(|e| e.to_string())
    }
}
