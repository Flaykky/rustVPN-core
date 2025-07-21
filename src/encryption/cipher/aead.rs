use crate::encryption::error::EncryptionError;
use crate::encryption::traits::{AeadCipher, AsyncCipher};
use crate::utils::logging::{log_debug, log_info, log_warn};
use chacha20poly1305::{
    aead::{Aead, NewAead},
    XChaCha20Poly1305, KeyInit, Key, Nonce,
};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::error::ErrorStack;
use std::convert::TryInto;
use std::vec::Vec;
use rand::RngCore;

/// AEAD-шифрование через XChaCha20Poly1305
pub struct XChaCha20Aead {
    cipher: XChaCha20Poly1305,
    key: Key,
}

impl XChaCha20Aead {
    /// Создаёт шифратор с 32-байтным ключом
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 32 {
            log_warn!("Неверная длина ключа для XChaCha20Poly1305 (ожидается 32 байта)");
            return Err(EncryptionError::InvalidKey);
        }
        log_info!("Создан шифр XChaCha20Poly1305");
        let mut key_buf = Key::default();
        key_buf.copy_from_slice(key);
        Ok(Self {
            cipher: XChaCha20Poly1305::new(&key_buf),
            key: key_buf,
        })
    }

    /// Генерирует случайный 24-байтный nonce
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = Nonce::default();
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован nonce для XChaCha20Poly1305");
        nonce.to_vec()
    }
}

impl AeadCipher for XChaCha20Aead {
    /// Шифрование с nonce
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 24 {
            log_warn!("Неверная длина nonce для XChaCha20Poly1305 (ожидается 24 байта)");
            return Err(EncryptionError::InvalidNonce);
        }
        let nonce = Nonce::from_slice(nonce);
        let encrypted = self.cipher.encrypt(nonce, data).map_err(|e| {
            log_warn!("Ошибка шифрования XChaCha20Poly1305: {}", e);
            EncryptionError::EncryptionFailed(e.to_string())
        })?;
        log_debug!("XChaCha20Poly1305: зашифровано {} байт", data.len());
        Ok(encrypted)
    }

    /// Расшифровка с nonce
    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 24 {
            log_warn!("Неверная длина nonce для XChaCha20Poly1305");
            return Err(EncryptionError::InvalidNonce);
        }
        let nonce = Nonce::from_slice(nonce);
        let decrypted = self.cipher.decrypt(nonce, data).map_err(|e| {
            log_warn!("Ошибка расшифровки XChaCha20Poly1305: {}", e);
            EncryptionError::DecryptionFailed(e.to_string())
        })?;
        log_debug!("XChaCha20Poly1305: расшифровано {} байт", decrypted.len());
        Ok(decrypted)
    }
}

/// AEAD-шифрование через AES-256-GCM
pub struct Aes256Gcm {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes256Gcm {
    /// Создаёт шифратор с 32-байтным ключом
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 32 {
            log_warn!("Неверная длина ключа для AES-256-GCM (ожидается 32 байта)");
            return Err(EncryptionError::InvalidKey);
        }
        log_info!("Создан шифр AES-256-GCM");
        Ok(Self {
            key: key.to_vec(),
            cipher: Cipher::aes_256_gcm(),
        })
    }

    /// Генерирует случайный 12-байтный nonce
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован nonce для AES-256-GCM");
        nonce
    }
}

impl AeadCipher for Aes256Gcm {
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-256-GCM (ожидается 12 байт)");
            return Err(EncryptionError::InvalidNonce);
        }
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(nonce))?;
        crypter.set_data_len(data.len())?;
        let mut output = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut output[..])?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        log_debug!("AES-256-GCM: зашифровано {} байт", data.len());
        Ok(output)
    }

    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-256-GCM");
            return Err(EncryptionError::InvalidNonce);
        }
        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(nonce))?;
        let mut output = vec![0; data.len()];
        let count = crypter.update(data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        log_debug!("AES-256-GCM: расшифровано {} байт", output.len());
        Ok(output)
    }
}

/// AEAD-шифрование через AES-128-GCM
pub struct Aes128Gcm {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes128Gcm {
    /// Создаёт шифратор с 16-байтным ключом
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 16 {
            log_warn!("Неверная длина ключа для AES-128-GCM (ожидается 16 байт)");
            return Err(EncryptionError::InvalidKey);
        }
        log_info!("Создан шифр AES-128-GCM");
        Ok(Self {
            key: key.to_vec(),
            cipher: Cipher::aes_128_gcm(),
        })
    }

    /// Генерирует случайный 12-байтный nonce
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован nonce для AES-128-GCM");
        nonce
    }
}

impl AeadCipher for Aes128Gcm {
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-128-GCM");
            return Err(EncryptionError::InvalidNonce);
        }
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(nonce))?;
        crypter.set_data_len(data.len())?;
        let mut output = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        log_debug!("AES-128-GCM: зашифровано {} байт", data.len());
        Ok(output)
    }

    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-128-GCM");
            return Err(EncryptionError::InvalidNonce);
        }
        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(nonce))?;
        let mut output = vec![0; data.len()];
        let count = crypter.update(data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        log_debug!("AES-128-GCM: расшифровано {} байт", output.len());
        Ok(output)
    }
}

/// Общий интерфейс для AEAD-шифрования
pub trait AeadCipher: Send + Sync {
    /// Зашифровывает данные с nonce
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError>;

    /// Расшифровывает данные с nonce
    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError>;
}

/// Общий интерфейс для асинхронного шифрования
pub trait AsyncCipher: Send + Sync {
    /// Зашифровывает данные
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError>;

    /// Расшифровывает данные
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError>;
}

impl AsyncCipher for dyn AeadCipher + '_ {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let nonce = XChaCha20Aead::generate_nonce();
        self.encrypt_with_nonce(data, &nonce)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < 12 {
            return Err(EncryptionError::InvalidDataLength("Недостаточно данных для nonce".to_string()));
        }
        let (nonce, cipher_text) = data.split_at(12);
        self.decrypt_with_nonce(cipher_text, nonce)
    }
}

/// Создаёт AEAD-шифр по методу и ключу
pub fn create_aead_cipher(
    method: &str,
    key: &[u8],
) -> Result<Box<dyn AeadCipher>, EncryptionError> {
    match method.to_lowercase().as_str() {
        "chacha20-ietf-poly1305" => {
            let cipher = XChaCha20Aead::new(key)?;
            Ok(Box::new(cipher))
        }
        "aes-256-gcm" => {
            let cipher = Aes256Gcm::new(key)?;
            Ok(Box::new(cipher))
        }
        "aes-128-gcm" => {
            let cipher = Aes128Gcm::new(key)?;
            Ok(Box::new(cipher))
        }
        _ => {
            log_warn!("Неподдерживаемый AEAD-шифр: {}", method);
            Err(EncryptionError::InvalidMethod(method.to_string()))
        }
    }
}

/// Поддерживаемые AEAD-методы шифрования
pub enum AeadMethod {
    XChaCha20Poly1305,
    Aes256Gcm,
    Aes128Gcm,
}

impl AeadMethod {
    /// Создаёт шифратор на основе строки
    pub fn from_str(s: &str) -> Result<Self, EncryptionError> {
        match s.to_lowercase().as_str() {
            "chacha20-ietf-poly1305" => Ok(AeadMethod::XChaCha20Poly1305),
            "aes-256-gcm" => Ok(AeadMethod::Aes256Gcm),
            "aes-128-gcm" => Ok(AeadMethod::Aes128Gcm),
            _ => {
                log_warn!("Неверный метод шифрования: {}", s);
                Err(EncryptionError::InvalidMethod(s.to_string()))
            }
        }
    }

    /// Возвращает список поддерживаемых методов
    pub fn supported_methods() -> Vec<&'static str> {
        vec!["chacha20-ietf-poly1305", "aes-256-gcm", "aes-128-gcm"]
    }

    /// Создаёт шифратор
    pub fn create_cipher(&self, key: &[u8]) -> Result<Box<dyn AeadCipher>, EncryptionError> {
        match self {
            AeadMethod::XChaCha20Poly1305 => {
                let cipher = XChaCha20Aead::new(key)?;
                Ok(Box::new(cipher))
            }
            AeadMethod::Aes256Gcm => {
                let cipher = Aes256Gcm::new(key)?;
                Ok(Box::new(cipher))
            }
            AeadMethod::Aes128Gcm => {
                let cipher = Aes128Gcm::new(key)?;
                Ok(Box::new(cipher))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::common::{generate_random_string, encode_base64};

    #[tokio::test]
    async fn test_xchacha20poly1305_encrypt_decrypt() {
        let key = generate_random_key(32).unwrap();
        let cipher = XChaCha20Aead::new(&key).unwrap();
        let nonce = XChaCha20Aead::generate_nonce();

        let plaintext = b"Hello, world!";
        let encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).unwrap();
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
        log_info!("XChaCha20Poly1305: тест шифрования успешен");
    }

    #[tokio::test]
    async fn test_aes256gcm_encrypt_decrypt() {
        let key = generate_random_key(32).unwrap();
        let cipher = Aes256Gcm::new(&key).unwrap();
        let nonce = Aes256Gcm::generate_nonce();

        let plaintext = b"Secret message";
        let encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).unwrap();
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
        log_info!("AES-256-GCM: тест шифрования успешен");
    }

    #[tokio::test]
    async fn test_invalid_nonce_lengths() {
        let key = generate_random_key(32).unwrap();
        let cipher = Aes256Gcm::new(&key).unwrap();

        let plaintext = b"test";
        let bad_nonce = vec![0u8; 8]; // Неверная длина

        assert!(cipher.encrypt_with_nonce(plaintext, &bad_nonce).is_err());
        log_debug!("Тест: ошибка на неверной длине nonce успешна");
    }

    #[tokio::test]
    async fn test_create_aead_cipher() {
        let key = generate_random_key(32).unwrap();
        let cipher = create_aead_cipher("chacha20-ietf-poly1305", &key).unwrap();
        let nonce = XChaCha20Aead::generate_nonce();
        let encrypted = cipher.encrypt_with_nonce(b"test", &nonce).unwrap();
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).unwrap();
        assert_eq!(decrypted, b"test");
        log_info!("create_aead_cipher: шифр создан и работает");
    }
}
