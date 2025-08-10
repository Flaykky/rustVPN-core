//! Реализация потоковых шифров ChaCha.
//! Поддерживает:
//! - chacha20-ietf (потоковый шифр)
//! - chacha20-ietf-poly1305 (AEAD)
//! - xchacha20-ietf-poly1305 (AEAD с расширенным nonce)

use crate::encryption::error::CipherError;
use crate::encryption::traits::{StreamCipher, AeadCipher};
use crate::utils::logging::{log_debug, log_info, log_warn};
use rand::RngCore;
// Для ChaCha20 (stream cipher)
use chacha20::{ChaCha20, Key, Nonce, StreamCipher as ChaChaStreamCipherT};
// Для ChaCha20-Poly1305 (AEAD)
use chacha20poly1305::{
    aead::{Aead, KeyInit, Nonce as AeadNonce},
    ChaCha20Poly1305, XChaCha20Poly1305,
};
// Для работы с массивами
use generic_array::GenericArray;

// --- ChaCha20-IEFT (потоковый шифр) ---

/// ChaCha20-IEFT потоковый шифр
pub struct ChaCha20Ietf {
    key: Key,
}

impl ChaCha20Ietf {
    /// Создает новый экземпляр ChaCha20-IEFT.
    ///
    /// # Аргументы
    /// * `key` - 32-байтный ключ.
    ///
    /// # Возвращает
    /// * `Result<Self, CipherError>` - экземпляр шифра или ошибка.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        if key.len() != 32 {
            log_warn!("Неверная длина ключа для chacha20-ietf: {} байт", key.len());
            return Err(CipherError::InvalidKeyLength(format!(
                "ChaCha20 требует 32-байтный ключ, получено {} байт",
                key.len()
            )));
        }
        log_info!("Инициализация ChaCha20-IEFT шифра");
        
        let key_array = Key::from_slice(key);
        Ok(Self {
            key: *key_array,
        })
    }

    /// Генерирует случайный 12-байтный nonce для ChaCha20.
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован 12-байтный nonce для ChaCha20-IEFT");
        nonce
    }
}

impl StreamCipher for ChaCha20Ietf {
    fn encrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        log_debug!("Шифрование {} байт через ChaCha20-IEFT", data.len());
        
        // Для потокового шифра nonce должен быть предоставлен вызывающей стороной
        // В целях совместимости с shadowsocks, где nonce передается отдельно,
        // мы будем ожидать, что nonce будет частью протокола.
        // Для демонстрации используем нулевой nonce, что НЕ безопасно.
        let nonce = Nonce::from([0u8; 12]); // НЕ безопасно! Только для примера.
        
        let mut cipher = ChaCha20::new(&self.key.into(), &nonce);
        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);
        
        log_info!("ChaCha20-IEFT: зашифровано {} байт", data.len());
        Ok(buffer)
    }

    fn decrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        log_debug!("Расшифровка {} байт через ChaCha20-IEFT", data.len());
        
        // Для ChaCha20 шифрование и дешифрование идентичны
        let nonce = Nonce::from([0u8; 12]); // НЕ безопасно! Только для примера.
        
        let mut cipher = ChaCha20::new(&self.key.into(), &nonce);
        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);
        
        log_info!("ChaCha20-IEFT: расшифровано {} байт", data.len());
        Ok(buffer)
    }
}

// --- ChaCha20-IEFT-Poly1305 (AEAD) ---

/// ChaCha20-IEFT-Poly1305 AEAD шифр
pub struct ChaCha20IetfPoly1305 {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20IetfPoly1305 {
    /// Создает новый экземпляр ChaCha20-IEFT-Poly1305.
    ///
    /// # Аргументы
    /// * `key` - 32-байтный ключ.
    ///
    /// # Возвращает
    /// * `Result<Self, CipherError>` - экземпляр шифра или ошибка.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        if key.len() != 32 {
            log_warn!("Неверная длина ключа для chacha20-ietf-poly1305: {} байт", key.len());
            return Err(CipherError::InvalidKeyLength(format!(
                "ChaCha20-Poly1305 требует 32-байтный ключ, получено {} байт",
                key.len()
            )));
        }
        log_info!("Инициализация ChaCha20-IEFT-Poly1305 шифра");
        
        let key_array = GenericArray::from_slice(key);
        let cipher = ChaCha20Poly1305::new(key_array);
        Ok(Self { cipher })
    }

    /// Генерирует случайный 12-байтный nonce для ChaCha20-Poly1305.
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован 12-байтный nonce для ChaCha20-IEFT-Poly1305");
        nonce
    }
}

impl AeadCipher for ChaCha20IetfPoly1305 {
    fn encrypt_with_nonce(&self,  &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для ChaCha20-IEFT-Poly1305: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "ChaCha20-Poly1305 требует 12-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        log_debug!("Шифрование {} байт через ChaCha20-IEFT-Poly1305", data.len());
        
        let nonce_array = AeadNonce::from_slice(nonce);
        let encrypted = self.cipher.encrypt(nonce_array, data)
            .map_err(|e| {
                log::error!("Ошибка шифрования ChaCha20-IEFT-Poly1305: {:?}", e);
                CipherError::EncryptionFailed(format!("ChaCha20-Poly1305 encryption error: {:?}", e))
            })?;
        
        log_info!("ChaCha20-IEFT-Poly1305: зашифровано {} байт (итоговый размер: {} байт)", 
                  data.len(), encrypted.len());
        Ok(encrypted)
    }

    fn decrypt_with_nonce(&self,  &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для ChaCha20-IEFT-Poly1305: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "ChaCha20-Poly1305 требует 12-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        // Для расшифровки данные должны содержать тег аутентификации (16 байт)
        if data.len() < 16 {
            log_warn!("Слишком короткие данные для расшифровки ChaCha20-IEFT-Poly1305: {} байт", data.len());
            return Err(CipherError::InvalidDataLength(
                "Данные слишком короткие для ChaCha20-Poly1305 (минимум 16 байт для тега)".to_string()
            ).into());
        }

        log_debug!("Расшифровка {} байт через ChaCha20-IEFT-Poly1305", data.len());
        
        let nonce_array = AeadNonce::from_slice(nonce);
        let decrypted = self.cipher.decrypt(nonce_array, data)
            .map_err(|e| {
                log::error!("Ошибка расшифровки ChaCha20-IEFT-Poly1305 (возможно, ошибка аутентификации): {:?}", e);
                CipherError::DecryptionFailed(format!("ChaCha20-Poly1305 decryption/authentication error: {:?}", e))
            })?;
        
        log_info!("ChaCha20-IEFT-Poly1305: расшифровано {} байт", decrypted.len());
        Ok(decrypted)
    }

    fn cipher_name(&self) -> &'static str {
        "chacha20-ietf-poly1305"
    }
}

// --- XChaCha20-IEFT-Poly1305 (AEAD с расширенным nonce) ---

/// XChaCha20-IEFT-Poly1305 AEAD шифр
pub struct XChaCha20IetfPoly1305 {
    cipher: XChaCha20Poly1305,
}

impl XChaCha20IetfPoly1305 {
    /// Создает новый экземпляр XChaCha20-IEFT-Poly1305.
    ///
    /// # Аргументы
    /// * `key` - 32-байтный ключ.
    ///
    /// # Возвращает
    /// * `Result<Self, CipherError>` - экземпляр шифра или ошибка.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        if key.len() != 32 {
            log_warn!("Неверная длина ключа для xchacha20-ietf-poly1305: {} байт", key.len());
            return Err(CipherError::InvalidKeyLength(format!(
                "XChaCha20-Poly1305 требует 32-байтный ключ, получено {} байт",
                key.len()
            )));
        }
        log_info!("Инициализация XChaCha20-IEFT-Poly1305 шифра");
        
        let key_array = GenericArray::from_slice(key);
        let cipher = XChaCha20Poly1305::new(key_array);
        Ok(Self { cipher })
    }

    /// Генерирует случайный 24-байтный nonce для XChaCha20-Poly1305.
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован 24-байтный nonce для XChaCha20-IEFT-Poly1305");
        nonce
    }
}

impl AeadCipher for XChaCha20IetfPoly1305 {
    fn encrypt_with_nonce(&self,  &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 24 {
            log_warn!("Неверная длина nonce для XChaCha20-IEFT-Poly1305: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "XChaCha20-Poly1305 требует 24-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        log_debug!("Шифрование {} байт через XChaCha20-IEFT-Poly1305", data.len());
        
        let nonce_array = chacha20poly1305::XNonce::from_slice(nonce);
        let encrypted = self.cipher.encrypt(nonce_array, data)
            .map_err(|e| {
                log::error!("Ошибка шифрования XChaCha20-IEFT-Poly1305: {:?}", e);
                CipherError::EncryptionFailed(format!("XChaCha20-Poly1305 encryption error: {:?}", e))
            })?;
        
        log_info!("XChaCha20-IEFT-Poly1305: зашифровано {} байт (итоговый размер: {} байт)", 
                  data.len(), encrypted.len());
        Ok(encrypted)
    }

    fn decrypt_with_nonce(&self,  &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 24 {
            log_warn!("Неверная длина nonce для XChaCha20-IEFT-Poly1305: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "XChaCha20-Poly1305 требует 24-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        if data.len() < 16 {
            log_warn!("Слишком короткие данные для расшифровки XChaCha20-IEFT-Poly1305: {} байт", data.len());
            return Err(CipherError::InvalidDataLength(
                "Данные слишком короткие для XChaCha20-Poly1305 (минимум 16 байт для тега)".to_string()
            ).into());
        }

        log_debug!("Расшифровка {} байт через XChaCha20-IEFT-Poly1305", data.len());
        
        let nonce_array = chacha20poly1305::XNonce::from_slice(nonce);
        let decrypted = self.cipher.decrypt(nonce_array, data)
            .map_err(|e| {
                log::error!("Ошибка расшифровки XChaCha20-IEFT-Poly1305 (возможно, ошибка аутентификации): {:?}", e);
                CipherError::DecryptionFailed(format!("XChaCha20-Poly1305 decryption/authentication error: {:?}", e))
            })?;
        
        log_info!("XChaCha20-IEFT-Poly1305: расшифровано {} байт", decrypted.len());
        Ok(decrypted)
    }

    fn cipher_name(&self) -> &'static str {
        "xchacha20-ietf-poly1305"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::common::generate_random_key;

    #[test]
    fn test_chacha20_ietf_encrypt_decrypt() {
        let key = generate_random_key(32).expect("Не удалось сгенерировать 32-байтный ключ");
        let cipher = ChaCha20Ietf::new(&key).expect("Не удалось создать ChaCha20-IEFT шифр");
        let plaintext = b"Hello, ChaCha20-IEFT World!";

        let encrypted = cipher.encrypt(plaintext).expect("Шифрование не удалось");
        let decrypted = cipher.decrypt(&encrypted).expect("Расшифровка не удалась");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_ietf_poly1305_encrypt_decrypt() {
        let key = generate_random_key(32).expect("Не удалось сгенерировать 32-байтный ключ");
        let cipher = ChaCha20IetfPoly1305::new(&key).expect("Не удалось создать ChaCha20-IEFT-Poly1305 шифр");
        let nonce = ChaCha20IetfPoly1305::generate_nonce();
        let plaintext = b"Hello, ChaCha20-IEFT-Poly1305 World!";

        let encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).expect("Шифрование не удалось");
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).expect("Расшифровка не удалась");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_xchacha20_ietf_poly1305_encrypt_decrypt() {
        let key = generate_random_key(32).expect("Не удалось сгенерировать 32-байтный ключ");
        let cipher = XChaCha20IetfPoly1305::new(&key).expect("Не удалось создать XChaCha20-IEFT-Poly1305 шифр");
        let nonce = XChaCha20IetfPoly1305::generate_nonce();
        let plaintext = b"Hello, XChaCha20-IEFT-Poly1305 World!";

        let encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).expect("Шифрование не удалось");
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).expect("Расшифровка не удалась");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_ietf_invalid_key_length() {
        let key = vec![0u8; 31]; // Неверная длина
        let result = ChaCha20Ietf::new(&key);
        assert!(result.is_err());
        match result.unwrap_err() {
            CipherError::InvalidKeyLength(_) => {}, // Ожидаем эту ошибку
            _ => panic!("Ожидалась ошибка InvalidKeyLength"),
        }
    }

    #[test]
    fn test_chacha20_ietf_poly1305_invalid_nonce_length() {
        let key = generate_random_key(32).expect("Не удалось сгенерировать ключ");
        let cipher = ChaCha20IetfPoly1305::new(&key).expect("Не удалось создать шифр");
        let nonce = vec![0u8; 11]; // Неверная длина nonce
        let plaintext = b"test";
        
        let result = cipher.encrypt_with_nonce(plaintext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_xchacha20_ietf_poly1305_invalid_nonce_length() {
        let key = generate_random_key(32).expect("Не удалось сгенерировать ключ");
        let cipher = XChaCha20IetfPoly1305::new(&key).expect("Не удалось создать шифр");
        let nonce = vec![0u8; 23]; // Неверная длина nonce
        let plaintext = b"test";
        
        let result = cipher.encrypt_with_nonce(plaintext, &nonce);
        assert!(result.is_err());
    }

    #[test]
    fn test_chacha20_ietf_poly1305_decryption_failure_on_tampered_data() {
        let key = generate_random_key(32).expect("Не удалось сгенерировать ключ");
        let cipher = ChaCha20IetfPoly1305::new(&key).expect("Не удалось создать шифр");
        let nonce = ChaCha20IetfPoly1305::generate_nonce();
        let plaintext = b"original data";
        
        let mut encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).expect("Шифрование не удалось");
        
        // Портим данные
        if !encrypted.is_empty() {
            encrypted[0] ^= 0x01;
        }
        
        let result = cipher.decrypt_with_nonce(&encrypted, &nonce);
        assert!(result.is_err());
    }
}
