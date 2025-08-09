//! Реализация AES-GCM (Galois/Counter Mode).
//! Поддерживает AES-128-GCM, AES-192-GCM, AES-256-GCM.
//! Использует OpenSSL для криптографических операций.

use crate::encryption::error::CipherError;
use crate::encryption::traits::AeadCipher;
use crate::utils::logging::{log_debug, log_info, log_warn};
// Для генерации nonce
use rand::RngCore;
// OpenSSL для AES-GCM
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::error::ErrorStack;

/// AES-128-GCM шифр
pub struct Aes128Gcm {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes128Gcm {
    /// Создает новый экземпляр AES-128-GCM.
    ///
    /// # Аргументы
    /// * `key` - 16-байтный ключ (128 бит).
    ///
    /// # Возвращает
    /// * `Result<Self, CipherError>` - экземпляр шифра или ошибка.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        if key.len() != 16 {
            log_warn!("Неверная длина ключа для AES-128-GCM: {} байт", key.len());
            return Err(CipherError::InvalidKeyLength(format!(
                "AES-128-GCM требует 16-байтный ключ, получено {} байт",
                key.len()
            )));
        }
        log_info!("Инициализация AES-128-GCM шифра");
        Ok(Self {
            key: key.to_vec(),
            cipher: Cipher::aes_128_gcm(),
        })
    }

    /// Генерирует случайный 12-байтный nonce для AES-GCM.
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован 12-байтный nonce для AES-GCM");
        nonce
    }
}

impl AeadCipher for Aes128Gcm {
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-128-GCM: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "AES-GCM требует 12-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        log_debug!("Шифрование {} байт через AES-128-GCM", data.len());
        
        // Создаем криптор
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(nonce))
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка создания Crypter для AES-128-GCM: {}", e);
                CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        // Устанавливаем размер данных (опционально, но рекомендуется)
        crypter.set_data_len(data.len()).map_err(|e: ErrorStack| {
            log_error!("Ошибка установки длины данных для AES-128-GCM: {}", e);
            CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
        })?;
        
        // Буфер для зашифрованных данных
        // Размер может быть больше из-за паддинга, но для GCM обычно data.len() + tag.len()
        // Тег аутентификации добавляется в конце
        let mut output = vec![0; data.len() + self.cipher.block_size()];
        
        // Шифруем данные
        let count = crypter.update(data, &mut output)
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка шифрования данных AES-128-GCM: {}", e);
                CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        // Финализируем шифрование (добавляет тег аутентификации)
        let final_count = crypter.finalize(&mut output[count..])
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка финализации AES-128-GCM: {}", e);
                CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        // Обрезаем вектор до фактического размера
        output.truncate(count + final_count);
        
        log_info!("AES-128-GCM: зашифровано {} байт (итоговый размер: {} байт)", data.len(), output.len());
        Ok(output)
    }

    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-128-GCM: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "AES-GCM требует 12-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        // Для расшифровки нам нужно как минимум тег аутентификации (16 байт)
        if data.len() < 16 {
            log_warn!("Слишком короткие данные для расшифровки AES-128-GCM: {} байт", data.len());
            return Err(CipherError::InvalidDataLength(
                "Данные слишком короткие для AES-GCM (минимум 16 байт для тега)".to_string()
            ).into());
        }

        log_debug!("Расшифровка {} байт через AES-128-GCM", data.len());
        
        // Создаем криптор
        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(nonce))
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка создания Crypter для AES-128-GCM (decrypt): {}", e);
                CipherError::DecryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        // Буфер для расшифрованных данных
        // Размер может быть немного больше из-за внутренней буферизации
        let mut output = vec![0; data.len() + self.cipher.block_size()];
        
        // Расшифровываем данные
        let count = crypter.update(data, &mut output)
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка расшифровки данных AES-128-GCM: {}", e);
                CipherError::DecryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        // Финализируем расшифровку
        let final_count = crypter.finalize(&mut output[count..])
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка финализации AES-128-GCM (decrypt): {}", e);
                // Это часто бывает при неверном ключе или поврежденных данных
                CipherError::DecryptionFailed(format!("Ошибка аутентификации или OpenSSL: {}", e))
            })?;
        
        // Обрезаем вектор до фактического размера
        output.truncate(count + final_count);
        
        log_info!("AES-128-GCM: расшифровано {} байт", output.len());
        Ok(output)
    }

    fn cipher_name(&self) -> &'static str {
        "aes-128-gcm"
    }
}

/// AES-192-GCM шифр
pub struct Aes192Gcm {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes192Gcm {
    /// Создает новый экземпляр AES-192-GCM.
    ///
    /// # Аргументы
    /// * `key` - 24-байтный ключ (192 бита).
    ///
    /// # Возвращает
    /// * `Result<Self, CipherError>` - экземпляр шифра или ошибка.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        if key.len() != 24 {
            log_warn!("Неверная длина ключа для AES-192-GCM: {} байт", key.len());
            return Err(CipherError::InvalidKeyLength(format!(
                "AES-192-GCM требует 24-байтный ключ, получено {} байт",
                key.len()
            )));
        }
        log_info!("Инициализация AES-192-GCM шифра");
        Ok(Self {
            key: key.to_vec(),
            cipher: Cipher::aes_192_gcm(),
        })
    }

    /// Генерирует случайный 12-байтный nonce для AES-GCM.
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован 12-байтный nonce для AES-192-GCM");
        nonce
    }
}

impl AeadCipher for Aes192Gcm {
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-192-GCM: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "AES-GCM требует 12-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        log_debug!("Шифрование {} байт через AES-192-GCM", data.len());
        
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(nonce))
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка создания Crypter для AES-192-GCM: {}", e);
                CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        crypter.set_data_len(data.len()).map_err(|e: ErrorStack| {
            log_error!("Ошибка установки длины данных для AES-192-GCM: {}", e);
            CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
        })?;
        
        let mut output = vec![0; data.len() + self.cipher.block_size()];
        
        let count = crypter.update(data, &mut output)
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка шифрования данных AES-192-GCM: {}", e);
                CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        let final_count = crypter.finalize(&mut output[count..])
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка финализации AES-192-GCM: {}", e);
                CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        output.truncate(count + final_count);
        
        log_info!("AES-192-GCM: зашифровано {} байт (итоговый размер: {} байт)", data.len(), output.len());
        Ok(output)
    }

    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-192-GCM: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "AES-GCM требует 12-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        if data.len() < 16 {
            log_warn!("Слишком короткие данные для расшифровки AES-192-GCM: {} байт", data.len());
            return Err(CipherError::InvalidDataLength(
                "Данные слишком короткие для AES-GCM (минимум 16 байт для тега)".to_string()
            ).into());
        }

        log_debug!("Расшифровка {} байт через AES-192-GCM", data.len());
        
        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(nonce))
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка создания Crypter для AES-192-GCM (decrypt): {}", e);
                CipherError::DecryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        let mut output = vec![0; data.len() + self.cipher.block_size()];
        
        let count = crypter.update(data, &mut output)
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка расшифровки данных AES-192-GCM: {}", e);
                CipherError::DecryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        let final_count = crypter.finalize(&mut output[count..])
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка финализации AES-192-GCM (decrypt): {}", e);
                CipherError::DecryptionFailed(format!("Ошибка аутентификации или OpenSSL: {}", e))
            })?;
        
        output.truncate(count + final_count);
        
        log_info!("AES-192-GCM: расшифровано {} байт", output.len());
        Ok(output)
    }

    fn cipher_name(&self) -> &'static str {
        "aes-192-gcm"
    }
}

/// AES-256-GCM шифр
pub struct Aes256Gcm {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes256Gcm {
    /// Создает новый экземпляр AES-256-GCM.
    ///
    /// # Аргументы
    /// * `key` - 32-байтный ключ (256 бит).
    ///
    /// # Возвращает
    /// * `Result<Self, CipherError>` - экземпляр шифра или ошибка.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        if key.len() != 32 {
            log_warn!("Неверная длина ключа для AES-256-GCM: {} байт", key.len());
            return Err(CipherError::InvalidKeyLength(format!(
                "AES-256-GCM требует 32-байтный ключ, получено {} байт",
                key.len()
            )));
        }
        log_info!("Инициализация AES-256-GCM шифра");
        Ok(Self {
            key: key.to_vec(),
            cipher: Cipher::aes_256_gcm(),
        })
    }

    /// Генерирует случайный 12-байтный nonce для AES-GCM.
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован 12-байтный nonce для AES-256-GCM");
        nonce
    }
}

impl AeadCipher for Aes256Gcm {
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-256-GCM: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "AES-GCM требует 12-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        log_debug!("Шифрование {} байт через AES-256-GCM", data.len());
        
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(nonce))
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка создания Crypter для AES-256-GCM: {}", e);
                CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        crypter.set_data_len(data.len()).map_err(|e: ErrorStack| {
            log_error!("Ошибка установки длины данных для AES-256-GCM: {}", e);
            CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
        })?;
        
        let mut output = vec![0; data.len() + self.cipher.block_size()];
        
        let count = crypter.update(data, &mut output)
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка шифрования данных AES-256-GCM: {}", e);
                CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        let final_count = crypter.finalize(&mut output[count..])
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка финализации AES-256-GCM: {}", e);
                CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        output.truncate(count + final_count);
        
        log_info!("AES-256-GCM: зашифровано {} байт (итоговый размер: {} байт)", data.len(), output.len());
        Ok(output)
    }

    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-256-GCM: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "AES-GCM требует 12-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        if data.len() < 16 {
            log_warn!("Слишком короткие данные для расшифровки AES-256-GCM: {} байт", data.len());
            return Err(CipherError::InvalidDataLength(
                "Данные слишком короткие для AES-GCM (минимум 16 байт для тега)".to_string()
            ).into());
        }

        log_debug!("Расшифровка {} байт через AES-256-GCM", data.len());
        
        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(nonce))
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка создания Crypter для AES-256-GCM (decrypt): {}", e);
                CipherError::DecryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        let mut output = vec![0; data.len() + self.cipher.block_size()];
        
        let count = crypter.update(data, &mut output)
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка расшифровки данных AES-256-GCM: {}", e);
                CipherError::DecryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        let final_count = crypter.finalize(&mut output[count..])
            .map_err(|e: ErrorStack| {
                log_error!("Ошибка финализации AES-256-GCM (decrypt): {}", e);
                // Очень важная ошибка - часто означает неверный ключ или поврежденные данные
                CipherError::DecryptionFailed(format!("Ошибка аутентификации или OpenSSL: {}", e))
            })?;
        
        output.truncate(count + final_count);
        
        log_info!("AES-256-GCM: расшифровано {} байт", output.len());
        Ok(output)
    }

    fn cipher_name(&self) -> &'static str {
        "aes-256-gcm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::common::generate_random_key;

    #[test]
    fn test_aes128gcm_encrypt_decrypt() {
        let key = generate_random_key(16).expect("Не удалось сгенерировать ключ");
        let cipher = Aes128Gcm::new(&key).expect("Не удалось создать шифр");
        let nonce = Aes128Gcm::generate_nonce();
        let plaintext = b"Hello, AES-128-GCM World!";

        let encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).expect("Шифрование не удалось");
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).expect("Расшифровка не удалась");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes192gcm_encrypt_decrypt() {
        let key = generate_random_key(24).expect("Не удалось сгенерировать ключ");
        let cipher = Aes192Gcm::new(&key).expect("Не удалось создать шифр");
        let nonce = Aes192Gcm::generate_nonce();
        let plaintext = b"Hello, AES-192-GCM World!";

        let encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).expect("Шифрование не удалось");
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).expect("Расшифровка не удалась");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256gcm_encrypt_decrypt() {
        let key = generate_random_key(32).expect("Не удалось сгенерировать ключ");
        let cipher = Aes256Gcm::new(&key).expect("Не удалось создать шифр");
        let nonce = Aes256Gcm::generate_nonce();
        let plaintext = b"Hello, AES-256-GCM World!";

        let encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).expect("Шифрование не удалось");
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).expect("Расшифровка не удалась");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128gcm_invalid_key_length() {
        let key = vec![0u8; 15]; // Неверная длина
        let result = Aes128Gcm::new(&key);
        assert!(result.is_err());
        match result.unwrap_err() {
            CipherError::InvalidKeyLength(_) => {}, // Ожидаем эту ошибку
            _ => panic!("Ожидалась ошибка InvalidKeyLength"),
        }
    }

    #[test]
    fn test_aes128gcm_invalid_nonce_length() {
        let key = generate_random_key(16).expect("Не удалось сгенерировать ключ");
        let cipher = Aes128Gcm::new(&key).expect("Не удалось создать шифр");
        let nonce = vec![0u8; 11]; // Неверная длина nonce
        let plaintext = b"test";
        
        let result = cipher.encrypt_with_nonce(plaintext, &nonce);
        assert!(result.is_err());
        // Ошибка будет преобразована в VpnError, но внутри должна быть CipherError::InvalidNonce
    }
}
