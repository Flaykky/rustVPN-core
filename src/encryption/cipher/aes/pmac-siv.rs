//! Реализация AES-PMAC-SIV шифров.
//! Поддерживает aes-128-pmac-siv и aes-256-pmac-siv.
//! Использует крейт `aes-siv`.

use crate::encryption::error::CipherError;
use crate::encryption::traits::AeadCipher;
use crate::utils::logging::{log_debug, log_info, log_warn};
use aes_siv::aead::{AeadInPlace, KeyInit, Nonce};
// Импорты для Aes128PmacSiv и Aes256PmacSiv
use aes_siv::{Aes128PmacSiv, Aes256PmacSiv};
// Для генерации случайных значений
use rand::RngCore;
// Для работы с массивами фиксированного размера
use generic_array::{GenericArray, ArrayLength};
use std::vec::Vec;

/// AES-128-PMAC-SIV шифр
pub struct Aes128PmacSivCipher {
    cipher: Aes128PmacSiv,
}

impl Aes128PmacSivCipher {
    /// Создает новый экземпляр AES-128-PMAC-SIV.
    ///
    /// # Аргументы
    /// * `key` - 32-байтный ключ (для SIV: половина для шифрования, половина для MAC).
    ///
    /// # Возвращает
    /// * `Result<Self, CipherError>` - экземпляр шифра или ошибка.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        // AES-128-SIV требует 256-битный (32 байта) ключ
        if key.len() != 32 {
            log_warn!("Неверная длина ключа для AES-128-PMAC-SIV: {} байт", key.len());
            return Err(CipherError::InvalidKeyLength(format!(
                "AES-128-PMAC-SIV требует 32-байтный ключ, получено {} байт",
                key.len()
            )));
        }
        log_info!("Инициализация AES-128-PMAC-SIV шифра");
        
        // Преобразуем &[u8] в GenericArray
        // KeySize для Aes128PmacSiv это U32 (32 байта)
        let key_array: &GenericArray<u8, <Aes128PmacSiv as KeyInit>::KeySize> = 
            GenericArray::from_slice(key);
        
        let cipher = Aes128PmacSiv::new(key_array);
        Ok(Self { cipher })
    }

    /// Генерирует случайный nonce подходящего размера для AES-PMAC-SIV.
    /// Размер nonce для aes-siv крейта обычно 16 байт.
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 16]; // Стандартный размер nonce для SIV
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован 16-байтный nonce для AES-PMAC-SIV");
        nonce
    }
}

impl AeadCipher for Aes128PmacSivCipher {
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        // Проверяем длину nonce
        if nonce.len() != 16 { // Обычно 16 байт для SIV
            log_warn!("Неверная длина nonce для AES-128-PMAC-SIV: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "AES-PMAC-SIV требует 16-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        log_debug!("Шифрование {} байт через AES-128-PMAC-SIV", data.len());
        
        // Копируем данные во временный вектор, так как AeadInPlace работает in-place
        let mut buffer = data.to_vec();
        // Добавляем место под тег аутентификации (обычно добавляется в конец)
        // Но aes-siv крейт обычно сам добавляет тег, так что просто передаем buffer
        
        // Преобразуем nonce
        let nonce_array: &GenericArray<u8, <Aes128PmacSiv as AeadInPlace>::NonceSize> = 
            GenericArray::from_slice(nonce);
        
        // Шифруем данные in-place
        self.cipher.encrypt_in_place(nonce_array, b"", &mut buffer)
            .map_err(|e| {
                log::error!("Ошибка шифрования AES-128-PMAC-SIV: {:?}", e);
                CipherError::EncryptionFailed(format!("AES-SIV encryption error: {:?}", e))
            })?;
        
        log_info!("AES-128-PMAC-SIV: зашифровано {} байт (итоговый размер: {} байт)", data.len(), buffer.len());
        Ok(buffer)
    }

    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 16 {
            log_warn!("Неверная длина nonce для AES-128-PMAC-SIV: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "AES-PMAC-SIV требует 16-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        // Для расшифровки данные должны содержать тег аутентификации
        // Минимальный размер зависит от реализации, но обычно не менее размера тега (16 байт)
        if data.len() < 16 {
            log_warn!("Слишком короткие данные для расшифровки AES-128-PMAC-SIV: {} байт", data.len());
            return Err(CipherError::InvalidDataLength(
                "Данные слишком короткие для AES-PMAC-SIV".to_string()
            ).into());
        }

        log_debug!("Расшифровка {} байт через AES-128-PMAC-SIV", data.len());
        
        // Копируем данные во временный вектор для in-place расшифровки
        let mut buffer = data.to_vec();
        
        // Преобразуем nonce
        let nonce_array: &GenericArray<u8, <Aes128PmacSiv as AeadInPlace>::NonceSize> = 
            GenericArray::from_slice(nonce);
        
        // Расшифровываем данные in-place
        self.cipher.decrypt_in_place(nonce_array, b"", &mut buffer)
            .map_err(|e| {
                log::error!("Ошибка расшифровки AES-128-PMAC-SIV (возможно, ошибка аутентификации): {:?}", e);
                CipherError::DecryptionFailed(format!("AES-SIV decryption/authentication error: {:?}", e))
            })?;
        
        log_info!("AES-128-PMAC-SIV: расшифровано {} байт", buffer.len());
        Ok(buffer)
    }

    fn cipher_name(&self) -> &'static str {
        "aes-128-pmac-siv"
    }
}

/// AES-256-PMAC-SIV шифр
pub struct Aes256PmacSivCipher {
    cipher: Aes256PmacSiv,
}

impl Aes256PmacSivCipher {
    /// Создает новый экземпляр AES-256-PMAC-SIV.
    ///
    /// # Аргументы
    /// * `key` - 64-байтный ключ (для SIV: половина для шифрования, половина для MAC).
    ///
    /// # Возвращает
    /// * `Result<Self, CipherError>` - экземпляр шифра или ошибка.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        // AES-256-SIV требует 512-битный (64 байта) ключ
        if key.len() != 64 {
            log_warn!("Неверная длина ключа для AES-256-PMAC-SIV: {} байт", key.len());
            return Err(CipherError::InvalidKeyLength(format!(
                "AES-256-PMAC-SIV требует 64-байтный ключ, получено {} байт",
                key.len()
            )));
        }
        log_info!("Инициализация AES-256-PMAC-SIV шифра");
        
        // Преобразуем &[u8] в GenericArray
        let key_array: &GenericArray<u8, <Aes256PmacSiv as KeyInit>::KeySize> = 
            GenericArray::from_slice(key);
        
        let cipher = Aes256PmacSiv::new(key_array);
        Ok(Self { cipher })
    }

    /// Генерирует случайный nonce подходящего размера для AES-PMAC-SIV.
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 16]; // Стандартный размер nonce для SIV
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован 16-байтный nonce для AES-256-PMAC-SIV");
        nonce
    }
}

impl AeadCipher for Aes256PmacSivCipher {
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 16 {
            log_warn!("Неверная длина nonce для AES-256-PMAC-SIV: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "AES-PMAC-SIV требует 16-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        log_debug!("Шифрование {} байт через AES-256-PMAC-SIV", data.len());
        
        let mut buffer = data.to_vec();
        
        let nonce_array: &GenericArray<u8, <Aes256PmacSiv as AeadInPlace>::NonceSize> = 
            GenericArray::from_slice(nonce);
        
        self.cipher.encrypt_in_place(nonce_array, b"", &mut buffer)
            .map_err(|e| {
                log::error!("Ошибка шифрования AES-256-PMAC-SIV: {:?}", e);
                CipherError::EncryptionFailed(format!("AES-SIV encryption error: {:?}", e))
            })?;
        
        log_info!("AES-256-PMAC-SIV: зашифровано {} байт (итоговый размер: {} байт)", data.len(), buffer.len());
        Ok(buffer)
    }

    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        if nonce.len() != 16 {
            log_warn!("Неверная длина nonce для AES-256-PMAC-SIV: {} байт", nonce.len());
            return Err(CipherError::InvalidNonce(format!(
                "AES-PMAC-SIV требует 16-байтный nonce, получено {} байт",
                nonce.len()
            )).into());
        }

        if data.len() < 16 {
            log_warn!("Слишком короткие данные для расшифровки AES-256-PMAC-SIV: {} байт", data.len());
            return Err(CipherError::InvalidDataLength(
                "Данные слишком короткие для AES-PMAC-SIV".to_string()
            ).into());
        }

        log_debug!("Расшифровка {} байт через AES-256-PMAC-SIV", data.len());
        
        let mut buffer = data.to_vec();
        
        let nonce_array: &GenericArray<u8, <Aes256PmacSiv as AeadInPlace>::NonceSize> = 
            GenericArray::from_slice(nonce);
        
        self.cipher.decrypt_in_place(nonce_array, b"", &mut buffer)
            .map_err(|e| {
                log::error!("Ошибка расшифровки AES-256-PMAC-SIV (возможно, ошибка аутентификации): {:?}", e);
                CipherError::DecryptionFailed(format!("AES-SIV decryption/authentication error: {:?}", e))
            })?;
        
        log_info!("AES-256-PMAC-SIV: расшифровано {} байт", buffer.len());
        Ok(buffer)
    }

    fn cipher_name(&self) -> &'static str {
        "aes-256-pmac-siv"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::common::generate_random_key;

    #[test]
    fn test_aes128_pmac_siv_encrypt_decrypt() {
        let key = generate_random_key(32).expect("Не удалось сгенерировать 32-байтный ключ");
        let cipher = Aes128PmacSivCipher::new(&key).expect("Не удалось создать AES-128-PMAC-SIV шифр");
        let nonce = Aes128PmacSivCipher::generate_nonce();
        let plaintext = b"Hello, AES-128-PMAC-SIV World!";

        let encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).expect("Шифрование не удалось");
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).expect("Расшифровка не удалась");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes256_pmac_siv_encrypt_decrypt() {
        let key = generate_random_key(64).expect("Не удалось сгенерировать 64-байтный ключ");
        let cipher = Aes256PmacSivCipher::new(&key).expect("Не удалось создать AES-256-PMAC-SIV шифр");
        let nonce = Aes256PmacSivCipher::generate_nonce();
        let plaintext = b"Hello, AES-256-PMAC-SIV World!";

        let encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).expect("Шифрование не удалось");
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).expect("Расшифровка не удалась");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes128_pmac_siv_invalid_key_length() {
        let key = vec![0u8; 31]; // Неверная длина
        let result = Aes128PmacSivCipher::new(&key);
        assert!(result.is_err());
        match result.unwrap_err() {
            CipherError::InvalidKeyLength(_) => {}, // Ожидаем эту ошибку
            _ => panic!("Ожидалась ошибка InvalidKeyLength"),
        }
    }

    #[test]
    fn test_aes256_pmac_siv_invalid_key_length() {
        let key = vec![0u8; 63]; // Неверная длина
        let result = Aes256PmacSivCipher::new(&key);
        assert!(result.is_err());
        match result.unwrap_err() {
            CipherError::InvalidKeyLength(_) => {}, // Ожидаем эту ошибку
            _ => panic!("Ожидалась ошибка InvalidKeyLength"),
        }
    }

    #[test]
    fn test_aes128_pmac_siv_invalid_nonce_length() {
        let key = generate_random_key(32).expect("Не удалось сгенерировать ключ");
        let cipher = Aes128PmacSivCipher::new(&key).expect("Не удалось создать шифр");
        let nonce = vec![0u8; 15]; // Неверная длина nonce
        let plaintext = b"test";
        
        let result = cipher.encrypt_with_nonce(plaintext, &nonce);
        assert!(result.is_err());
        // Ошибка будет преобразована в VpnError, но внутри должна быть CipherError::InvalidNonce
    }

    #[test]
    fn test_aes128_pmac_siv_decryption_failure_on_tampered_data() {
        let key = generate_random_key(32).expect("Не удалось сгенерировать ключ");
        let cipher = Aes128PmacSivCipher::new(&key).expect("Не удалось создать шифр");
        let nonce = Aes128PmacSivCipher::generate_nonce();
        let plaintext = b"original data";
        
        let mut encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).expect("Шифрование не удалось");
        
        // Портим данные
        if !encrypted.is_empty() {
            encrypted[0] ^= 0x01;
        }
        
        let result = cipher.decrypt_with_nonce(&encrypted, &nonce);
        assert!(result.is_err());
        // Ожидаем ошибку расшифровки (аутентификации)
    }
}
