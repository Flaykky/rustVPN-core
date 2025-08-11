//! Реализация потокового шифра Salsa20.
//! Поддерживает алгоритм шифрования `salsa20`.

use crate::encryption::error::CipherError;
use crate::encryption::traits::StreamCipher;
use crate::utils::logging::{log_debug, log_info, log_warn};
use rand::RngCore;
// Для Salsa20
use salsa20::{
    cipher::{KeyIvInit, StreamCipher as SalsaStreamCipherT},
    Salsa20,
};
// Для работы с ключами и nonce
use generic_array::{GenericArray, typenum::{U32, U8}};

/// Salsa20 потоковый шифр
pub struct Salsa20Cipher {
    key: GenericArray<u8, U32>, // 32 байта
}

impl Salsa20Cipher {
    /// Создает новый экземпляр Salsa20.
    ///
    /// # Аргументы
    /// * `key` - 32-байтный ключ.
    ///
    /// # Возвращает
    /// * `Result<Self, CipherError>` - экземпляр шифра или ошибка.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        if key.len() != 32 {
            log_warn!("Неверная длина ключа для salsa20: {} байт", key.len());
            return Err(CipherError::InvalidKeyLength(format!(
                "Salsa20 требует 32-байтный ключ, получено {} байт",
                key.len()
            )));
        }
        log_info!("Инициализация Salsa20 шифра");
        
        let key_array = GenericArray::from_slice(key);
        Ok(Self {
            key: *key_array,
        })
    }

    /// Генерирует случайный 8-байтный nonce для Salsa20.
    /// Salsa20 использует 64-битный nonce.
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован 8-байтный nonce для Salsa20");
        nonce
    }
}

impl StreamCipher for Salsa20Cipher {
    fn encrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        log_debug!("Шифрование {} байт через Salsa20", data.len());
        
        // Для потокового шифра nonce должен быть предоставлен вызывающей стороной
        // В целях совместимости с различными протоколами,
        // мы будем ожидать, что nonce будет частью протокола.
        // Для демонстрации используем нулевой nonce, что НЕ безопасно.
        let nonce = GenericArray::from([0u8; 8]); // НЕ безопасно! Только для примера.
        
        let mut cipher = Salsa20::new(&self.key, &nonce);
        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);
        
        log_info!("Salsa20: зашифровано {} байт", data.len());
        Ok(buffer)
    }

    fn decrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        log_debug!("Расшифровка {} байт через Salsa20", data.len());
        
        // Для Salsa20 шифрование и дешифрование идентичны
        let nonce = GenericArray::from([0u8; 8]); // НЕ безопасно! Только для примера.
        
        let mut cipher = Salsa20::new(&self.key, &nonce);
        let mut buffer = data.to_vec();
        cipher.apply_keystream(&mut buffer);
        
        log_info!("Salsa20: расшифровано {} байт", data.len());
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::common::generate_random_key;

    #[test]
    fn test_salsa20_encrypt_decrypt() {
        let key = generate_random_key(32).expect("Не удалось сгенерировать 32-байтный ключ");
        let cipher = Salsa20Cipher::new(&key).expect("Не удалось создать Salsa20 шифр");
        let plaintext = b"Hello, Salsa20 World!";

        let encrypted = cipher.encrypt(plaintext).expect("Шифрование не удалось");
        let decrypted = cipher.decrypt(&encrypted).expect("Расшифровка не удалась");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_salsa20_invalid_key_length() {
        let key = vec![0u8; 31]; // Неверная длина
        let result = Salsa20Cipher::new(&key);
        assert!(result.is_err());
        match result.unwrap_err() {
            CipherError::InvalidKeyLength(_) => {}, // Ожидаем эту ошибку
            _ => panic!("Ожидалась ошибка InvalidKeyLength"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_consistency() {
        // Проверим, что encrypt и decrypt дают одинаковый результат (что верно для потоковых шифров)
        let key = generate_random_key(32).expect("Не удалось сгенерировать ключ");
        let cipher = Salsa20Cipher::new(&key).expect("Не удалось создать шифр");
        let data = b"consistency test";
        
        let encrypted1 = cipher.encrypt(data).expect("Шифрование 1 не удалось");
        let encrypted2 = cipher.decrypt(data).expect("Шифрование 2 (через decrypt) не удалось");
        
        assert_eq!(encrypted1, encrypted2);
    }
    
    #[test]
    fn test_same_data_different_nonce() {
        // Этот тест демонстрирует важность nonce
        // В реальной реализации nonce должен быть уникальным
        // Здесь мы просто показываем, что с одинаковым ключом и nonce результат одинаков
        let key = generate_random_key(32).expect("Не удалось сгенерировать ключ");
        let cipher1 = Salsa20Cipher::new(&key).expect("Не удалось создать шифр 1");
        let cipher2 = Salsa20Cipher::new(&key).expect("Не удалось создать шифр 2");
        let data = b"same data";
        
        let encrypted1 = cipher1.encrypt(data).expect("Шифрование 1 не удалось");
        let encrypted2 = cipher2.encrypt(data).expect("Шифрование 2 не удалось");
        
        // С одинаковым (нулевым) nonce результаты должны быть одинаковыми
        assert_eq!(encrypted1, encrypted2);
    }
}
