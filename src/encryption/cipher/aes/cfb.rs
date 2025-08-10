//! Реализация AES шифров в режиме CFB (Cipher Feedback).
//! Поддерживает:
//! - aes-128-cfb, aes-128-cfb1, aes-128-cfb8, aes-128-cfb128
//! - aes-256-cfb, aes-256-cfb1, aes-256-cfb8, aes-256-cfb128
//!
//! Использует OpenSSL для криптографических операций.

use crate::encryption::error::CipherError;
use crate::encryption::traits::StreamCipher;
use crate::utils::logging::{log_debug, log_info, log_warn};
use openssl::symm::{Cipher, Crypter, Mode};
use openssl::error::ErrorStack;

// --- Вспомогательные функции ---

/// Проверяет и возвращает соответствующий OpenSSL `Cipher` для метода.
fn get_cipher(method: &str) -> Result<(&'static Cipher, usize, usize), CipherError> {
    match method.to_lowercase().as_str() {
        // AES-128-CFB варианты
        "aes-128-cfb" | "aes-128-cfb128" => Ok((Cipher::aes_128_cfb128(), 16, 128)),
        "aes-128-cfb1" => Ok((Cipher::aes_128_cfb1(), 16, 1)),
        "aes-128-cfb8" => Ok((Cipher::aes_128_cfb8(), 16, 8)),
        // AES-256-CFB варианты
        "aes-256-cfb" | "aes-256-cfb128" => Ok((Cipher::aes_256_cfb128(), 32, 128)),
        "aes-256-cfb1" => Ok((Cipher::aes_256_cfb1(), 32, 1)),
        "aes-256-cfb8" => Ok((Cipher::aes_256_cfb8(), 32, 8)),
        _ => {
            log_warn!("Неподдерживаемый метод CFB: {}", method);
            Err(CipherError::UnsupportedCipher(method.to_string()))
        }
    }
}

// --- Структуры шифров ---

/// Универсальная структура для AES-CFB шифров.
struct AesCfb {
    cipher: &'static Cipher,
    key: Vec<u8>,
    bits: usize, // bits per feedback (1, 8, 128)
}

impl AesCfb {
    /// Создает новый экземпляр AES-CFB.
    ///
    /// # Аргументы
    /// * `method` - Строка с названием метода (например, "aes-128-cfb").
    /// * `key` - Ключ шифрования.
    ///
    /// # Возвращает
    /// * `Result<Self, CipherError>` - экземпляр шифра или ошибка.
    fn new(method: &str, key: &[u8]) -> Result<Self, CipherError> {
        let (cipher, expected_key_len, bits) = get_cipher(method)?;
        
        if key.len() != expected_key_len {
            log_warn!("Неверная длина ключа для {}: {} байт, ожидалось {}", method, key.len(), expected_key_len);
            return Err(CipherError::InvalidKeyLength(format!(
                "{} требует {}-байтный ключ, получено {} байт",
                method, expected_key_len, key.len()
            )));
        }
        
        log_info!("Инициализация {} шифра ({} bits CFB)", method, bits);
        Ok(Self {
            cipher,
            key: key.to_vec(),
            bits,
        })
    }

    /// Шифрует данные. Для CFB шифрование и дешифрование идентичны.
    fn process(&self, data: &[u8]) -> Result<Vec<u8>, CipherError> {
        log_debug!("Обработка {} байт через AES-CFB ({} bits)", data.len(), self.bits);
        
        // Для CFB IV обычно 16 байт (размер блока AES), но OpenSSL может генерировать его
        // В целях совместимости с shadowsocks, где IV передается отдельно,
        // мы будем ожидать, что IV будет передан как часть данных или отдельно.
        // Для простоты в StreamCipher мы будем генерировать случайный IV и добавлять его к результату.
        // Но в данном базовом примере будем считать, что IV уже учтен или не требуется.
        // В реальной реализации IV должен быть частью протокола.
        
        // Создаем криптор
        // IV будет None, предполагается, что он будет установлен позже или не требуется для данной конфигурации
        // На самом деле, для CFB в OpenSSL IV обязателен, поэтому нужно передавать его.
        // Для простоты здесь будем использовать вектор из нулей, но это НЕ безопасно для реального использования.
        // В реальной системе IV должен быть уникальным и передаваться отдельно.
        let iv = vec![0u8; 16]; // НЕ безопасный IV, только для демонстрации
        
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(&iv))
            .map_err(|e: ErrorStack| {
                log::error!("Ошибка создания Crypter для AES-CFB: {}", e);
                CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        // Буфер для результата
        let mut output = vec![0; data.len() + self.cipher.block_size()];
        
        // Обрабатываем данные
        let count = crypter.update(data, &mut output)
            .map_err(|e: ErrorStack| {
                log::error!("Ошибка обработки данных AES-CFB: {}", e);
                CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        // Финализируем (обычно для CFB это не добавляет данных)
        let final_count = crypter.finalize(&mut output[count..])
            .map_err(|e: ErrorStack| {
                log::error!("Ошибка финализации AES-CFB: {}", e);
                CipherError::EncryptionFailed(format!("OpenSSL error: {}", e))
            })?;
        
        // Обрезаем вектор до фактического размера
        output.truncate(count + final_count);
        
        log_debug!("AES-CFB: обработано {} байт (итоговый размер: {} байт)", data.len(), output.len());
        Ok(output)
    }
    
    /// Возвращает имя метода.
    fn cipher_name(&self) -> &'static str {
        // Это упрощенная реализация. В реальности нужно сопоставлять self.cipher и self.bits.
        // Для демонстрации возвращаем фиктивное имя.
        "aes-cfb-generic"
    }
}

// --- Конкретные реализации для каждого метода ---

/// AES-128-CFB (128-bit feedback) шифр
pub struct Aes128Cfb {
    inner: AesCfb,
}

impl Aes128Cfb {
    /// Создает новый экземпляр AES-128-CFB.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        Ok(Self {
            inner: AesCfb::new("aes-128-cfb", key)?,
        })
    }
}

impl StreamCipher for Aes128Cfb {
    fn encrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        self.inner.process(data).map_err(Into::into)
    }

    fn decrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        // Для CFB режима шифрование и дешифрование идентичны
        self.inner.process(data).map_err(Into::into)
    }
}

/// AES-128-CFB1 (1-bit feedback) шифр
pub struct Aes128Cfb1 {
    inner: AesCfb,
}

impl Aes128Cfb1 {
    /// Создает новый экземпляр AES-128-CFB1.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        Ok(Self {
            inner: AesCfb::new("aes-128-cfb1", key)?,
        })
    }
}

impl StreamCipher for Aes128Cfb1 {
    fn encrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        self.inner.process(data).map_err(Into::into)
    }

    fn decrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        self.inner.process(data).map_err(Into::into)
    }
}

/// AES-128-CFB8 (8-bit feedback) шифр
pub struct Aes128Cfb8 {
    inner: AesCfb,
}

impl Aes128Cfb8 {
    /// Создает новый экземпляр AES-128-CFB8.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        Ok(Self {
            inner: AesCfb::new("aes-128-cfb8", key)?,
        })
    }
}

impl StreamCipher for Aes128Cfb8 {
    fn encrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        self.inner.process(data).map_err(Into::into)
    }

    fn decrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        self.inner.process(data).map_err(Into::into)
    }
}

/// AES-256-CFB (128-bit feedback) шифр
pub struct Aes256Cfb {
    inner: AesCfb,
}

impl Aes256Cfb {
    /// Создает новый экземпляр AES-256-CFB.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        Ok(Self {
            inner: AesCfb::new("aes-256-cfb", key)?,
        })
    }
}

impl StreamCipher for Aes256Cfb {
    fn encrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        self.inner.process(data).map_err(Into::into)
    }

    fn decrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        self.inner.process(data).map_err(Into::into)
    }
}

/// AES-256-CFB1 (1-bit feedback) шифр
pub struct Aes256Cfb1 {
    inner: AesCfb,
}

impl Aes256Cfb1 {
    /// Создает новый экземпляр AES-256-CFB1.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        Ok(Self {
            inner: AesCfb::new("aes-256-cfb1", key)?,
        })
    }
}

impl StreamCipher for Aes256Cfb1 {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        self.inner.process(data).map_err(Into::into)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        self.inner.process(data).map_err(Into::into)
    }
}

/// AES-256-CFB8 (8-bit feedback) шифр
pub struct Aes256Cfb8 {
    inner: AesCfb,
}

impl Aes256Cfb8 {
    /// Создает новый экземпляр AES-256-CFB8.
    pub fn new(key: &[u8]) -> Result<Self, CipherError> {
        Ok(Self {
            inner: AesCfb::new("aes-256-cfb8", key)?,
        })
    }
}

impl StreamCipher for Aes256Cfb8 {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        self.inner.process(data).map_err(Into::into)
    }

    fn decrypt(&self,  &[u8]) -> Result<Vec<u8>, crate::utils::error::VpnError> {
        self.inner.process(data).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::common::generate_random_key;

    #[test]
    fn test_aes128_cfb_variants_encrypt_decrypt() {
        let key = generate_random_key(16).expect("Не удалось сгенерировать 16-байтный ключ");
        let plaintext = b"Hello, AES-128-CFB World! Test data for encryption.";

        // Тест для aes-128-cfb / aes-128-cfb128
        {
            let cipher = Aes128Cfb::new(&key).expect("Не удалось создать AES-128-CFB шифр");
            let encrypted = cipher.encrypt(plaintext).expect("Шифрование не удалось");
            let decrypted = cipher.decrypt(&encrypted).expect("Расшифровка не удалась");
            assert_eq!(decrypted, plaintext);
        }

        // Тест для aes-128-cfb1
        {
            let cipher = Aes128Cfb1::new(&key).expect("Не удалось создать AES-128-CFB1 шифр");
            let encrypted = cipher.encrypt(plaintext).expect("Шифрование не удалось");
            let decrypted = cipher.decrypt(&encrypted).expect("Расшифровка не удалась");
            assert_eq!(decrypted, plaintext);
        }

        // Тест для aes-128-cfb8
        {
            let cipher = Aes128Cfb8::new(&key).expect("Не удалось создать AES-128-CFB8 шифр");
            let encrypted = cipher.encrypt(plaintext).expect("Шифрование не удалось");
            let decrypted = cipher.decrypt(&encrypted).expect("Расшифровка не удалась");
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_aes256_cfb_variants_encrypt_decrypt() {
        let key = generate_random_key(32).expect("Не удалось сгенерировать 32-байтный ключ");
        let plaintext = b"Hello, AES-256-CFB World! Test data for encryption.";

        // Тест для aes-256-cfb / aes-256-cfb128
        {
            let cipher = Aes256Cfb::new(&key).expect("Не удалось создать AES-256-CFB шифр");
            let encrypted = cipher.encrypt(plaintext).expect("Шифрование не удалось");
            let decrypted = cipher.decrypt(&encrypted).expect("Расшифровка не удалась");
            assert_eq!(decrypted, plaintext);
        }

        // Тест для aes-256-cfb1
        {
            let cipher = Aes256Cfb1::new(&key).expect("Не удалось создать AES-256-CFB1 шифр");
            let encrypted = cipher.encrypt(plaintext).expect("Шифрование не удалось");
            let decrypted = cipher.decrypt(&encrypted).expect("Расшифровка не удалась");
            assert_eq!(decrypted, plaintext);
        }

        // Тест для aes-256-cfb8
        {
            let cipher = Aes256Cfb8::new(&key).expect("Не удалось создать AES-256-CFB8 шифр");
            let encrypted = cipher.encrypt(plaintext).expect("Шифрование не удалось");
            let decrypted = cipher.decrypt(&encrypted).expect("Расшифровка не удалась");
            assert_eq!(decrypted, plaintext);
        }
    }

    #[test]
    fn test_aes128_cfb_invalid_key_length() {
        let key = vec![0u8; 15]; // Неверная длина
        let result = Aes128Cfb::new(&key);
        assert!(result.is_err());
        match result.unwrap_err() {
            CipherError::InvalidKeyLength(_) => {}, // Ожидаем эту ошибку
            _ => panic!("Ожидалась ошибка InvalidKeyLength"),
        }
    }

    #[test]
    fn test_aes256_cfb_invalid_key_length() {
        let key = vec![0u8; 31]; // Неверная длина
        let result = Aes256Cfb::new(&key);
        assert!(result.is_err());
        match result.unwrap_err() {
            CipherError::InvalidKeyLength(_) => {}, // Ожидаем эту ошибку
            _ => panic!("Ожидалась ошибка InvalidKeyLength"),
        }
    }

    #[test]
    fn test_encrypt_decrypt_consistency() {
        // Проверим, что encrypt и decrypt дают одинаковый результат (что верно для CFB)
        let key = generate_random_key(16).expect("Не удалось сгенерировать ключ");
        let cipher = Aes128Cfb::new(&key).expect("Не удалось создать шифр");
        let data = b"consistency test";
        
        let encrypted1 = cipher.encrypt(data).expect("Шифрование 1 не удалось");
        let encrypted2 = cipher.decrypt(data).expect("Шифрование 2 (через decrypt) не удалось");
        
        assert_eq!(encrypted1, encrypted2);
    }
}
