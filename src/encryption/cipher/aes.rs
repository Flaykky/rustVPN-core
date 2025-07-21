// src/encryption/cipher/aes.rs
//
// Реализация AES-шифрования в двух режимах:
// - AES-256-GCM: AEAD-шифрование с аутентификацией данных
// - AES-256-CTR: потоковое шифрование с счетчиком
//
// Все шифры реализуют интерфейсы `AeadCipher` и `AsyncCipher`.
// Используется `openssl::symm::Crypter` для низкоуровневой реализации.
// Логирование выполняется через `log_info!`, `log_debug!`, `log_warn!`.

use crate::encryption::error::EncryptionError;
use crate::encryption::traits::{AeadCipher, AsyncCipher};
use crate::utils::logging::{log_debug, log_info, log_warn};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::RngCore;
use std::convert::TryInto;
use std::vec::Vec;

/// AES-256-GCM: AEAD-шифрование с аутентификацией данных
pub struct Aes256Gcm {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes256Gcm {
    /// Создает новый экземпляр AES-256-GCM шифратора
    ///
    /// # Аргументы
    ///
    /// * `key` - 32-байтный ключ шифрования (256 бит)
    ///
    /// # Возвращает
    ///
    /// * `Result<Self, EncryptionError>` - шифратор или ошибка валидации ключа
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 32 {
            log_warn!("Неверная длина ключа для AES-256-GCM (ожидается 32 байта)");
            return Err(EncryptionError::InvalidKey);
        }
        log_info!("Создан шифратор AES-256-GCM");
        Ok(Self {
            key: key.to_vec(),
            cipher: Cipher::aes_256_gcm(),
        })
    }

    /// Генерирует случайный 12-байтный nonce для AES-GCM
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован 12-байтный nonce для AES-256-GCM");
        nonce
    }
}

impl AeadCipher for Aes256Gcm {
    /// Шифрует данные с nonce
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-256-GCM (ожидается 12 байт)");
            return Err(EncryptionError::InvalidNonce);
        }

        log_debug!("Шифрование {} байт через AES-256-GCM", data.len());

        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(nonce))?;
        crypter.set_data_len(data.len())?;

        let mut output = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut output[..])?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }

    /// Расшифровывает данные с nonce
    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-256-GCM");
            return Err(EncryptionError::InvalidNonce);
        }

        log_debug!("Расшифровка {} байт через AES-256-GCM", data.len());

        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(nonce))?;
        let mut output = vec![0; data.len()];
        let count = crypter.update(data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }
}

/// AES-256-CTR: потоковое шифрование с использованием счетчика
pub struct Aes256Ctr {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes256Ctr {
    /// Создает новый AES-256-CTR шифратор
    ///
    /// # Аргументы
    ///
    /// * `key` - 32-байтный ключ шифрования (256 бит)
    ///
    /// # Возвращает
    ///
    /// * `Result<Self, EncryptionError>` - шифратор или ошибка валидации
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 32 {
            log_warn!("Неверная длина ключа для AES-256-CTR (ожидается 32 байта)");
            return Err(EncryptionError::InvalidKey);
        }
        log_info!("Создан шифратор AES-256-CTR");
        Ok(Self {
            key: key.to_vec(),
            cipher: Cipher::aes_256_ctr(),
        })
    }

    /// Генерирует случайный 16-байтный блок для CTR (включает IV и счетчик)
    pub fn generate_block() -> Vec<u8> {
        let mut block = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut block);
        log_debug!("Сгенерирован 16-байтный блок для AES-256-CTR");
        block
    }

    /// Генерирует случайный IV (8 байт)
    pub fn generate_iv() -> Vec<u8> {
        let mut iv = vec![0u8; 8];
        rand::thread_rng().fill_bytes(&mut iv);
        log_debug!("Сгенерирован 8-байтный IV для AES-256-CTR");
        iv
    }
}

impl AsyncCipher for Aes256Ctr {
    /// Шифрует данные в режиме CTR
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        log_debug!("Шифрование {} байт через AES-256-CTR", data.len());

        // Генерация IV (8 байт)
        let iv = Self::generate_iv();

        // Создание счетчика (8 байт, начиная с IV)
        let mut counter = [0u8; 16];
        counter[..8].copy_from_slice(&iv);

        // Инициализация криптографии
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(&counter))?;

        let mut output = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);

        // Добавляем IV в начало зашифрованных данных для расшифровки
        let mut result = iv;
        result.extend(output);
        Ok(result)
    }

    /// Расшифровывает данные в режиме CTR
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < 8 {
            log_warn!("Неверная длина данных для AES-256-CTR");
            return Err(EncryptionError::InvalidDataLength(
                "Недостаточно данных для извлечения IV".to_string(),
            ));
        }

        log_debug!("Расшифровка {} байт через AES-256-CTR", data.len());

        // Извлечение IV (первые 8 байт)
        let (iv, cipher_text) = data.split_at(8);

        // Создание счетчика (8 байт IV + 8 байт 0)
        let mut counter = [0u8; 16];
        counter[..8].copy_from_slice(iv);

        // Инициализация криптографии
        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(&counter))?;

        let mut output = vec![0; cipher_text.len() + self.cipher.block_size()];
        let count = crypter.update(cipher_text, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }
}

/// AES-128-GCM: AEAD-шифрование с 16-байтным ключом
pub struct Aes128Gcm {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes128Gcm {
    /// Создает AES-128-GCM шифратор
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 16 {
            log_warn!("Неверная длина ключа для AES-128-GCM");
            return Err(EncryptionError::InvalidKey);
        }
        log_info!("Создан шифратор AES-128-GCM");
        Ok(Self {
            key: key.to_vec(),
            cipher: Cipher::aes_128_gcm(),
        })
    }

    /// Генерирует случайный 12-байтный nonce
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован 12-байтный nonce для AES-128-GCM");
        nonce
    }
}

impl AeadCipher for Aes128Gcm {
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-128-GCM");
            return Err(EncryptionError::InvalidNonce);
        }

        log_debug!("Шифрование {} байт через AES-128-GCM", data.len());

        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(nonce))?;
        crypter.set_data_len(data.len())?;

        let mut output = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut output[..])?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }

    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-128-GCM");
            return Err(EncryptionError::InvalidNonce);
        }

        log_debug!("Расшифровка {} байт через AES-128-GCM", data.len());

        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(nonce))?;
        let mut output = vec![0; data.len()];
        let count = crypter.update(data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }
}

/// AES-128-CTR: потоковое шифрование с 16-байтным ключом
pub struct Aes128Ctr {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes128Ctr {
    /// Создает AES-128-CTR шифратор
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 16 {
            log_warn!("Неверная длина ключа для AES-128-CTR (ожидается 16 байт)");
            return Err(EncryptionError::InvalidKey);
        }
        log_info!("Создан шифратор AES-128-CTR");
        Ok(Self {
            key: key.to_vec(),
            cipher: Cipher::aes_128_ctr(),
        })
    }
}

impl AsyncCipher for Aes128Ctr {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        log_debug!("Шифрование {} байт через AES-128-CTR", data.len());

        // Генерация IV (8 байт)
        let iv = Aes256Ctr::generate_iv();

        // Счетчик: 8 байт IV + 8 байт счетчика
        let mut counter = [0u8; 16];
        counter[..8].copy_from_slice(&iv);

        // Инициализация криптографии
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(&counter))?;

        let mut output = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);

        // Добавляем IV в начало зашифрованных данных
        let mut result = iv.to_vec();
        result.extend(output);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < 8 {
            log_warn!("Неверная длина данных для AES-128-CTR");
            return Err(EncryptionError::InvalidDataLength(
                "Недостаточно данных для извлечения IV".to_string(),
            ));
        }

        log_debug!("Расшифровка {} байт через AES-128-CTR", data.len());

        // Извлечение IV (первые 8 байт)
        let (iv, cipher_text) = data.split_at(8);

        // Счетчик: 8 байт IV + 8 байт 0
        let mut counter = [0u8; 16];
        counter[..8].copy_from_slice(iv);

        // Инициализация криптографии
        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(&counter))?;

        let mut output = vec![0; cipher_text.len() + self.cipher.block_size()];
        let count = crypter.update(cipher_text, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }
}

/// AES-192-CTR: потоковое шифрование с 24-байтным ключом
pub struct Aes192Ctr {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes192Ctr {
    /// Создает AES-192-CTR шифратор
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 24 {
            log_warn!("Неверная длина ключа для AES-192-CTR (ожидается 24 байта)");
            return Err(EncryptionError::InvalidKey);
        }
        log_info!("Создан шифратор AES-192-CTR");
        Ok(Self {
            key: key.to_vec(),
            cipher: Cipher::aes_192_ctr(),
        })
    }
}

impl AsyncCipher for Aes192Ctr {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        log_debug!("Шифрование {} байт через AES-192-CTR", data.len());

        // Генерация IV (8 байт)
        let iv = Aes256Ctr::generate_iv();

        // Счетчик: 8 байт IV + 8 байт счетчика
        let mut counter = [0u8; 16];
        counter[..8].copy_from_slice(&iv);

        // Инициализация криптографии
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(&counter))?;

        let mut output = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);

        // Добавляем IV в начало зашифрованных данных
        let mut result = iv.to_vec();
        result.extend(output);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < 8 {
            log_warn!("Неверная длина данных для AES-192-CTR");
            return Err(EncryptionError::InvalidDataLength(
                "Недостаточно данных для извлечения IV".to_string(),
            ));
        }

        log_debug!("Расшифровка {} байт через AES-192-CTR", data.len());

        // Извлечение IV (первые 8 байт)
        let (iv, cipher_text) = data.split_at(8);

        // Счетчик: 8 байт IV + 8 байт 0
        let mut counter = [0u8; 16];
        counter[..8].copy_from_slice(iv);

        // Инициализация криптографии
        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(&counter))?;

        let mut output = vec![0; cipher_text.len() + self.cipher.block_size()];
        let count = crypter.update(cipher_text, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }
}

/// AES-192-GCM: AEAD-шифрование с 24-байтным ключом
pub struct Aes192Gcm {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes192Gcm {
    /// Создает AES-192-GCM шифратор
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 24 {
            log_warn!("Неверная длина ключа для AES-192-GCM (ожидается 24 байта)");
            return Err(EncryptionError::InvalidKey);
        }
        log_info!("Создан шифратор AES-192-GCM");
        Ok(Self {
            key: key.to_vec(),
            cipher: Cipher::aes_192_gcm(),
        })
    }

    /// Генерирует случайный 12-байтный nonce
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = vec![0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Сгенерирован 12-байтный nonce для AES-192-GCM");
        nonce
    }
}

impl AeadCipher for Aes192Gcm {
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-192-GCM");
            return Err(EncryptionError::InvalidNonce);
        }

        log_debug!("Шифрование {} байт через AES-192-GCM", data.len());

        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(nonce))?;
        crypter.set_data_len(data.len())?;

        let mut output = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }

    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 12 {
            log_warn!("Неверная длина nonce для AES-192-GCM");
            return Err(EncryptionError::InvalidNonce);
        }

        log_debug!("Расшифровка {} байт через AES-192-GCM", data.len());

        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(nonce))?;
        let mut output = vec![0; data.len()];
        let count = crypter.update(data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }
}

/// AES-128-CBC: блочное шифрование с вектором инициализации
pub struct Aes128Cbc {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes128Cbc {
    /// Создает AES-128-CBC шифратор
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 16 {
            log_warn!("Неверная длина ключа для AES-128-CBC (ожидается 16 байт)");
            return Err(EncryptionError::InvalidKey);
        }
        log_info!("Создан шифратор AES-128-CBC");
        Ok(Self {
            key: key.to_vec(),
            cipher: Cipher::aes_128_cbc(),
        })
    }

    /// Генерирует случайный 16-байтный вектор инициализации
    pub fn generate_iv() -> Vec<u8> {
        let mut iv = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut iv);
        log_debug!("Сгенерирован 16-байтный IV для AES-128-CBC");
        iv
    }
}

impl AsyncCipher for Aes128Cbc {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        log_debug!("Шифрование {} байт через AES-128-CBC", data.len());

        // Генерация IV
        let mut iv = Self::generate_iv();

        // Добавляем IV в начало зашифрованных данных
        let mut result = iv.clone();
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(&iv))?;

        // Выравнивание данных под размер блока
        let padded_data = Self::pad_data(data, self.cipher.block_size())?;
        let mut output = vec![0; padded_data.len() + self.cipher.block_size()];
        let count = crypter.update(&padded_data, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);

        result.extend(output);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if data.len() < 16 {
            log_warn!("Неверная длина данных для AES-128-CBC");
            return Err(EncryptionError::InvalidDataLength(
                "Недостаточно данных для извлечения IV".to_string(),
            ));
        }

        log_debug!("Расшифровка {} байт через AES-128-CBC", data.len());

        // Извлечение IV (первые 16 байт)
        let (iv, cipher_text) = data.split_at(16);

        // Инициализация криптографии
        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(iv))?;

        let mut output = vec![0; cipher_text.len() + self.cipher.block_size()];
        let count = crypter.update(cipher_text, &mut output)?;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);

        // Удаление PKCS7 паддинга
        Self::remove_padding(&output, self.cipher.block_size())
    }
}

impl Aes128Cbc {
    /// Добавляет PKCS7 паддинг для AES-CBC
    fn pad_data(data: &[u8], block_size: usize) -> Result<Vec<u8>, EncryptionError> {
        let pad_len = block_size - (data.len() % block_size);
        let mut padded = data.to_vec();
        padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
        Ok(padded)
    }

    /// Удаляет PKCS7 паддинг
    fn remove_padding(data: &[u8], block_size: usize) -> Result<Vec<u8>, EncryptionError> {
        if data.is_empty() {
            return Ok(data.to_vec());
        }

        let pad_len = data[data.len() - 1] as usize;
        if pad_len > block_size || pad_len == 0 {
            return Err(EncryptionError::InvalidDataLength("Неверный паддинг".to_string()));
        }

        let pad = data[data.len() - pad_len..].to_vec();
        if pad.iter().any(|&b| b != pad_len as u8) {
            return Err(EncryptionError::InvalidDataLength("Неверный паддинг".to_string()));
        }

        let mut output = data[..data.len() - pad_len].to_vec();
        output.truncate(Self::find_last_nonzero(&output));
        Ok(output)
    }

    /// Находит последний ненулевой байт (для очистки паддинга)
    fn find_last_nonzero(data: &[u8]) -> usize {
        for i in (0..data.len()).rev() {
            if data[i] != 0 {
                return i + 1;
            }
        }
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::common::generate_random_key;
    use crate::utils::logging::init_logging;

    #[tokio::test]
    async fn test_aes256_gcm() {
        init_logging("info");

        // Генерация ключа
        let key = generate_random_key(32).unwrap();
        let cipher = Aes256Gcm::new(&key).unwrap();
        let nonce = Aes256Gcm::generate_nonce();

        // Шифрование
        let plaintext = b"secret_data_for_aes_256_gcm";
        let encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).unwrap();

        // Расшифровка
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).unwrap();
        assert_eq!(decrypted, plaintext);
        log_info!("AES-256-GCM: шифрование и расшифровка успешны");
    }

    #[tokio::test]
    async fn test_aes256_ctr() {
        init_logging("info");

        // Генерация ключа
        let key = generate_random_key(32).unwrap();
        let cipher = Aes256Ctr::new(&key).unwrap();

        // Шифрование
        let plaintext = b"secret_data_for_aes_256_ctr";
        let encrypted = cipher.encrypt(plaintext).unwrap();

        // Расшифровка
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
        log_info!("AES-256-CTR: шифрование и расшифровка успешны");
    }

    #[tokio::test]
    async fn test_aes128_cbc() {
        init_logging("info");

        // Генерация ключа
        let key = generate_random_key(16).unwrap();
        let cipher = Aes128Cbc::new(&key).unwrap();

        // Шифрование
        let plaintext = b"secret_data_for_aes_128_cbc";
        let encrypted = cipher.encrypt(plaintext).unwrap();

        // Расшифровка
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
        log_info!("AES-128-CBC: шифрование и расшифровка успешны");
    }

    #[tokio::test]
    async fn test_invalid_key() {
        let key = vec![0u8; 16]; // 16 байт — для AES-256-GCM это недостаточно
        let result = Aes256Gcm::new(&key);
        assert!(result.is_err());
        log_debug!("Тест: ошибка при использовании неверного ключа — успешна");
    }

    #[tokio::test]
    async fn test_invalid_nonce() {
        let key = generate_random_key(32).unwrap();
        let cipher = Aes256Gcm::new(&key).unwrap();

        let bad_nonce = vec![0u8; 8]; // 8 байт — недостаточно для AES-GCM
        let result = cipher.encrypt_with_nonce(b"test", &bad_nonce);
        assert!(result.is_err());
        log_debug!("Тест: ошибка при использовании неверного nonce — успешна");
    }
}
