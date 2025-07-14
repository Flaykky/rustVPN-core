use crate::utils::error::VpnError;

/// Интерфейс для асинхронного шифрования
pub trait AsyncCipher {
    /// Зашифровывает данные
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, VpnError>;
    
    /// Расшифровывает данные
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, VpnError>;
}

/// Интерфейс для AEAD-шифрования
pub trait AeadCipher {
    /// Зашифровывает данные с nonce
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, VpnError>;
    
    /// Расшифровывает данные с nonce
    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, VpnError>;
}