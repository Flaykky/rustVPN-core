use crate::utils::error::VpnError;
use crate::encryption::traits::AeadCipher;
use std::sync::Arc;

/// Factory for creating AEAD ciphers based on method and key
pub struct CipherFactory;

impl CipherFactory {
    /// Creates a cipher based on method and key
    pub fn create_aead(
        method: &str,
        key: &[u8],
    ) -> Result<Box<dyn AeadCipher + Send + Sync>, VpnError> {
        match method.to_lowercase().as_str() {
            "chacha20-ietf-poly1305" => {
                let cipher = crate::encryption::cipher::chacha20::ChaCha20Cipher::new(key)?;
                Ok(Box::new(cipher))
            }
            "aes-256-gcm" => {
                let cipher = crate::encryption::cipher::aes::Aes256Gcm::new(key)?;
                Ok(Box::new(cipher))
            }
            "aes-128-gcm" => {
                let cipher = crate::encryption::cipher::aes::Aes128Gcm::new(key)?;
                Ok(Box::new(cipher))
            }
            "2022-blake3-aes-256-gcm" => {
                let cipher = crate::encryption::cipher::sip022::Sip022Aes256Gcm::new(key)?;
                Ok(Box::new(cipher))
            }
            _ => Err(VpnError::EncryptionError(format!("Unsupported cipher: {}", method))),
        }
    }
}
