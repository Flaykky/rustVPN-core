// src/encryption/cipher.rs

use crate::utils::error::VpnError;
use crate::encryption::traits::{AeadCipher, StreamCipher};
use crate::encryption::error::CipherError;
use std::sync::Arc;

/// Factory for creating ciphers based on method and key
pub struct CipherFactory;

impl CipherFactory {
    /// Creates an AEAD cipher based on method and key
    pub fn create_aead(
        method: &str,
        key: &[u8],
    ) -> Result<Box<dyn AeadCipher + Send + Sync>, VpnError> {
        match method.to_lowercase().as_str() {
            // AES-GCM
            "aes-128-gcm" => {
                let cipher = crate::encryption::cipher::aes::gcm::Aes128Gcm::new(key)?;
                Ok(Box::new(cipher))
            }
            "aes-192-gcm" => {
                let cipher = crate::encryption::cipher::aes::gcm::Aes192Gcm::new(key)?;
                Ok(Box::new(cipher))
            }
            "aes-256-gcm" => {
                let cipher = crate::encryption::cipher::aes::gcm::Aes256Gcm::new(key)?;
                Ok(Box::new(cipher))
            }
            // ChaCha20
            "chacha20-ietf-poly1305" => {
                // Пока используем старую реализацию, позже заменим
                let cipher = crate::encryption::cipher::chacha20::ChaCha20Cipher::new(key)?;
                Ok(Box::new(cipher))
            }
            // Другие AEAD шифры
            "2022-blake3-aes-256-gcm" => {
                // TODO: Реализовать Sip022Aes256Gcm
                Err(VpnError::EncryptionError("SIP022 шифры пока не реализованы".to_string()))
            }
            // XCChaCha20-Poly1305
            "xchacha20-ietf-poly1305" => {
                // TODO: Реализовать XCChaCha20-Poly1305
                Err(VpnError::EncryptionError("XCChaCha20-Poly1305 пока не реализован".to_string()))
            }
            _ => {
                log::warn!("Неподдерживаемый AEAD шифр: {}", method);
                Err(CipherError::UnsupportedCipher(method.to_string()).into())
            }
        }
    }

    /// Creates a stream cipher based on method and key
    pub fn create_stream(
        method: &str,
        key: &[u8],
    ) -> Result<Box<dyn StreamCipher + Send + Sync>, VpnError> {
        match method.to_lowercase().as_str() {
            // AES-CFB
            "aes-128-cfb" | "aes-128-cfb128" => {
                // TODO: Реализовать Aes128Cfb
                Err(VpnError::EncryptionError("AES-CFB шифры пока не реализованы".to_string()))
            }
            "aes-192-cfb" | "aes-192-cfb128" => {
                // TODO: Реализовать Aes192Cfb
                Err(VpnError::EncryptionError("AES-CFB шифры пока не реализованы".to_string()))
            }
            "aes-256-cfb" | "aes-256-cfb128" => {
                // TODO: Реализовать Aes256Cfb
                Err(VpnError::EncryptionError("AES-CFB шифры пока не реализованы".to_string()))
            }
            // AES-CFB с другими размерами сдвигов
            "aes-128-cfb1" | "aes-128-cfb8" => {
                Err(VpnError::EncryptionError("AES-CFB1/8 шифры не рекомендуются и не реализованы".to_string()))
            }
            "aes-192-cfb1" | "aes-192-cfb8" => {
                Err(VpnError::EncryptionError("AES-CFB1/8 шифры не рекомендуются и не реализованы".to_string()))
            }
            "aes-256-cfb1" | "aes-256-cfb8" => {
                Err(VpnError::EncryptionError("AES-CFB1/8 шифры не рекомендуются и не реализованы".to_string()))
            }
            // ChaCha20 (без аутентификации)
            "chacha20-ietf" => {
                // TODO: Реализовать ChaCha20Stream
                Err(VpnError::EncryptionError("ChaCha20 stream cipher пока не реализован".to_string()))
            }
            // RC4
            "rc4" => {
                // TODO: Реализовать Rc4Stream
                Err(VpnError::EncryptionError("RC4 stream cipher пока не реализован".to_string()))
            }
            "rc4-md5" => {
                // TODO: Реализовать Rc4Md5Stream
                Err(VpnError::EncryptionError("RC4-MD5 stream cipher пока не реализован".to_string()))
            }
            // Salsa20
            "salsa20" => {
                // TODO: Реализовать Salsa20Stream
                Err(VpnError::EncryptionError("Salsa20 stream cipher пока не реализован".to_string()))
            }
            _ => {
                log::warn!("Неподдерживаемый stream шифр: {}", method);
                Err(CipherError::UnsupportedCipher(method.to_string()).into())
            }
        }
    }
}
