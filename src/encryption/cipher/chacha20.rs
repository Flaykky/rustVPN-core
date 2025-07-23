// src/encryption/cipher/chacha20.rs
//
// Implementation of ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD ciphers.
// These are modern, fast, and secure authenticated encryption algorithms.
// 
// Supported ciphers:
// - ChaCha20Poly1305 (12-byte nonce)
// - XChaCha20Poly1305 (24-byte nonce)
//
// All ciphers implement the `AeadCipher` trait for encrypt/decrypt with nonce.
// Uses `chacha20poly1305` crate for low-level cryptography.
// Logging via `log_info!`, `log_debug!`, `log_warn!`.

use crate::encryption::error::EncryptionError;
use crate::encryption::traits::AeadCipher;
use crate::utils::logging::{log_debug, log_info, log_warn};
use chacha20poly1305::{
    aead::{Aead, NewAead},
    ChaCha20Poly1305, XChaCha20Poly1305, KeyInit, Key, Nonce,
};
use rand::RngCore;
use std::vec::Vec;

/// ChaCha20-Poly1305 AEAD cipher (12-byte nonce)
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
    key: Key,
}

impl ChaCha20Poly1305Cipher {
    /// Creates a new ChaCha20-Poly1305 cipher with a 32-byte key
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte secret key (256 bits)
    ///
    /// # Returns
    ///
    /// * `Result<Self, EncryptionError>` - cipher instance or error
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 32 {
            log_warn!("Invalid key length for ChaCha20-Poly1305 (expected 32 bytes, got {})", key.len());
            return Err(EncryptionError::InvalidKeyLength(format!(
                "Expected 32 bytes, got {}",
                key.len()
            )));
        }
        log_info!("Initialized ChaCha20-Poly1305 cipher");
        let mut key_buf = Key::default();
        key_buf.copy_from_slice(key);
        Ok(Self {
            cipher: ChaCha20Poly1305::new(&key_buf),
            key: key_buf,
        })
    }

    /// Generates a random 12-byte nonce for ChaCha20-Poly1305
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Generated 12-byte nonce for ChaCha20-Poly1305");
        nonce.to_vec()
    }
}

impl AeadCipher for ChaCha20Poly1305Cipher {
    /// Encrypts data with a 12-byte nonce
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 12 {
            log_warn!("Invalid nonce length for ChaCha20-Poly1305 (expected 12 bytes, got {})", nonce.len());
            return Err(EncryptionError::InvalidNonce(format!(
                "Expected 12 bytes, got {}",
                nonce.len()
            )));
        }
        let nonce = Nonce::from_slice(nonce);
        let encrypted = self.cipher.encrypt(nonce, data).map_err(|e| {
            log_warn!("ChaCha20-Poly1305 encryption failed: {}", e);
            EncryptionError::EncryptionFailed(e.to_string())
        })?;
        log_debug!("ChaCha20-Poly1305: encrypted {} bytes", data.len());
        Ok(encrypted)
    }

    /// Decrypts data with a 12-byte nonce
    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 12 {
            log_warn!("Invalid nonce length for ChaCha20-Poly1305 (expected 12 bytes, got {})", nonce.len());
            return Err(EncryptionError::InvalidNonce(format!(
                "Expected 12 bytes, got {}",
                nonce.len()
            )));
        }
        let nonce = Nonce::from_slice(nonce);
        let decrypted = self.cipher.decrypt(nonce, data).map_err(|e| {
            log_warn!("ChaCha20-Poly1305 decryption failed: {}", e);
            EncryptionError::DecryptionFailed(e.to_string())
        })?;
        log_debug!("ChaCha20-Poly1305: decrypted {} bytes", decrypted.len());
        Ok(decrypted)
    }

    /// Returns cipher name
    fn cipher_name(&self) -> &'static str {
        "ChaCha20-Poly1305"
    }
}

/// XChaCha20-Poly1305 AEAD cipher (24-byte nonce)
pub struct XChaCha20Poly1305Cipher {
    cipher: XChaCha20Poly1305,
    key: Key,
}

impl XChaCha20Poly1305Cipher {
    /// Creates a new XChaCha20-Poly1305 cipher with a 32-byte key
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte secret key (256 bits)
    ///
    /// # Returns
    ///
    /// * `Result<Self, EncryptionError>` - cipher instance or error
    pub fn new(key: &[u8]) -> Result<Self, EncryptionError> {
        if key.len() != 32 {
            log_warn!("Invalid key length for XChaCha20-Poly1305 (expected 32 bytes, got {})", key.len());
            return Err(EncryptionError::InvalidKeyLength(format!(
                "Expected 32 bytes, got {}",
                key.len()
            )));
        }
        log_info!("Initialized XChaCha20-Poly1305 cipher");
        let mut key_buf = Key::default();
        key_buf.copy_from_slice(key);
        Ok(Self {
            cipher: XChaCha20Poly1305::new(&key_buf),
            key: key_buf,
        })
    }

    /// Generates a random 24-byte nonce for XChaCha20-Poly1305
    pub fn generate_nonce() -> Vec<u8> {
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        log_debug!("Generated 24-byte nonce for XChaCha20-Poly1305");
        nonce.to_vec()
    }
}

impl AeadCipher for XChaCha20Poly1305Cipher {
    /// Encrypts data with a 24-byte nonce
    fn encrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 24 {
            log_warn!("Invalid nonce length for XChaCha20-Poly1305 (expected 24 bytes, got {})", nonce.len());
            return Err(EncryptionError::InvalidNonce(format!(
                "Expected 24 bytes, got {}",
                nonce.len()
            )));
        }
        let nonce = chacha20poly1305::XNonce::from_slice(nonce);
        let encrypted = self.cipher.encrypt(nonce, data).map_err(|e| {
            log_warn!("XChaCha20-Poly1305 encryption failed: {}", e);
            EncryptionError::EncryptionFailed(e.to_string())
        })?;
        log_debug!("XChaCha20-Poly1305: encrypted {} bytes", data.len());
        Ok(encrypted)
    }

    /// Decrypts data with a 24-byte nonce
    fn decrypt_with_nonce(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        if nonce.len() != 24 {
            log_warn!("Invalid nonce length for XChaCha20-Poly1305 (expected 24 bytes, got {})", nonce.len());
            return Err(EncryptionError::InvalidNonce(format!(
                "Expected 24 bytes, got {}",
                nonce.len()
            )));
        }
        let nonce = chacha20poly1305::XNonce::from_slice(nonce);
        let decrypted = self.cipher.decrypt(nonce, data).map_err(|e| {
            log_warn!("XChaCha20-Poly1305 decryption failed: {}", e);
            EncryptionError::DecryptionFailed(e.to_string())
        })?;
        log_debug!("XChaCha20-Poly1305: decrypted {} bytes", decrypted.len());
        Ok(decrypted)
    }

    /// Returns cipher name
    fn cipher_name(&self) -> &'static str {
        "XChaCha20-Poly1305"
    }
}

/// Creates a ChaCha20 cipher based on method and key
pub fn create_chacha20_cipher(
    method: &str,
    key: &[u8],
) -> Result<Box<dyn AeadCipher + Send + Sync>, EncryptionError> {
    match method.to_lowercase().as_str() {
        "chacha20-ietf-poly1305" => {
            let cipher = ChaCha20Poly1305Cipher::new(key)?;
            Ok(Box::new(cipher))
        }
        "xchacha20-ietf-poly1305" => {
            let cipher = XChaCha20Poly1305Cipher::new(key)?;
            Ok(Box::new(cipher))
        }
        _ => {
            log_warn!("Unsupported ChaCha20 cipher method: {}", method);
            Err(EncryptionError::UnsupportedCipher(method.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::common::generate_random_key;

    #[tokio::test]
    async fn test_chacha20_poly1305_encrypt_decrypt() {
        let key = generate_random_key(32).unwrap();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();

        let plaintext = b"Hello, ChaCha20-Poly1305!";
        let encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).unwrap();
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
        log_info!("ChaCha20-Poly1305: encrypt/decrypt test passed");
    }

    #[tokio::test]
    async fn test_xchacha20_poly1305_encrypt_decrypt() {
        let key = generate_random_key(32).unwrap();
        let cipher = XChaCha20Poly1305Cipher::new(&key).unwrap();
        let nonce = XChaCha20Poly1305Cipher::generate_nonce();

        let plaintext = b"Hello, XChaCha20-Poly1305!";
        let encrypted = cipher.encrypt_with_nonce(plaintext, &nonce).unwrap();
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).unwrap();

        assert_eq!(decrypted, plaintext);
        log_info!("XChaCha20-Poly1305: encrypt/decrypt test passed");
    }

    #[tokio::test]
    async fn test_invalid_nonce_lengths() {
        let key = generate_random_key(32).unwrap();
        let cipher = ChaCha20Poly1305Cipher::new(&key).unwrap();

        let plaintext = b"test";
        let bad_nonce = vec![0u8; 8]; // Too short

        assert!(cipher.encrypt_with_nonce(plaintext, &bad_nonce).is_err());
        log_debug!("ChaCha20-Poly1305: invalid nonce length test passed");
    }

    #[tokio::test]
    async fn test_create_chacha20_cipher() {
        let key = generate_random_key(32).unwrap();
        let cipher = create_chacha20_cipher("chacha20-ietf-poly1305", &key).unwrap();
        let nonce = ChaCha20Poly1305Cipher::generate_nonce();
        let encrypted = cipher.encrypt_with_nonce(b"test", &nonce).unwrap();
        let decrypted = cipher.decrypt_with_nonce(&encrypted, &nonce).unwrap();
        assert_eq!(decrypted, b"test");
        log_info!("create_chacha20_cipher: cipher created and working");
    }
}
