use thiserror::Error;

/// Specific errors for cryptographic operations
#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Invalid method: {0}")]
    InvalidMethod(String),
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(String),
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),
    #[error("Invalid data length: {0}")]
    InvalidDataLength(String),
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    #[error("Unsupported cipher: {0}")]
    UnsupportedCipher(String),
    #[error("Cipher not initialized")]
    CipherNotInitialized,
    #[error("KDF not supported: {0}")]
    KdfNotSupported(String),
    #[error("Key expired")]
    KeyExpired,
    #[error("Key not found")]
    KeyNotFound,
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),
    #[error("Invalid key size: {0}")]
    InvalidKeySize(usize),
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherError::InvalidMethod(m) => write!(f, "Invalid cipher method: {}", m),
            CipherError::InvalidKeyLength(m) => write!(f, "Invalid key length: {}", m),
            CipherError::InvalidNonce(m) => write!(f, "Invalid nonce: {}", m),
            CipherError::InvalidDataLength(m) => write!(f, "Invalid data length: {}", m),
            CipherError::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            CipherError::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            CipherError::KeyDerivationFailed(e) => write!(f, "Key derivation failed: {}", e),
            CipherError::UnsupportedCipher(m) => write!(f, "Unsupported cipher: {}", m),
            CipherError::CipherNotInitialized => write!(f, "Cipher not initialized"),
            CipherError::KeyExpired => write!(f, "Key expired"),
            CipherError::KeyNotFound => write!(f, "Key not found"),
            CipherError::KdfNotSupported(kdf) => write!(f, "KDF not supported: {}", kdf),
            CipherError::InvalidKeyFormat(m) => write!(f, "Invalid key format: {}", m),
            CipherError::InvalidKeySize(size) => write!(f, "Invalid key size: {} bytes", size),
        }
    }
}
