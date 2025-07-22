use crate::utils::error::VpnError;

/// Common interface for AEAD encryption
pub trait AeadCipher: Send + Sync {
    /// Encrypts data with a nonce
    fn encrypt_with_nonce(
        &self,
        data: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, VpnError>;

    /// Decrypts data with a nonce
    fn decrypt_with_nonce(
        &self,
        data: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, VpnError>;

    /// Returns cipher name
    fn cipher_name(&self) -> &'static str;
}

/// Stream cipher interface for legacy ciphers
pub trait StreamCipher: Send + Sync {
    /// Encrypts data
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, VpnError>;

    /// Decrypts data
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, VpnError>;
}

/// Interface for key derivation
pub trait KeyDerivable: Send + Sync {
    /// Derives a key from a password
    fn derive_key(
        &self,
        password: &str,
        salt: &[u8],
        method: &str,
    ) -> Result<Vec<u8>, VpnError>;

    /// Generates a random key
    fn generate_random_key(&self, method: &str) -> Result<Vec<u8>, VpnError>;
}

/// Interface for cipher factories
pub trait CipherFactory {
    /// Creates an AEAD cipher
    fn create_aead(
        &self,
        method: &str,
        key: &[u8],
    ) -> Result<Box<dyn AeadCipher + Send + Sync>, VpnError>;

    /// Creates a stream cipher
    fn create_stream(
        &self,
        method: &str,
        key: &[u8],
    ) -> Result<Box<dyn StreamCipher + Send + Sync>, VpnError>;
}
