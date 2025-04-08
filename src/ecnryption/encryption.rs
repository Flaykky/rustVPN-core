// src/encryption/encryption.rs
use openssl::{
    symm::{Cipher, Crypter, Mode},
    rand::rand_bytes,
    error::ErrorStack,
};
use zeroize::Zeroize;
use std::{
    sync::{Arc, Mutex},
    mem::ManuallyDrop,
};
use anyhow::{Result, anyhow};
use lazy_static::lazy_static;

lazy_static! {
    static ref ENCRYPTION_CONTEXT: Mutex<Option<EncryptionContext>> = Mutex::new(None);
}

pub struct EncryptionContext {
    key: Vec<u8>,
    iv: Vec<u8>,
    cipher_type: CipherType,
    cipher: Cipher,
}



use openssl::{
    symm::{Cipher, Crypter, Mode},
    rand::rand_bytes,
};



#[derive(Clone, Copy)]
pub enum CipherType {
    AES256GCM,
    ChaCha20Poly1305,
}

pub struct EncryptionContext {
    key: [u8; 32],
    iv: [u8; 16],
    cipher: Cipher,
}

impl EncryptionContext {
    pub fn new() -> Result<Self> {
        let mut key = [0u8; 32];
        let mut iv = [0u8; 16];
        rand_bytes(&mut key)?;
        rand_bytes(&mut iv)?;
        
        Ok(Self {
            key,
            iv,
            cipher: Cipher::aes_256_gcm(),
        })
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut crypter = Crypter::new(
            self.cipher,
            Mode::Encrypt,
            &self.key,
            Some(&self.iv),
        )?;
        
        let mut ciphertext = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut ciphertext)?;
        ciphertext.truncate(count + crypter.finalize(&mut ciphertext[count..])?);
        Ok(ciphertext)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut crypter = Crypter::new(
            self.cipher,
            Mode::Decrypt,
            &self.key,
            Some(&self.iv),
        )?;
        
        let mut plaintext = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut plaintext)?;
        plaintext.truncate(count + crypter.finalize(&mut plaintext[count..])?);
        Ok(plaintext)
    }

    pub fn rotate_keys(&mut self) -> Result<()> {
        rand_bytes(&mut self.key)?;
        rand_bytes(&mut self.iv)?;
        Ok(())
    }
}

impl Drop for EncryptionContext {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

pub fn initialize_encryption() -> Result<()> {
    let mut ctx = ENCRYPTION_CONTEXT.lock()
        .map_err(|_| anyhow!("Failed to acquire encryption context"))?;
    
    *ctx = Some(EncryptionContext::new()?);
    Ok(())
}

pub fn encrypt_data(data: &[u8]) -> Result<Vec<u8>> {
    let ctx = ENCRYPTION_CONTEXT.lock()
        .map_err(|_| anyhow!("Failed to acquire encryption context"))?
        .as_ref()
        .ok_or(anyhow!("Encryption not initialized"))?;
    
    ctx.encrypt(data)
}

pub fn decrypt_data(data: &[u8]) -> Result<Vec<u8>> {
    let ctx = ENCRYPTION_CONTEXT.lock()
        .map_err(|_| anyhow!("Failed to acquire encryption context"))?
        .as_ref()
        .ok_or(anyhow!("Encryption not initialized"))?;
    
    ctx.decrypt(data)
}

pub fn rotate_encryption_keys() -> Result<()> {
    let mut ctx = ENCRYPTION_CONTEXT.lock()
        .map_err(|_| anyhow!("Failed to acquire encryption context"))?
        .as_mut()
        .ok_or(anyhow!("Encryption not initialized"))?;
    
    ctx.rotate_keys()
}

pub fn secure_clear_memory() {
    if let Ok(mut ctx) = ENCRYPTION_CONTEXT.lock() {
        ctx.take().map(|c| {
            let mut c = ManuallyDrop::new(c);
            c.key.zeroize();
            c.iv.zeroize();
        });
    }
}




impl EncryptionContext {
    fn new(cipher_type: CipherType) -> Result<Self> {
        let (key_len, iv_len, cipher) = match cipher_type {
            CipherType::AES256GCM => (32, 12, Cipher::aes_256_gcm()),
            CipherType::ChaCha20Poly1305 => (32, 12, Cipher::chacha20_poly1305()),
        };

        let mut key = vec![0u8; key_len];
        let mut iv = vec![0u8; iv_len];
        rand_bytes(&mut key)?;
        rand_bytes(&mut iv)?;

        Ok(Self {
            key,
            iv,
            cipher_type,
            cipher,
        })
    }

    pub fn get_key(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn get_iv(&self) -> Vec<u8> {
        self.iv.clone()
    }

    pub fn set_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != self.key.len() {
            anyhow::bail!("Invalid key length");
        }
        self.key.copy_from_slice(key);
        Ok(())
    }

    pub fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        if iv.len() != self.iv.len() {
            anyhow::bail!("Invalid IV length");
        }
        self.iv.copy_from_slice(iv);
        Ok(())
    }

    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut crypter = Crypter::new(
            self.cipher,
            Mode::Encrypt,
            &self.key,
            Some(&self.iv),
        )?;
        
        let mut ciphertext = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut ciphertext)?;
        ciphertext.truncate(count + crypter.finalize(&mut ciphertext[count..])?);
        Ok(ciphertext)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut crypter = Crypter::new(
            self.cipher,
            Mode::Decrypt,
            &self.key,
            Some(&self.iv),
        )?;
        
        let mut plaintext = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update(data, &mut plaintext)?;
        plaintext.truncate(count + crypter.finalize(&mut plaintext[count..])?);
        Ok(plaintext)
    }
}

impl Drop for EncryptionContext {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

pub fn initialize_encryption(cipher_type: CipherType) -> Result<()> {
    let mut ctx = ENCRYPTION_CONTEXT.lock()
        .map_err(|_| anyhow!("Failed to acquire encryption context"))?;
    
    *ctx = Some(EncryptionContext::new(cipher_type)?);
    Ok(())
}

pub fn get_encryption_key() -> Option<Vec<u8>> {
    ENCRYPTION_CONTEXT.lock()
        .ok()
        .and_then(|ctx| ctx.as_ref().map(|c| c.get_key()))
}

pub fn get_encryption_iv() -> Option<Vec<u8>> {
    ENCRYPTION_CONTEXT.lock()
        .ok()
        .and_then(|ctx| ctx.as_ref().map(|c| c.get_iv()))
}

pub fn set_encryption_key(key: &[u8]) -> Result<()> {
    let mut ctx = ENCRYPTION_CONTEXT.lock()?;
    if let Some(ref mut c) = *ctx {
        c.set_key(key)
    } else {
        Err(anyhow!("Encryption not initialized"))
    }
}

pub fn set_encryption_iv(iv: &[u8]) -> Result<()> {
    let mut ctx = ENCRYPTION_CONTEXT.lock()?;
    if let Some(ref mut c) = *ctx {
        c.set_iv(iv)
    } else {
        Err(anyhow!("Encryption not initialized"))
    }
}

pub fn is_encryption_initialized() -> bool {
    ENCRYPTION_CONTEXT.lock()
        .map(|ctx| ctx.is_some())
        .unwrap_or(false)
}

pub fn rotate_encryption_keys() -> Result<()> {
    let mut ctx = ENCRYPTION_CONTEXT.lock()?;
    if let Some(ref mut c) = *ctx {
        let new_key = {
            let mut key = vec![0u8; c.key.len()];
            rand_bytes(&mut key)?;
            key
        };
        let new_iv = {
            let mut iv = vec![0u8; c.iv.len()];
            rand_bytes(&mut iv)?;
            iv
        };
        c.key.zeroize();
        c.iv.zeroize();
        c.key = new_key;
        c.iv = new_iv;
        Ok(())
    } else {
        Err(anyhow!("Encryption not initialized"))
    }
}

pub fn secure_clear_memory() {
    if let Ok(mut ctx) = ENCRYPTION_CONTEXT.lock() {
        ctx.take().map(|c| {
            let mut c = ManuallyDrop::new(c);
            c.key.zeroize();
            c.iv.zeroize();
        });
    }
}
