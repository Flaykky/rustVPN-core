use openssl::symm::{Cipher, Crypter, Mode};
use crate::utils::common::{encode_base64, decode_base64};
use crate::utils::error::VpnError;
use crate::utils::logging::{log_debug, log_info, log_warn};

pub struct AesGcm {
    cipher: Cipher,
    key: Vec<u8>,
}

impl AesGcm {
    pub fn new(key: &[u8], size: usize) -> Result<Self, VpnError> {
        if key.len() != size {
            return Err(VpnError::EncryptionError(format!("Неверная длина ключа для AES-{}", size * 8)));
        }
        log_info!("Создан шифр AES-{}-GCM", size * 8);
        Ok(Self {
            cipher: Cipher::aes_256_gcm(),
            key: key.to_vec(),
        })
    }

    pub fn encrypt(&self, data: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>, VpnError> {
        log_debug!("Шифрование AES-{}-GCM", self.key.len() * 8);
        let mut crypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(iv))?;
        crypter.set_data_len(data.len())?;
        let mut output = vec![0; data.len() + self.cipher.block_size()];
        let count = crypter.update_aad(aad)?;
        let count = crypter.update(data, &mut output[..])? + count;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }

    pub fn decrypt(&self, data: &[u8], iv: &[u8], aad: &[u8]) -> Result<Vec<u8>, VpnError> {
        log_debug!("Расшифровка AES-{}-GCM", self.key.len() * 8);
        let mut crypter = Crypter::new(self.cipher, Mode::Decrypt, &self.key, Some(iv))?;
        let mut output = vec![0; data.len()];
        let count = crypter.update_aad(aad)?;
        let count = crypter.update(data, &mut output)? + count;
        let final_count = crypter.finalize(&mut output[count..])?;
        output.truncate(count + final_count);
        Ok(output)
    }
}
