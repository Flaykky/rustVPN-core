use sha2::{Sha256, Digest};
use crate::obfuscation::common::ObfuscationError;

/// XOR-шифрование с ключом
pub fn xor_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// SHA-256 хэш
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Добавляет PKCS7-подобный паддинг
pub fn add_padding(data: &[u8], block_size: usize) -> Vec<u8> {
    let pad_len = block_size - (data.len() % block_size);
    let mut padded = data.to_vec();
    padded.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor() {
        let data = b"hello";
        let key = b"key";
        let encrypted = xor_bytes(data, key);
        let decrypted = xor_bytes(&encrypted, key);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_hash() {
        let hash = hash_data(b"test");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_padding() {
        let data = b"data";
        let padded = add_padding(data, 8);
        assert_eq!(padded.len(), 8);
        assert_eq!(padded[4], 4); // pad byte
    }
}
