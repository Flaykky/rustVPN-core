// src/encryption/cipher/aes/mod.rs

//! Модуль для реализаций шифров AES.
//! Поддерживает различные режимы: GCM (AEAD), CFB (Stream), PMAC-SIV.

// Подмодули
pub mod gcm;
pub mod cfb;
pub mod pmac_siv; // Будет обновлен позже

// Реэкспорт основных типов для удобства
pub use gcm::{Aes128Gcm, Aes192Gcm, Aes256Gcm};
pub use cfb::{
    Aes128Cfb, Aes128Cfb1, Aes128Cfb8,
    Aes256Cfb, Aes256Cfb1, Aes256Cfb8,
};
// pub use pmac_siv::{Aes128PmacSivCipher, Aes256PmacSivCipher}; // Уже было
