pub mod manager;
pub mod store;
pub mod kdf;

pub use manager::KeyManager;
pub use store::{KeyStore, StoredKey};
pub use kdf::{derive_key, generate_random_key};

// Общий тип для ключей
pub type Key = Vec<u8>;
