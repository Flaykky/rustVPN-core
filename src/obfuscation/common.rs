use thiserror::Error;

/// Типы обфускации
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObfuscationType {
    DpiFragment,
    DpiMasquerade,
    DpiProtocolShift,
    DpiTiming,
    ProtocolTunnel,
    ProtocolEncryption,
    ProtocolHeader,
    TimingDelay,
    TimingJitter,
    Plugin(String), // имя плагина
}

/// Уровень обхода DPI
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpiBypassLevel {
    None,
    Basic,     // Простое маскирование
    Medium,    // Fragmentation + timing
    Aggressive, // Все методы DPI
    Custom,    // Пользовательский набор
}

/// Типы готовых профилей
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObfuscationPreset {
    Basic,      // HTTPS spoof
    Advanced,   // DPI bypass + tunnel
    Stealth,    // Full obfuscation
    Custom,     // Из конфига
}

/// Ошибки обфускации
#[derive(Error, Debug)]
pub enum ObfuscationError {
    #[error("Неверный тип обфускации: {0}")]
    InvalidType(String),
    
    #[error("Ошибка фрагментации пакета")]
    FragmentationFailed,
    
    #[error("Ошибка маскировки протокола")]
    MasqueradeFailed,
    
    #[error("Ошибка туннелирования")]
    TunnelFailed,
    
    #[error("Ошибка шифрования")]
    EncryptionFailed,
    
    #[error("Ошибка плагина: {0}")]
    PluginError(String),
    
    #[error("Неверная конфигурация: {0}")]
    ConfigError(String),
    
    #[error("Не реализовано")]
    NotImplemented,
}

impl ObfuscationError {
    pub fn invalid_type(t: &str) -> Self {
        Self::InvalidType(t.to_string())
    }
    
    pub fn plugin_error(e: &str) -> Self {
        Self::PluginError(e.to_string())
    }
    
    pub fn config_error(e: &str) -> Self {
        Self::ConfigError(e.to_string())
    }
}
