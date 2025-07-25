pub mod dpi;
pub mod protocol;
pub mod timing;
pub mod preset;
pub mod plugin;
pub mod utils;
pub mod common;

// Экспорт основных типов
pub use common::{
    ObfuscationType, 
    DpiBypassLevel, 
    ObfuscationPreset, 
    ObfuscationError
};

// Экспорт модулей
pub use dpi::fragment::PacketFragmenter;
pub use dpi::masquerade::ProtocolMasquerader;
pub use protocol::tunnel::TunnelObfuscator;
pub use timing::delay::DelayObfuscator;
pub use preset::basic::BasicPreset;
