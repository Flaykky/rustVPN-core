pub mod model;
pub mod parser;

pub use model::{ServerConfig, ProtocolConfig};
pub use parser::parse_config;
