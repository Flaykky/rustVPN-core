pub mod http;
pub mod https;
pub mod socks4;
pub mod socks5;

pub use http::HttpProxy;
pub use https::HttpsProxy;
pub use socks4::Socks4Proxy;
pub use socks5::Socks5Proxy;