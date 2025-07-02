use crate::utils::error::VpnError;
use crate::config::model::ServerConfig;
use std::path::PathBuf;
use std::sync::Arc;
use std::collections::HashMap;
use libloading::{Library, Symbol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Интерфейс для динамических плагинов
pub trait PluginProtocol: Send + Sync {
    fn connect(&self) -> Pin<Box<dyn Future<Output = Result<Box<dyn PluginConnection>, VpnError>> + Send + '_>>;
    fn protocol_type(&self) -> String;
}

pub trait PluginConnection: Send + Sync {
    fn send_packet(&mut self, packet: &[u8]) -> Pin<Box<dyn Future<Output = Result<(), VpnError>> + Send + '_>>;
    fn receive_packet(&mut self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, VpnError>> + Send + '_>>;
    fn close(&mut self) -> Pin<Box<dyn Future<Output = Result<(), VpnError>> + Send + '_>>;
}

// Загрузчик плагинов
pub struct PluginLoader {
    plugins: HashMap<String, Arc<Library>>,
}

impl PluginLoader {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    // Загружает плагин из .so/.dll файла
    pub fn load_plugin(&mut self, name: &str, path: &str) -> Result<(), VpnError> {
        unsafe {
            let lib = Library::new(path).map_err(|e| {
                VpnError::PluginError(format!("Не удалось загрузить плагин {}: {}", name, e))
            })?;
            self.plugins.insert(name.to_string(), Arc::new(lib));
            Ok(())
        }
    }

    // Создает протокол из плагина
    pub fn create_protocol(&self, config: &ServerConfig) -> Result<Box<dyn PluginProtocol>, VpnError> {
        let plugin_name = config.config.get("plugin").and_then(|v| v.as_str())
            .ok_or_else(|| VpnError::ConfigError("Отсутствует имя плагина в конфиге".to_string()))?;

        let lib = self.plugins.get(plugin_name)
            .ok_or_else(|| VpnError::PluginError(format!("Плагин {} не загружен", plugin_name)))?;

        unsafe {
            let symbol: Symbol<fn(&ServerConfig) -> Box<dyn PluginProtocol>> = lib.get(b"create_protocol")
                .map_err(|e| VpnError::PluginError(format!("Ошибка получения символа: {}", e)))?;
            
            Ok(symbol(config))
        }
    }
}

// Пример реализации плагина (для тестов)
pub struct DummyPlugin;

impl PluginProtocol for DummyPlugin {
    fn connect(&self) -> Pin<Box<dyn Future<Output = Result<Box<dyn PluginConnection>, VpnError>> + Send + '_>> {
        Box::pin(async move {
            Ok(Box::new(DummyConnection))
        })
    }

    fn protocol_type(&self) -> String {
        "dummy".to_string()
    }
}

pub struct DummyConnection;

#[async_trait::async_trait]
impl PluginConnection for DummyConnection {
    async fn send_packet(&mut self, _packet: &[u8]) -> Result<(), VpnError> {
        Ok(())
    }

    async fn receive_packet(&mut self) -> Result<Vec<u8>, VpnError> {
        Ok(vec![0])
    }

    async fn close(&mut self) -> Result<(), VpnError> {
        Ok(())
    }
}
