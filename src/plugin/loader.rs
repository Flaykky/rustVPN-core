//! Загрузчик внешних плагинов.
//! Поддерживает загрузку динамических библиотек и управление плагинами.

use crate::utils::logging::{log_debug, log_info, log_warn, log_error};
use crate::utils::error::VpnError;
use libloading::{Library, Symbol};
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;

/// Типы плагинов
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PluginType {
    Protocol,
    Obfuscation,
    Encryption,
    Proxy,
    Transport,
    Other,
}

/// Категории плагинов для более детальной классификации
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PluginCategory {
    WireGuard,
    Shadowsocks,
    OpenVpn,
    HttpProxy,
    SocksProxy,
    DpiBypass,
    Tunnel,
    AeadCipher,
    StreamCipher,
    Custom(String),
}

/// Метаданные плагина
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub name: String,
    pub version: String,
    pub description: String,
    pub plugin_type: PluginType,
    pub category: PluginCategory,
    pub author: Option<String>,
    pub license: Option<String>,
    pub dependencies: Vec<String>,
}

/// Трейт для всех плагинов
pub trait Plugin: Send + Sync {
    /// Возвращает метаданные плагина
    fn metadata(&self) -> &PluginMetadata;
    
    /// Инициализирует плагин
    fn initialize(&mut self) -> Result<(), PluginError>;
    
    /// Освобождает ресурсы плагина
    fn shutdown(&mut self) -> Result<(), PluginError>;
}

/// Ошибки системы плагинов
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("Ошибка загрузки библиотеки: {0}")]
    LibraryLoadError(String),
    
    #[error("Ошибка получения символа: {0}")]
    SymbolError(String),
    
    #[error("Плагин не найден: {0}")]
    PluginNotFound(String),
    
    #[error("Несовместимая версия API: {0}")]
    VersionMismatch(String),
    
    #[error("Ошибка инициализации плагина: {0}")]
    InitializationError(String),
    
    #[error("Плагин уже загружен: {0}")]
    PluginAlreadyLoaded(String),
    
    #[error("Недопустимый путь к плагину: {0}")]
    InvalidPath(String),
}

impl From<PluginError> for VpnError {
    fn from(error: PluginError) -> Self {
        VpnError::PluginError(error.to_string())
    }
}

/// Загрузчик плагинов
pub struct PluginLoader {
    /// Загруженные плагины: (имя, (библиотека, экземпляр плагина))
    plugins: Arc<RwLock<HashMap<String, (Arc<Library>, Box<dyn Plugin>)>>>,
    /// Каталоги для поиска плагинов
    plugin_paths: Vec<PathBuf>,
}

impl PluginLoader {
    /// Создает новый загрузчик плагинов
    pub fn new() -> Self {
        log_info!("Инициализация загрузчика плагинов");
        Self {
            plugins: Arc::new(RwLock::new(HashMap::new())),
            plugin_paths: vec![
                PathBuf::from("./plugins"),
                PathBuf::from("/usr/lib/vpn-plugins"),
                PathBuf::from("/usr/local/lib/vpn-plugins"),
            ],
        }
    }

    /// Добавляет каталог для поиска плагинов
    pub fn add_plugin_path<P: AsRef<Path>>(&mut self, path: P) {
        log_debug!("Добавление каталога плагинов: {:?}", path.as_ref());
        self.plugin_paths.push(path.as_ref().to_path_buf());
    }

    /// Загружает плагин из файла
    pub fn load_plugin<P: AsRef<Path>>(&self, plugin_path: P) -> Result<String, PluginError> {
        let path = plugin_path.as_ref();
        log_info!("Загрузка плагина из: {:?}", path);
        
        if !path.exists() {
            log_error!("Файл плагина не найден: {:?}", path);
            return Err(PluginError::InvalidPath(format!("Файл не найден: {:?}", path)));
        }

        // Загружаем библиотеку
        let lib = unsafe { 
            Library::new(path).map_err(|e| {
                log_error!("Ошибка загрузки библиотеки {:?}: {}", path, e);
                PluginError::LibraryLoadError(e.to_string())
            })?
        };

        // Получаем символ создания плагина
        let constructor: Symbol<unsafe extern "C" fn() -> *mut dyn Plugin> = unsafe {
            lib.get(b"create_plugin").map_err(|e| {
                log_error!("Ошибка получения символа 'create_plugin' из {:?}: {}", path, e);
                PluginError::SymbolError(e.to_string())
            })?
        };

        // Создаем экземпляр плагина
        let plugin = unsafe {
            let plugin_ptr = constructor();
            if plugin_ptr.is_null() {
                return Err(PluginError::InitializationError("Плагин вернул null".to_string()));
            }
            Box::from_raw(plugin_ptr)
        };

        // Получаем имя плагина
        let plugin_name = plugin.metadata().name.clone();
        log_debug!("Плагин '{}' успешно создан", plugin_name);

        // Проверяем, не загружен ли уже такой плагин
        {
            let plugins_read = self.plugins.read().unwrap();
            if plugins_read.contains_key(&plugin_name) {
                log_warn!("Плагин '{}' уже загружен", plugin_name);
                return Err(PluginError::PluginAlreadyLoaded(plugin_name));
            }
        }

        // Инициализируем плагин
        plugin.initialize().map_err(|e| {
            log_error!("Ошибка инициализации плагина '{}': {}", plugin_name, e);
            PluginError::InitializationError(e.to_string())
        })?;

        // Сохраняем плагин
        {
            let mut plugins_write = self.plugins.write().unwrap();
            plugins_write.insert(plugin_name.clone(), (Arc::new(lib), plugin));
        }

        log_info!("Плагин '{}' успешно загружен и инициализирован", plugin_name);
        Ok(plugin_name)
    }

    /// Загружает все плагины из указанного каталога
    pub fn load_plugins_from_directory<P: AsRef<Path>>(&self, dir: P) -> Result<Vec<String>, PluginError> {
        let dir_path = dir.as_ref();
        log_info!("Загрузка плагинов из каталога: {:?}", dir_path);
        
        if !dir_path.exists() || !dir_path.is_dir() {
            log_warn!("Каталог плагинов не найден или не является каталогом: {:?}", dir_path);
            return Ok(vec![]);
        }

        let mut loaded_plugins = Vec::new();
        
        // Определяем расширение для динамических библиотек в зависимости от платформы
        let lib_extension = if cfg!(target_os = "windows") {
            "dll"
        } else if cfg!(target_os = "macos") {
            "dylib"
        } else {
            "so"
        };

        // Читаем каталог
        for entry in std::fs::read_dir(dir_path).map_err(|e| {
            log_error!("Ошибка чтения каталога {:?}: {}", dir_path, e);
            PluginError::LibraryLoadError(e.to_string())
        })? {
            let entry = entry.map_err(|e| {
                log_error!("Ошибка чтения записи каталога: {}", e);
                PluginError::LibraryLoadError(e.to_string())
            })?;
            
            let path = entry.path();
            
            // Проверяем, что это файл с правильным расширением
            if path.is_file() && path.extension() == Some(OsStr::new(lib_extension)) {
                match self.load_plugin(&path) {
                    Ok(plugin_name) => {
                        loaded_plugins.push(plugin_name);
                    }
                    Err(e) => {
                        log_warn!("Не удалось загрузить плагин {:?}: {}", path, e);
                        // Продолжаем загрузку других плагинов
                    }
                }
            }
        }

        log_info!("Загружено {} плагинов из каталога {:?}", loaded_plugins.len(), dir_path);
        Ok(loaded_plugins)
    }

    /// Загружает плагины из всех зарегистрированных каталогов
    pub fn load_plugins_from_all_paths(&self) -> Result<Vec<String>, PluginError> {
        log_info!("Загрузка плагинов из всех зарегистрированных каталогов");
        let mut all_loaded = Vec::new();
        
        for path in &self.plugin_paths {
            let loaded = self.load_plugins_from_directory(path)?;
            all_loaded.extend(loaded);
        }
        
        log_info!("Всего загружено {} плагинов", all_loaded.len());
        Ok(all_loaded)
    }

    /// Получает ссылку на загруженный плагин по имени
    pub fn get_plugin(&self, name: &str) -> Option<std::sync::RwLockReadGuard<HashMap<String, (Arc<Library>, Box<dyn Plugin>)>>> {
        let plugins = self.plugins.read().unwrap();
        if plugins.contains_key(name) {
            Some(plugins)
        } else {
            None
        }
    }

    /// Получает список всех загруженных плагинов
    pub fn list_plugins(&self) -> Vec<PluginMetadata> {
        let plugins = self.plugins.read().unwrap();
        plugins.values()
            .map(|(_, plugin)| plugin.metadata().clone())
            .collect()
    }

    /// Выгружает плагин по имени
    pub fn unload_plugin(&self, name: &str) -> Result<(), PluginError> {
        log_info!("Выгрузка плагина: {}", name);
        
        let mut plugins = self.plugins.write().unwrap();
        if let Some((_, mut plugin)) = plugins.remove(name) {
            // Освобождаем ресурсы плагина
            plugin.shutdown().map_err(|e| {
                log_warn!("Ошибка при завершении работы плагина '{}': {}", name, e);
                PluginError::InitializationError(e.to_string())
            })?;
            log_info!("Плагин '{}' успешно выгружен", name);
            Ok(())
        } else {
            log_warn!("Плагин '{}' не найден для выгрузки", name);
            Err(PluginError::PluginNotFound(name.to_string()))
        }
    }

    /// Выгружает все плагины
    pub fn unload_all_plugins(&self) -> Result<(), PluginError> {
        log_info!("Выгрузка всех плагинов");
        let mut plugins = self.plugins.write().unwrap();
        let plugin_names: Vec<String> = plugins.keys().cloned().collect();
        
        for name in plugin_names {
            if let Some((_, mut plugin)) = plugins.remove(&name) {
                if let Err(e) = plugin.shutdown() {
                    log_warn!("Ошибка при завершении работы плагина '{}': {}", name, e);
                }
            }
        }
        
        log_info!("Все плагины выгружены");
        Ok(())
    }
}

// Реализация Drop для автоматической выгрузки плагинов
impl Drop for PluginLoader {
    fn drop(&mut self) {
        if let Err(e) = self.unload_all_plugins() {
            log_error!("Ошибка при автоматической выгрузке плагинов: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_plugin_loader_creation() {
        let loader = PluginLoader::new();
        assert!(!loader.plugin_paths.is_empty());
    }

    #[test]
    fn test_add_plugin_path() {
        let mut loader = PluginLoader::new();
        let initial_count = loader.plugin_paths.len();
        loader.add_plugin_path("/test/plugins");
        assert_eq!(loader.plugin_paths.len(), initial_count + 1);
    }

    #[test]
    fn test_list_plugins_empty() {
        let loader = PluginLoader::new();
        let plugins = loader.list_plugins();
        assert!(plugins.is_empty());
    }

    #[test]
    fn test_load_plugin_nonexistent() {
        let loader = PluginLoader::new();
        let result = loader.load_plugin("/nonexistent/plugin.so");
        assert!(result.is_err());
        match result.unwrap_err() {
            PluginError::InvalidPath(_) => {}, // Ожидаем эту ошибку
            _ => panic!("Ожидалась ошибка InvalidPath"),
        }
    }

    #[test]
    fn test_load_plugins_from_empty_directory() {
        let loader = PluginLoader::new();
        let temp_dir = TempDir::new().unwrap();
        let result = loader.load_plugins_from_directory(temp_dir.path());
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
