use crate::cli::interface::{run, Command};
use crate::utils::logging::init_logging;
use crate::config::parser::parse_config;
use crate::config::model::ServerConfig;
use crate::connection::manager::ConnectionManager;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;

#[tokio::main]
async fn main() {
    // Инициализация логгирования
    init_logging("info");

    // Загрузка конфигурации
    let config_path = "config.json";
    let servers = match parse_config(config_path) {
        Ok(servers) => Arc::new(TokioMutex::new(servers)),
        Err(e) => {
            eprintln!("❌ Ошибка загрузки конфигурации: {}", e);
            return;
        }
    };

    // Инициализация менеджера подключений
    let connection_manager = Arc::new(TokioMutex::new(ConnectionManager::new()));

    // Запуск CLI-интерфейса
    if let Err(e) = run(servers, connection_manager).await {
        eprintln!("❌ Ошибка CLI: {}", e);
    }
}
