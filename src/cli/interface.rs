use crate::utils::error::VpnError;
use crate::config::model::ServerConfig;
use crate::connection::manager::{ConnectionManager, ConnectionState};
use crate::connection::manager::ConnectionManager;
use crate::tunneling::device::TunDevice;
use crate::utils::common::{read_file_to_string, generate_random_string};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use clap::{Command as ClapCommand, Arg, ArgMatches};
use std::time::SystemTime;
use std::fmt::Write;

pub enum Command {
    Connect { config_path: PathBuf, server_tag: String },
    Disconnect,
    Status,
}

pub async fn run(
    servers: Arc<TokioMutex<Vec<ServerConfig>>>,
    connection_manager: Arc<TokioMutex<ConnectionManager>>,
) -> Result<(), VpnError> {
    let matches = build_cli().get_matches();

    match parse_command(&matches)? {
        Command::Connect { config_path, server_tag } => {
            connect_command(servers, connection_manager, &config_path, &server_tag).await?;
        }
        Command::Disconnect => {
            disconnect_command(connection_manager).await?;
        }
        Command::Status => {
            status_command(servers, connection_manager).await?;
        }
    }

    Ok(())
}

fn build_cli() -> ClapCommand<'static> {
    ClapCommand::new("vpn-cli")
        .version("1.0")
        .author("VPN Team")
        .about("Минималистичный CLI для управления VPN")
        .subcommand_required(true)
        .subcommand(
            ClapCommand::new("connect")
                .about("Подключение к серверу")
                .arg(Arg::new("config")
                    .short('c')
                    .long("config")
                    .value_name("PATH")
                    .help("Путь к конфигурационному файлу")
                    .required(true))
                .arg(Arg::new("server")
                    .short('s')
                    .long("server")
                    .value_name("TAG")
                    .help("Тег сервера из конфига")
                    .required(true)),
        )
        .subcommand(
            ClapCommand::new("disconnect")
                .about("Отключение от сервера"),
        )
        .subcommand(
            ClapCommand::new("status")
                .about("Показывает текущий статус подключения"),
        )
}

fn parse_command(matches: &ArgMatches) -> Result<Command, VpnError> {
    if let Some(connect) = matches.subcommand_matches("connect") {
        let config_path = connect.value_of("config").unwrap().into();
        let server_tag = connect.value_of("server").unwrap().to_string();
        return Ok(Command::Connect { config_path, server_tag });
    }

    if matches.subcommand_matches("disconnect").is_some() {
        return Ok(Command::Disconnect);
    }

    if matches.subcommand_matches("status").is_some() {
        return Ok(Command::Status);
    }

    Err(VpnError::cli_error("Неизвестная команда"))
}

async fn connect_command(
    servers: Arc<TokioMutex<Vec<ServerConfig>>>,
    manager: Arc<TokioMutex<ConnectionManager>>,
    config_path: &PathBuf,
    server_tag: &str,
) -> Result<(), VpnError> {
    println!("🔄 Подключение к серверу '{}'...", server_tag);

    // Загрузка конфига (если нужен повторный парсинг)
    let servers_locked = servers.lock().await;
    if let Some(server) = servers_locked.iter().find(|s| s.tag == server_tag) {
        let mut manager_locked = manager.lock().await;
        manager_locked.connect(server).await?;
        print_status(server, &manager_locked).await;
    } else {
        eprintln!("⚠️ Сервер '{}' не найден в конфиге", server_tag);
    }

    Ok(())
}

async fn disconnect_command(manager: Arc<TokioMutex<ConnectionManager>>) -> Result<(), VpnError> {
    println!("🔌 Отключение от сервера...");
    let mut manager_locked = manager.lock().await;
    manager_locked.disconnect().await?;
    println!("✅ Отключено");
    Ok(())
}

async fn status_command(
    servers: Arc<TokioMutex<Vec<ServerConfig>>>,
    manager: Arc<TokioMutex<ConnectionManager>>,
) -> Result<(), VpnError> {
    let manager_locked = manager.lock().await;
    let state = manager_locked.get_state().await;

    match state {
        ConnectionState::Connected => {
            let current_server = servers.lock().await.iter().find(|s| s.tag == "default").cloned(); // Упрощенно
            if let Some(ref server) = current_server {
                print_status(server, &manager_locked).await;
            } else {
                println!("🟢 Подключение установлено, но сервер не определен");
            }
        }
        ConnectionState::Connecting => {
            println!("⏳ Подключение...");
        }
        ConnectionState::Reconnecting => {
            println!("🔄 Переподключение...");
        }
        ConnectionState::Disconnected => {
            println!("🔴 Не подключено");
        }
        ConnectionState::Error(msg) => {
            eprintln!("❌ Ошибка подключения: {}", msg);
        }
    }

    Ok(())
}

async fn print_status(server: &ServerConfig, manager: &ConnectionManager) {
    println!("{}\n", get_status_header());
    println!("Сервер: {} ({})", get_flag(&server.tag), server.protocol);
    println!("Вход:  {}", server.server_ip);
    println!("Выход: {}\n", server.server_ip); // Примерное значение

    // Примерные данные (заменить на реальные метрики)
    let upload = format_data_size(123 * 1024); // 123 KB
    let download = format_data_size(456 * 1024); // 456 KB

    println!("Статус:");
    println!("↑  {}     ↓  {}", upload, download);
    println!();
}

fn get_status_header() -> String {
    format!("\x1b[32m[VPN: connected]\x1b[0m")
}

fn get_flag(tag: &str) -> String {
    match tag.to_lowercase().as_str() {
        "sweden" => "🇸🇪".to_string(),
        "germany" => "🇩🇪".to_string(),
        "usa" => "🇺🇸".to_string(),
        _ => "🌐".to_string(),
    }
}

fn format_data_size(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = 1024 * KB;
    const GB: usize = 1024 * MB;

    let (value, suffix) = match bytes {
        0..=KB => (bytes as f64, "B"),
        KB..=MB => (bytes as f64 / KB as f64, "KB"),
        MB..=GB => (bytes as f64 / MB as f64, "MB"),
        _ => (bytes as f64 / GB as f64, "GB"),
    };

    format!("{:.1} {}", value, suffix)
}
