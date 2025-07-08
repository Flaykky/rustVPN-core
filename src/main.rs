use std::path::PathBuf;
use structopt::StructOpt;
use crate::utils::logging::init_logging;
use crate::config::parser::parse_config;
use crate::config::model::ServerConfig;
use crate::connection::manager::ConnectionManager;
use crate::tunneling::device::TunDevice;
use crate::tunneling::routing::RoutingManager;
use crate::obfuscation::common::Obfuscator;
use crate::cli::interface::{render_minimal_interface, render_pretty_interface};

#[derive(Debug, StructOpt)]
#[structopt(name = "vpn-core", about = "Минимальное ядро VPN клиента")]
struct Cli {
    #[structopt(short, long, default_value = "config.json")]
    config: PathBuf,

    #[structopt(short, long, default_value = "info")]
    log_level: String,

    #[structopt(short, long)]
    show_pretty: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::from_args();
    
    // Инициализация логгирования
    init_logging(&args.log_level);

    // Чтение и парсинг конфигурации
    log::info!("Загрузка конфигурации из {}", args.config.display());
    let servers = parse_config(&args.config)?;
    
    if servers.is_empty() {
        log::error!("Не найдено ни одного сервера в конфиге");
        return Ok(());
    }

    // Выбираем первый сервер для подключения
    let server = &servers[0];
    log::info!("Используется сервер: {} ({})", server.tag, server.protocol.protocol_type());

    // Создаем менеджер соединений
    let manager = ConnectionManager::new();
    
    // Подключаемся
    log::info!("Подключение к серверу...");
    manager.connect(server).await?;

    // Опционально: настройка TUN-интерфейса
    if let ProtocolConfig::Wireguard(ref wg) = server.protocol {
        let mut tun = TunDevice::new("tun0", Mode::Tun, Some(IpAddr::from_str(&wg.server_ip)?), Some(1420))?;
        tun.up()?;
        log::info!("TUN-интерфейс настроен");
        
        // Настройка маршрутов
        let routing = RoutingManager;
        routing.add_route("0.0.0.0/0", "tun0")?;
    }

    // Основной цикл — отображение статуса
    loop {
        let state = manager.get_state().await;
        
        if args.show_pretty {
            render_pretty_interface(server, &manager, &state)?;
        } else {
            render_minimal_interface(server, &manager, &state)?;
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
