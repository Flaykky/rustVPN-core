use crate::config::model::ServerConfig;
use crate::connection::manager::ConnectionManager;
use crate::connection::manager::ConnectionState;
use crate::utils::logging::{log_info, log_debug};
use std::sync::Arc;

/// Простой минимальный интерфейс CLI
pub fn render_minimal_interface(
    server: &ServerConfig,
    manager: &ConnectionManager,
    state: &ConnectionState
) -> Result<(), Box<dyn std::error::Error>> {
    log_info!("[VPN: {}]", match state {
        ConnectionState::Connected => "connected",
        ConnectionState::Connecting => "connecting...",
        _ => "disconnected"
    });

    log_info!("");
    log_info!("server: {} ({})", server.tag, match &server.protocol {
        ProtocolConfig::Wireguard(wg) => format!("WireGuard: {}", wg.server_ip),
        ProtocolConfig::Shadowsocks(ss) => format!("Shadowsocks: {}", ss.server_ip),
        _ => "Other".to_string()
    });
    log_info!("in: {}:{}", 
        server.protocol.get_server_ip(), 
        server.protocol.get_server_port()
    );
    log_info!("out: {}", server.protocol.get_out_ip().unwrap_or("N/A"));

    // Получаем статистику
    let stats = manager.get_stats()?;
    log_info!("status:");
    log_info!("↑  {} KB     ↓  {} KB     Speed: {} Mbps", 
        stats.uploaded / 1024,
        stats.downloaded / 1024,
        stats.speed / 1_000_000
    );

    Ok(())
}

/// Красивый CLI-интерфейс с рамками и деталями
pub fn render_pretty_interface(
    server: &ServerConfig,
    manager: &ConnectionManager,
    state: &ConnectionState
) -> Result<(), Box<dyn std::error::Error>> {
    // Статус подключения
    println!("╭── VPN CLIENT ─────────────────────────────╮");
    println!("│ Status       : {} │", match state {
        ConnectionState::Connected => "✅ Connected",
        ConnectionState::Connecting => "🔄 Connecting...",
        _ => "❌ Disconnected"
    });
    
    // Протокол
    println!("│ Protocol     : {:<25} │", match &server.protocol {
        ProtocolConfig::Wireguard(_) => "WireGuard",
        ProtocolConfig::Shadowsocks(_) => "Shadowsocks",
        _ => "Other"
    });

    // Обфускация (если есть)
    let obfuscation = match server.obfuscation.as_ref() {
        Some(oc) => match oc.obfuscation_type {
            ObfuscationType::ShadowsocksOverWireguard => "Shadowsocks",
            ObfuscationType::Fragmentation => "Fragmentation",
            ObfuscationType::Masquerade => "TLS Masquerade",
            ObfuscationType::CustomPlugin => "Custom Plugin"
        },
        None => "Disabled"
    };
    println!("│ Obfuscation  : {} │", format!("{}{}", 
        if obfuscation == "Disabled" { "❌ " } else { "✅ " }, 
        obfuscation
    ).pad_to_width(25));

    // DNS (если настроен)
    let dns = server.advanced_routing.as_ref()
        .and_then(|ar| ar.dns.as_ref())
        .map(|d| d.join(", "))
        .unwrap_or("Default".to_string());
    println!("│ Custom DNS   : {:<25} │", dns);
    println!("╰──────────────────────────────────────────╯");
    
    // Информация о сервере
    println!("╭── Server Info ───────────────────────────╮");
    println!("│ Location     : {} │", server.custom_tags.iter().find(|t| t.contains("geo-")).map(|t| t.replace("geo-", "")).unwrap_or("Unknown".to_string()));
    println!("│ Ingress IP   : {}:{} │", server.protocol.get_server_ip(), server.protocol.get_server_port());
    println!("│ Egress IP    : {} │", server.protocol.get_out_ip().unwrap_or("N/A"));
    println!("╰──────────────────────────────────────────╯");

    // Трафик
    let stats = manager.get_stats()?;
    println!("╭── Traffic ───────────────────────────────╮");
    println!("│ Uploaded     : {:.2} MB                │", stats.uploaded as f64 / 1024.0 / 1024.0);
    println!("│ Downloaded   : {:.2} MB                │", stats.downloaded as f64 / 1024.0 / 1024.0);
    println!("│ Speed        : ↑ {:.2} Mbps / ↓ {:.2} Mbps │", 
        stats.upload_speed as f64 / 125_000.0,
        stats.download_speed as f64 / 125_000.0
    );
    println!("╰──────────────────────────────────────────╯");

    Ok(())
}

// Расширение для форматирования текста
trait FormatUtils {
    fn pad_to_width(&self, width: usize) -> String;
}

impl FormatUtils for &str {
    fn pad_to_width(&self, width: usize) -> String {
        let mut s = self.to_string();
        while s.len() < width {
            s.push(' ');
        }
        s
    }
}
