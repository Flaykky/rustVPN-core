use crate::utils::logging::{log_info, log_warn};
use crate::utils::error::VpnError;
use std::net::IpAddr;

/// Менеджер для управления маршрутизацией.
pub struct RoutingManager;

impl RoutingManager {
    /// Добавляет маршрут для указанного CIDR через TUN-интерфейс.
    pub fn add_route(&self, cidr: &str, interface: &str) -> Result<(), VpnError> {
        log_info!("Добавление маршрута {} через {}", cidr, interface);

        #[cfg(target_os = "linux")]
        {
            let output = std::process::Command::new("ip")
                .args(["route", "add", cidr, "dev", interface])
                .output()
                .map_err(|e| {
                    log_warn!("Ошибка выполнения команды: {}", e);
                    VpnError::TunnelingError(format!("Ошибка добавления маршрута: {}", e))
                })?;

            if !output.status.success() {
                return Err(VpnError::TunnelingError(String::from_utf8_lossy(&output.stderr).into()));
            }
        }

        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "add", "route", cidr, interface])
                .output()
                .map_err(|e| {
                    log_warn!("Ошибка выполнения команды: {}", e);
                    VpnError::TunnelingError(format!("Ошибка добавления маршрута: {}", e))
                })?;

            if !output.status.success() {
                return Err(VpnError::TunnelingError(String::from_utf8_lossy(&output.stderr).into()));
            }
        }

        log_info!("Маршрут {} через {} добавлен", cidr, interface);
        Ok(())
    }

    /// Настраивает split-tunneling для указанного CIDR.
    pub fn set_split_tunnel(&self, cidr: &str, interface: &str) -> Result<(), VpnError> {
        log_info!("Настройка Split-Tunneling для {}", cidr);
        self.add_route(cidr, interface)?;
        log_info!("Split-Tunneling настроен для {}", cidr);
        Ok(())
    }

    /// Очищает все маршруты для указанного интерфейса.
    pub fn flush_routes(&self, interface: &str) -> Result<(), VpnError> {
        log_info!("Очистка маршрутов для интерфейса {}", interface);

        #[cfg(target_os = "linux")]
        {
            let output = std::process::Command::new("ip")
                .args(["route", "flush", "dev", interface])
                .output()
                .map_err(|e| {
                    log_warn!("Ошибка выполнения команды: {}", e);
                    VpnError::TunnelingError(format!("Ошибка очистки маршрутов: {}", e))
                })?;

            if !output.status.success() {
                return Err(VpnError::TunnelingError(String::from_utf8_lossy(&output.stderr).into()));
            }
        }

        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", "prefix=::/0", interface])
                .output()
                .map_err(|e| {
                    log_warn!("Ошибка выполнения команды: {}", e);
                    VpnError::TunnelingError(format!("Ошибка очистки маршрутов: {}", e))
                })?;

            if !output.status.success() {
                return Err(VpnError::TunnelingError(String::from_utf8_lossy(&output.stderr).into()));
            }
        }

        log_info!("Маршруты для {} очищены", interface);
        Ok(())
    }

    /// Получает список всех маршрутов.
    pub fn list_routes(&self) -> Result<String, VpnError> {
        #[cfg(target_os = "linux")]
        {
            let output = std::process::Command::new("ip")
                .args(["route", "show"])
                .output()
                .map_err(|e| {
                    log_warn!("Ошибка выполнения команды: {}", e);
                    VpnError::TunnelingError(format!("Ошибка получения маршрутов: {}", e))
                })?;

            let routes = String::from_utf8_lossy(&output.stdout).to_string();
            log_info!("Текущие маршруты:\n{}", routes);
            Ok(routes)
        }

        #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "show", "routes"])
                .output()
                .map_err(|e| {
                    log_warn!("Ошибка выполнения команды: {}", e);
                    VpnError::TunnelingError(format!("Ошибка получения маршрутов: {}", e))
                })?;

            let routes = String::from_utf8_lossy(&output.stdout).to_string();
            log_info!("Текущие маршруты:\n{}", routes);
            Ok(routes)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            log_warn!("Система не поддерживается для управления маршрутами");
            Ok("Маршруты: неподдерживаемая операция".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_route() {
        let manager = RoutingManager;
        // Тестовая команда (требует root)
        let result = manager.add_route("192.168.1.0/24", "tun0");
        assert!(result.is_ok() || result.unwrap_err().to_string().contains("не найден"));
    }
}
