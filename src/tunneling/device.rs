use crate::utils::logging::{log_info, log_warn};
use crate::utils::error::VpnError;
use tun_tap::{Iface, Mode};
use std::net::{IpAddr, Ipv4Addr};

/// Представляет виртуальный сетевой интерфейс (TUN/TAP).
pub struct TunDevice {
    iface: Iface,
}

impl TunDevice {
    /// Создает новый TUN-интерфейс.
    pub fn new(name: &str, mode: Mode, ip: Option<IpAddr>, mtu: Option<u32>) -> Result<Self, VpnError> {
        log_info!("Создание TUN-интерфейса {}", name);

        let mut builder = tun_tap::Configuration::default();
        builder.name(name).mode(mode);

        if let Some(ip) = ip {
            match ip {
                IpAddr::V4(ipv4) => {
                    builder.address(ipv4);
                }
                IpAddr::V6(ipv6) => {
                    log_warn!("IPv6 не поддерживается в текущей реализации");
                }
            }
        }

        if let Some(mtu) = mtu {
            builder.mtu(mtu as i32);
        }

        let iface = Iface::new(builder).map_err(|e| {
            log_warn!("Не удалось создать TUN-интерфейс: {}", e);
            VpnError::TunnelingError(format!("Ошибка создания TUN-интерфейса: {}", e))
        })?;

        log_info!("TUN-интерфейс {} успешно создан", name);
        Ok(Self { iface })
    }

    /// Устанавливает IPv4-адрес для интерфейса.
    pub fn set_ipv4_address(&mut self, ip: Ipv4Addr, prefix_len: u8) -> Result<(), VpnError> {
        log_info!("Установка IPv4-адреса {} для TUN-интерфейса", ip);
        self.iface.set_address(ip, prefix_len).map_err(|e| {
            log_warn!("Не удалось установить IPv4-адрес: {}", e);
            VpnError::TunnelingError(format!("Ошибка установки IPv4-адреса: {}", e))
        })
    }

    /// Устанавливает MTU для интерфейса.
    pub fn set_mtu(&mut self, mtu: u32) -> Result<(), VpnError> {
        log_info!("Установка MTU: {} для TUN-интерфейса", mtu);
        self.iface.set_mtu(mtu as i32).map_err(|e| {
            log_warn!("Не удалось установить MTU: {}", e);
            VpnError::TunnelingError(format!("Ошибка установки MTU: {}", e))
        })
    }

    /// Включает интерфейс.
    pub fn up(&mut self) -> Result<(), VpnError> {
        log_info!("Включение TUN-интерфейса");
        self.iface.up().map_err(|e| {
            log_warn!("Не удалось включить интерфейс: {}", e);
            VpnError::TunnelingError(format!("Ошибка включения интерфейса: {}", e))
        })
    }

    /// Выключает интерфейс.
    pub fn down(&mut self) -> Result<(), VpnError> {
        log_info!("Выключение TUN-интерфейса");
        self.iface.down().map_err(|e| {
            log_warn!("Не удалось выключить интерфейс: {}", e);
            VpnError::TunnelingError(format!("Ошибка выключения интерфейса: {}", e))
        })
    }

    /// Читает пакет из интерфейса.
    pub fn read_packet(&mut self, buffer: &mut [u8]) -> Result<usize, VpnError> {
        let size = self.iface.recv(buffer).map_err(|e| {
            log_warn!("Ошибка чтения пакета: {}", e);
            VpnError::TunnelingError(format!("Ошибка чтения пакета: {}", e))
        })?;
        log_info!("Прочитан пакет размером {} байт", size);
        Ok(size)
    }

    /// Отправляет пакет через интерфейс.
    pub fn write_packet(&mut self, packet: &[u8]) -> Result<(), VpnError> {
        self.iface.send(packet).map_err(|e| {
            log_warn!("Ошибка отправки пакета: {}", e);
            VpnError::TunnelingError(format!("Ошибка отправки пакета: {}", e))
        })?;
        log_info!("Пакет отправлен через TUN-интерфейс");
        Ok(())
    }

    /// Возвращает имя интерфейса.
    pub fn name(&self) -> String {
        self.iface.name().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_tun_device_creation() {
        let mut tun = TunDevice::new("tun0", Mode::Tun, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))), Some(1500));
        assert!(tun.is_ok());
        let tun = tun.unwrap();
        assert_eq!(tun.name(), "tun0");
    }
}
