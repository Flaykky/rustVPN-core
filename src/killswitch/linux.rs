// src/killswitch/linux.rs

use std::{
    process::{Command, Stdio},
    ffi::OsStr,
    path::Path,
    fs::File,
};
use regex::Regex;
use anyhow::{Result, Context, anyhow};
use crate::utils::logging::{log, LogLevel};

const IPTABLES: &str = "iptables";
const IP6TABLES: &str = "ip6tables";
const COMMENT: &str = "KILLSWITCH";

#[derive(Debug)]
pub struct KillSwitch {
    vpn_interface: String,
    original_rules: Option<String>,
}

impl KillSwitch {
    /// Создание нового Kill Switch
    pub fn new(interface: &str) -> Result<Self> {
        let re = Regex::new(r"^[a-zA-Z0-9_]+$")?;
        if !re.is_match(interface) {
            anyhow::bail!("Invalid interface name: {}", interface);
        }
        
        Ok(Self {
            vpn_interface: interface.to_owned(),
            original_rules: None,
        })
    }

    /// Включение защиты
    pub fn enable(&mut self) -> Result<()> {
        if self.original_rules.is_some() {
            return Ok(()); // Уже включен
        }

        // Сохраняем текущие правила
        let original = Self::save_iptables()?;
        self.original_rules = Some(original);

        // Применяем новые правила
        for &binary in &[IPTABLES, IP6TABLES] {
            self.add_rule(binary, "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT")?;
            self.add_rule(binary, "-A", "OUTPUT", "-o", &self.vpn_interface, "-j", "ACCEPT")?;
            self.add_rule(binary, "-A", "OUTPUT", "-j", "DROP")?;
        }

        log!(LogLevel::Info, "Kill Switch enabled for {}", self.vpn_interface);
        Ok(())
    }

    /// Отключение защиты
    pub fn disable(&mut self) -> Result<()> {
        if let Some(original) = self.original_rules.take() {
            // Восстанавливаем оригинальные правила
            let mut file = tempfile::NamedTempFile::new()?;
            file.write_all(original.as_bytes())?;
            Command::new("iptables-restore")
                .arg(file.path())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
                
            log!(LogLevel::Info, "Kill Switch disabled");
        }
        Ok(())
    }

    /// Добавление правила iptables
    fn add_rule<S: AsRef<OsStr>>(
        &self,
        binary: &str,
        ac1tion: S,
        chain: S,
        output_interface: S,
        jump: S,
    ) -> Result<()> {
        let status = Command::new(binary)
            .arg(action)
            .arg(chain)
            .arg("-o")
            .arg(output_interface)
            .arg("-j")
            .arg(jump)
            .arg("-m")
            .arg("comment")
            .arg("--comment")
            .arg(COMMENT)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;

        if !status.success() {
            anyhow::bail!("Failed to execute {} command", binary);
        }
        Ok(())
    }

    /// Сохранение текущих правил iptables
    fn save_iptables() -> Result<String> {
        let output = Command::new("iptables-save")
            .stdout(Stdio::piped())
            .output()?;
            
        if !output.status.success() {
            anyhow::bail!("Failed to save iptables rules");
        }
        
        Ok(String::from_utf8(output.stdout)?)
    }
}

impl Drop for KillSwitch {
    fn drop(&mut self) {
        let _ = self.disable();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kill_switch() {
        let mut ks = KillSwitch::new("tun0").unwrap();
        assert!(ks.enable().is_ok());
        assert!(ks.disable().is_ok());
    
    }
}