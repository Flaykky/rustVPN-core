// src/killswitch/windows.rs

use std::{
    process::{Command, Stdio},
    ffi::OsStr,
    collections::HashSet,
};
use anyhow::{Result, Context, anyhow};
use regex::Regex;
use crate::utils::logging::{log, LogLevel};

const RULE_NAME: &str = "VPN Kill Switch";
const RULE_GROUP: &str = "VPN Protection";

#[derive(Debug)]
pub struct KillSwitch {
    vpn_interface: String,
    original_state: Option<String>,
}

impl KillSwitch {
    /// Создание нового Kill Switch для Windows
    pub fn new(interface: &str) -> Result<Self> {
        let re = Regex::new(r"^[\p{L}\p{N}_ ]+$")?;
        if !re.is_match(interface) {
            anyhow::bail!("Invalid interface name: {}", interface);
        }

        Ok(Self {
            vpn_interface: interface.to_owned(),
            original_state: None,
        })
    }

    /// Включение защиты
    pub fn enable(&mut self) -> Result<()> {
        if self.original_state.is_some() {
            return Ok(());
        }

        // Сохраняем текущие правила
        let original = self.get_firewall_state()?;
        self.original_state = Some(original);

        // Создаем новые правила
        self.create_firewall_rules()?;

        log!(LogLevel::Info, "Windows Kill Switch enabled for {}", self.vpn_interface);
        Ok(())
    }

    /// Отключение защиты
    pub fn disable(&mut self) -> Result<()> {
        if let Some(original) = self.original_state.take() {
            // Восстанавливаем оригинальные правила
            self.restore_firewall_state(original)?;
            log!(LogLevel::Info, "Windows Kill Switch disabled");
        }
        Ok(())
    }

    /// Создание правил брандмауэра
    fn create_firewall_rules(&self) -> Result<()> {
        // Блокируем весь исходящий трафик
        self.execute_powershell(&[
            "New-NetFirewallRule",
            "-DisplayName", RULE_NAME,
            "-Group", RULE_GROUP,
            "-Direction", "Outbound",
            "-Action", "Block",
            "-Enabled", "True",
            "-Profile", "Any",
            "-InterfaceType", "Any"
        ])?;

        // Разрешаем трафик через VPN интерфейс
        self.execute_powershell(&[
            "New-NetFirewallRule",
            "-DisplayName", &format!("{} Allow", RULE_NAME),
            "-Group", RULE_GROUP,
            "-Direction", "Outbound",
            "-Action", "Allow",
            "-Enabled", "True",
            "-Profile", "Any",
            "-InterfaceAlias", &self.vpn_interface
        ])?;

        Ok(())
    }

    /// Сохранение текущего состояния брандмауэра
    fn get_firewall_state(&self) -> Result<String> {
        let output = self.execute_powershell(&[
            "Get-NetFirewallRule",
            "-Group", RULE_GROUP,
            "-ErrorAction", "SilentlyContinue"
        ])?;

        Ok(String::from_utf8(output.stdout)?)
    }

    /// Восстановление состояния брандмауэра
    fn restore_firewall_state(&self, original: String) -> Result<()> {
        // Удаляем все правила группы
        self.execute_powershell(&[
            "Remove-NetFirewallRule",
            "-Group", RULE_GROUP,
            "-Confirm:$false"
        ])?;

        // Восстанавливаем оригинальные правила
        if !original.is_empty() {
            let mut child = Command::new("powershell")
                .arg("-Command")
                .arg(original)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
                
            child.wait()?;
        }
        Ok(())
    }

    /// Безопасное выполнение PowerShell команд
    fn execute_powershell<S: AsRef<OsStr>>(&self, args: &[S]) -> Result<std::process::Output> {
        let mut cmd = format!("Start-Process powershell -ArgumentList '-Command ");
        for arg in args {
            cmd.push_str(&format!("{} ", arg.as_ref().to_string_lossy()));
        }
        cmd.push_str("' -Verb RunAs -Wait");

        let output = Command::new("powershell")
            .arg("-Command")
            .arg(cmd)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("PowerShell error: {}", error);
        }
        Ok(output)
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
        let mut ks = KillSwitch::new("VPN Interface").unwrap();
        assert!(ks.enable().is_ok());
        assert!(ks.disable().is_ok());
    }
}