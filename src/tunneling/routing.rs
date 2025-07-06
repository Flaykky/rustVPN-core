use crate::utils::logging::{log_info, log_warn};
use crate::utils::error::VpnError;
use std::net::IpAddr;

/// Manager for handling routing operations.
pub struct RoutingManager;

impl RoutingManager {
    /// Adds a route for the specified CIDR via the given TUN interface.
    ///
    /// # Arguments
    /// * `cidr` - The CIDR block to route (e.g., "192.168.1.0/24").
    /// * `interface` - The network interface to use (e.g., "tun0").
    pub fn add_route(&self, cidr: &str, interface: &str) -> Result<(), VpnError> {
        log_info!("Adding route {} via {}", cidr, interface);

        #[cfg(target_os = "linux")]
        {
            // Use the `ip` command to add a route on Linux.
            let output = std::process::Command::new("ip")
                .args(["route", "add", cidr, "dev", interface])
                .output()
                .map_err(|e| {
                    log_warn!("Command execution error: {}", e);
                    VpnError::TunnelingError(format!("Failed to add route: {}", e))
                })?;

            if !output.status.success() {
                return Err(VpnError::TunnelingError(String::from_utf8_lossy(&output.stderr).into()));
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Use the `netsh` command to add a route on Windows.
            let output = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "add", "route", cidr, interface])
                .output()
                .map_err(|e| {
                    log_warn!("Command execution error: {}", e);
                    VpnError::TunnelingError(format!("Failed to add route: {}", e))
                })?;

            if !output.status.success() {
                return Err(VpnError::TunnelingError(String::from_utf8_lossy(&output.stderr).into()));
            }
        }

        log_info!("Route {} via {} added", cidr, interface);
        Ok(())
    }

    /// Configures split-tunneling for the specified CIDR.
    ///
    /// # Arguments
    /// * `cidr` - The CIDR block to route through the tunnel.
    /// * `interface` - The network interface to use.
    pub fn set_split_tunnel(&self, cidr: &str, interface: &str) -> Result<(), VpnError> {
        log_info!("Configuring split-tunneling for {}", cidr);
        self.add_route(cidr, interface)?;
        log_info!("Split-tunneling configured for {}", cidr);
        Ok(())
    }

    /// Flushes all routes for the specified interface.
    ///
    /// # Arguments
    /// * `interface` - The network interface whose routes should be flushed.
    pub fn flush_routes(&self, interface: &str) -> Result<(), VpnError> {
        log_info!("Flushing routes for interface {}", interface);

        #[cfg(target_os = "linux")]
        {
            // Use the `ip` command to flush routes on Linux.
            let output = std::process::Command::new("ip")
                .args(["route", "flush", "dev", interface])
                .output()
                .map_err(|e| {
                    log_warn!("Command execution error: {}", e);
                    VpnError::TunnelingError(format!("Failed to flush routes: {}", e))
                })?;

            if !output.status.success() {
                return Err(VpnError::TunnelingError(String::from_utf8_lossy(&output.stderr).into()));
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Use the `netsh` command to delete all routes for the interface on Windows.
            let output = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "delete", "route", "prefix=::/0", interface])
                .output()
                .map_err(|e| {
                    log_warn!("Command execution error: {}", e);
                    VpnError::TunnelingError(format!("Failed to flush routes: {}", e))
                })?;

            if !output.status.success() {
                return Err(VpnError::TunnelingError(String::from_utf8_lossy(&output.stderr).into()));
            }
        }

        log_info!("Routes for {} flushed", interface);
        Ok(())
    }

    /// Retrieves a list of all current routes.
    ///
    /// # Returns
    /// * `Ok(String)` containing the list of routes.
    /// * `Err(VpnError)` if the command fails or is unsupported.
    pub fn list_routes(&self) -> Result<String, VpnError> {
        #[cfg(target_os = "linux")]
        {
            // Use the `ip` command to show routes on Linux.
            let output = std::process::Command::new("ip")
                .args(["route", "show"])
                .output()
                .map_err(|e| {
                    log_warn!("Command execution error: {}", e);
                    VpnError::TunnelingError(format!("Failed to get routes: {}", e))
                })?;

            let routes = String::from_utf8_lossy(&output.stdout).to_string();
            log_info!("Current routes:\n{}", routes);
            Ok(routes)
        }

        #[cfg(target_os = "windows")]
        {
            // Use the `netsh` command to show routes on Windows.
            let output = std::process::Command::new("netsh")
                .args(["interface", "ipv4", "show", "routes"])
                .output()
                .map_err(|e| {
                    log_warn!("Command execution error: {}", e);
                    VpnError::TunnelingError(format!("Failed to get routes: {}", e))
                })?;

            let routes = String::from_utf8_lossy(&output.stdout).to_string();
            log_info!("Current routes:\n{}", routes);
            Ok(routes)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            log_warn!("Route management is not supported on this system");
            Ok("Routes: unsupported operation".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_route() {
        let manager = RoutingManager;
        // Test command (requires root/admin privileges)
        let result = manager.add_route("192.168.1.0/24", "tun0");
        assert!(result.is_ok() || result.unwrap_err().to_string().contains("not found"));
    }
}
