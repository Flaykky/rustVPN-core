# rustVPN-core

A full VPN client in CLI mode.

## Features
- Works in CLI
- Popular protocols support (wireguard, openVPN, shadowsocks)
- DPI bypassing by obfuscations (udp2raw)
- Proxy support
- Many cli-interface modes


## Struct of project
```text
rustVPN-core/                        # Root directory of the Rust-based VPN project
├── src/                             # Main source code directory
│   ├── cli/                         # Command-line interface logic and user interaction
│   │   ├── handler.rs               # Handles CLI input commands and execution logic
│   │   ├── interface.rs             # Defines CLI interface layout and behavior
│   │   ├── mod.rs                   # Module declaration for the CLI
│   │   └── output.rs                # Handles CLI output formatting and printing
│
│   ├── config/                      # Configuration system for loading and parsing VPN settings
│   │   ├── loader.rs                # Loads configuration from files or environment
│   │   ├── mod.rs                   # Module declaration for configuration
│   │   ├── model.rs                 # Defines configuration data structures and schemas
│   │   └── parser.rs                # Parses configuration files (e.g., TOML, JSON)
│
│   ├── connection/                  # VPN connection protocols, proxies, and transport layers
│   │   ├── protocols/               # Supported VPN protocols
│   │   │   ├── mod.rs               # Module declaration for protocols
│   │   │   ├── openvpn.rs           # Integration with OpenVPN protocol
│   │   │   ├── plugin.rs            # Interface for protocol plugins
│   │   │   ├── shadowsocks.rs       # Integration with Shadowsocks protocol
│   │   │   └── wireguard.rs         # Integration with WireGuard protocol
│   │   ├── proxy/                   # Proxy protocol support
│   │   │   ├── http.rs              # HTTP proxy implementation
│   │   │   ├── https.rs             # HTTPS proxy implementation
│   │   │   ├── mod.rs               # Module declaration for proxy
│   │   │   ├── socks4.rs            # SOCKS4 proxy support
│   │   │   └── socks5.rs            # SOCKS5 proxy support
│   │   ├── transport/               # Transport layer abstraction for data transmission
│   │   │   ├── mod.rs               # Module declaration for transport
│   │   │   ├── quic.rs              # QUIC transport protocol implementation
│   │   │   ├── tcp.rs               # TCP transport protocol implementation
│   │   │   └── udp.rs               # UDP transport protocol implementation
│   │   ├── manager.rs               # Manages connections and their lifecycles
│   │   └── mod.rs                   # Module declaration for connection
│
│   ├── core/                        # Core logic and system state management
│   │   ├── controller.rs            # High-level VPN controller
│   │   ├── lifecycle.rs             # Manages application startup and shutdown lifecycle
│   │   ├── mod.rs                   # Module declaration for core
│   │   └── state.rs                 # Maintains global/shared state information
│
│   ├── encryption/                  # Encryption and key management system
│   │   ├── cipher/                  # Encryption ciphers
│   │   │   ├── aes/                 # AES cipher implementations
│   │   │   │   ├── cfb.rs           # AES-CFB mode
│   │   │   │   ├── gcm.rs           # AES-GCM mode
│   │   │   │   ├── mod.rs           # Module declaration for AES
│   │   │   │   └── pmac-siv.rs      # AES PMAC-SIV mode
│   │   │   └── stream/              # Stream cipher implementations
│   │   │       ├── chacha.rs        # ChaCha20 cipher
│   │   │       ├── mod.rs           # Module declaration for stream ciphers
│   │   │       ├── rc4.rs           # RC4 cipher
│   │   │       └── salsa.rs         # Salsa20 cipher
│   │   ├── key/                     # Key derivation and storage
│   │   │   ├── kdf.rs               # Key derivation functions
│   │   │   ├── manager.rs           # Key management logic
│   │   │   ├── mod.rs               # Module declaration for key
│   │   │   └── store.rs             # Secure key storage
│   │   ├── cipher.rs                # Cipher abstraction and interfaces
│   │   ├── error.rs                 # Encryption-related error definitions
│   │   ├── key_manager.rs           # High-level key manager abstraction
│   │   ├── mod.rs                   # Module declaration for encryption
│   │   └── traits.rs                # Encryption-related traits
│
│   ├── obfuscation/                # Obfuscation techniques to evade DPI/firewalls
│   │   ├── dpi/                    # DPI (Deep Packet Inspection) countermeasures
│   │   │   ├── fragment.rs          # Packet fragmentation logic
│   │   │   ├── masquerade.rs        # Protocol masquerading logic
│   │   │   ├── mod.rs               # Module declaration for DPI
│   │   │   ├── protocol_shift.rs    # Shifting protocol identifiers to confuse DPI
│   │   │   └── timing.rs            # Timing-based obfuscation
│   │   ├── plugin/                 # Obfuscation plugin support
│   │   │   ├── interface.rs         # Plugin interface
│   │   │   ├── loader.rs            # Dynamically loads obfuscation plugins
│   │   │   └── mod.rs               # Module declaration for plugin
│   │   ├── preset/                 # Predefined obfuscation profiles
│   │   │   ├── advanced.rs          # Advanced obfuscation preset
│   │   │   ├── basic.rs             # Basic obfuscation preset
│   │   │   ├── custom.rs            # Custom user-defined preset
│   │   │   └── mod.rs               # Module declaration for presets
│   │   ├── protocol/              # Custom obfuscation protocol definitions
│   │   │   ├── encryption.rs        # Obfuscation-layer encryption
│   │   │   ├── header.rs            # Custom protocol headers
│   │   │   ├── mod.rs               # Module declaration
│   │   │   └── tunnel.rs            # Tunnel protocol implementation
│   │   ├── timing/                # Timing obfuscation techniques
│   │   │   ├── delay.rs            # Adds artificial delay
│   │   │   ├── jitter.rs           # Adds random jitter to packets
│   │   │   └── mod.rs              # Module declaration
│   │   ├── utils/                 # Utility functions for obfuscation
│   │   │   ├── crypto.rs           # Cryptographic helpers
│   │   │   ├── mod.rs              # Module declaration
│   │   │   └── packet.rs           # Packet-level utilities
│   │   ├── wrappers/              # Wrappers for integrating with other tools
│   │   │   ├── mod.rs              # Module declaration
│   │   │   ├── quic-wrap.rs        # Wrapper for QUIC integration
│   │   │   ├── udp2raw.rs          # Wrapper for UDP2RAW tool
│   │   │   └── wireguard2tcp.rs    # Wrapper to tunnel WireGuard over TCP
│   │   ├── common.rs              # Common definitions used across obfuscation modules
│   │   └── mod.rs                 # Module declaration for obfuscation
│
│   ├── plugin/                    # General plugin system for extending core functionality
│   │   ├── loader.rs              # Dynamically loads plugins
│   │   └── mod.rs                 # Module declaration
│
│   ├── tunneling/                # Handles system-level tunneling and routing
│   │   ├── device.rs              # Interface to virtual network devices (e.g., TUN/TAP)
│   │   ├── mod.rs                 # Module declaration
│   │   └── routing.rs             # Routing table manipulation and setup
│
│   ├── utils/                    # Common utility functions and helpers
│   │   ├── common.rs              # Generic helper functions
│   │   ├── error.rs               # Error handling utilities
│   │   ├── logging.rs             # Logging setup and macros
│   │   ├── metrics.rs             # Metrics collection and telemetry
│   │   └── mod.rs                 # Module declaration
│
│   └── main.rs                   # Main entry point of the application
│
├── tests/                        # Integration and unit tests
│   ├── encryption.rs             # Tests for encryption and key handling
│   ├── obfuscation.rs            # Tests for obfuscation modules
│   └── transport.rs              # Tests for transport layers
│
├── Cargo.lock                   # Cargo lock file (exact dependency versions)
├── Cargo.toml                   # Cargo manifest file (project metadata and dependencies)
├── LICENSE                      # License file
├── README.md                    # Project overview and usage instructions
├── structMaybe.txt              # (Possibly) Proposed or alternative project structure
├── structNew.txt                # Newer version of the project structure
├── structOLD.txt                # Original/older project structure
```

## levels of cliInterface

- first: Minimum, only important info
- second: minimum with details
- third: just comfort interface  
- fourth: most similar to GUI

---

---
## installation && building [COMMING SOON]

### cloning repository 
```bash
git clone https://github.com/Flaykky/rustVPN-core
cd rustVPN-core
```


### requirments
- rustc 
- libaries in cargo.toml

### building

for linux:

```bash
./install_linux.sh
```

for windows (64, x86): 

```powershell
./install_win64.sh
```



## Basic WireGuard tunneling
```bash
./vpnCore WireGuard 1.1.1.1:51820 login:pass
```

## Connect through proxy
```bash
./vpnCore --proxy=socks5 tcp 1.1.1.1:443
```

## Json config file template
```json
{
    "protocol": "wireguard",
    "server_ip": "1.1.1.1",
    "server_port": 51820,
    "wireguard_private_key": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIg2fZOk7hKQ=",
    "wireguard_public_key": "xTIBA5rboUvnH4htodDoEj3WZ+barGBCQHbR47hTHA="
}
```

## Help information
```bash
./VpnCore help
```


## TODO

- CLI interfaces ❌
- DPI obfuscations ❌
- wireguard through shadowsocks obfuscation ❌
- http/https/socks4/socks5 proxy support ✔️
- shadowsocks protocol support ✔️
- install_linux , install_win64, install_mac shell scripts for installations ❌
- encryption methods ✔️
- openvpn protocol support ❌

## license 

Distributed under the MIT License. See [LICENSE](LICENSE) file for details.
