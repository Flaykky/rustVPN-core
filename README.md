# rustVPN-core

A full VPN client in CLI mode for private use written in rust.

## Features
- Works in CLI
- Popular protocols support (wireguard, openVPN, shadowsocks)
- DPI bypassing by obfuscations (udp2raw)
- all proxys support
- Many cli-interface modes
- avaible all most secure algorithms of encryption 


## Struct of project
```text
rustVPN-core/
├── src                                  # Main source code directory
│   ├── cli                              # Command-line interface logic
│   │   ├── handler.rs                   # Handles CLI commands and dispatches actions
│   │   ├── interface.rs                 # Defines CLI input/output interfaces
│   │   ├── mod.rs                       # CLI module entry point
│   │   └── output.rs                    # Formatting and displaying CLI output
│   ├── config                           # Configuration management
│   │   ├── loader.rs                    # Loads configuration files from disk or remote
│   │   ├── mod.rs                       # Config module entry point
│   │   ├── model.rs                     # Configuration data structures and types
│   │   └── parser.rs                    # Parses config files (e.g., TOML, YAML, JSON)
│   ├── connection                       # Connection setup and management
│   │   ├── protocols                    # Supported VPN protocols
│   │   │   ├── mod.rs                   # Protocols module entry point
│   │   │   ├── openvpn.rs               # OpenVPN protocol implementation
│   │   │   ├── plugin.rs                # Protocol plugin interface
│   │   │   ├── shadowsocks.rs           # Shadowsocks protocol implementation
│   │   │   └── wireguard.rs             # WireGuard protocol implementation
│   │   ├── proxy                        # Proxy protocol support
│   │   │   ├── http.rs                  # HTTP proxy support
│   │   │   ├── https.rs                 # HTTPS proxy support
│   │   │   ├── mod.rs                   # Proxy module entry point
│   │   │   ├── socks4.rs                # SOCKS4 proxy implementation
│   │   │   └── socks5.rs                # SOCKS5 proxy implementation
│   │   ├── transport                    # Transport layer implementations
│   │   │   ├── mod.rs                   # Transport module entry point
│   │   │   ├── quic.rs                  # QUIC transport support
│   │   │   ├── tcp.rs                   # TCP transport support
│   │   │   └── udp.rs                   # UDP transport support
│   │   ├── manager.rs                   # Manages active connections and sessions
│   │   └── mod.rs                       # Connection module entry point
│   ├── core                             # Core VPN control logic
│   │   ├── controller.rs                # Main control and coordination logic
│   │   ├── lifecycle.rs                 # Application lifecycle handling
│   │   ├── mod.rs                       # Core module entry point
│   │   └── state.rs                     # Global state management
│   ├── encryption                       # Encryption and cryptography
│   │   ├── cipher                       # Cipher algorithms
│   │   │   ├── aes                      # AES encryption modes
│   │   │   │   ├── cfb.rs               # AES-CFB mode implementation
│   │   │   │   ├── gcm.rs               # AES-GCM mode implementation
│   │   │   │   ├── mod.rs               # AES module entry point
│   │   │   │   └── pmac-siv.rs          # AES-PMAC-SIV mode implementation
│   │   │   └── stream                   # Stream cipher algorithms
│   │   │       ├── chacha.rs            # ChaCha/ChaCha20 implementation
│   │   │       ├── mod.rs               # Stream ciphers module entry point
│   │   │       ├── rc4.rs               # RC4 stream cipher
│   │   │       └── salsa.rs             # Salsa20 stream cipher
│   │   ├── key                          # Key management
│   │   │   ├── kdf.rs                   # Key derivation functions
│   │   │   ├── manager.rs               # Key manager for encryption/decryption
│   │   │   ├── mod.rs                   # Key module entry point
│   │   │   └── store.rs                 # Secure key storage
│   │   ├── cipher.rs                    # Unified cipher interface
│   │   ├── error.rs                     # Encryption-related error definitions
│   │   ├── key_manager.rs               # High-level key manager wrapper
│   │   ├── mod.rs                       # Encryption module entry point
│   │   └── traits.rs                    # Traits for cipher and encryption interfaces
│   ├── obfuscation                      # Traffic obfuscation and anti-censorship
│   │   ├── dpi                          # Deep Packet Inspection evasion techniques
│   │   │   ├── fragment.rs              # Packet fragmentation
│   │   │   ├── masquerade.rs            # Protocol masquerading
│   │   │   ├── mod.rs                   # DPI module entry point
│   │   │   ├── protocol_shift.rs        # Protocol shifting to avoid detection
│   │   │   └── timing.rs                # Timing obfuscation techniques
│   │   ├── plugin                       # Obfuscation plugin support
│   │   │   ├── interface.rs             # Plugin interface definition
│   │   │   ├── loader.rs                # Loads obfuscation plugins
│   │   │   └── mod.rs                   # Plugin module entry point
│   │   ├── preset                       # Predefined obfuscation presets
│   │   │   ├── advanced.rs              # Advanced obfuscation presets
│   │   │   ├── basic.rs                 # Basic obfuscation presets
│   │   │   ├── custom.rs                # User-defined obfuscation presets
│   │   │   └── mod.rs                   # Preset module entry point
│   │   ├── protocol                     # Obfuscation protocol implementations
│   │   │   ├── encryption.rs            # Encrypted obfuscation protocol
│   │   │   ├── header.rs                # Protocol header modifications
│   │   │   ├── mod.rs                   # Protocol module entry point
│   │   │   └── tunnel.rs                # Tunneling obfuscation protocol
│   │   ├── timing                       # Timing control for obfuscation
│   │   │   ├── delay.rs                 # Adds packet delays
│   │   │   ├── jitter.rs                # Adds jitter to packet timing
│   │   │   └── mod.rs                   # Timing module entry point
│   │   ├── utils                        # Obfuscation utilities
│   │   │   ├── crypto.rs                # Helper cryptographic functions
│   │   │   ├── mod.rs                   # Utils module entry point
│   │   │   └── packet.rs                # Packet manipulation helpers
│   │   ├── wrappers                     # Wrappers for transport conversions
│   │   │   ├── mod.rs                   # Wrappers module entry point
│   │   │   ├── quic-wrap.rs             # Wraps QUIC in another protocol
│   │   │   ├── udp2raw.rs               # UDP to raw socket wrapper
│   │   │   └── wireguard2tcp.rs         # Wraps WireGuard in TCP
│   │   ├── common.rs                    # Common obfuscation utilities
│   │   └── mod.rs                       # Obfuscation module entry point
│   ├── plugin                           # General plugin system
│   │   ├── loader.rs                    # Loads external plugins
│   │   └── mod.rs                       # Plugin system entry point
│   ├── tunneling                        # OS-level tunneling support
│   │   ├── device.rs                    # Virtual network device control
│   │   ├── mod.rs                       # Tunneling module entry point
│   │   └── routing.rs                   # VPN routing configuration
│   ├── utils                            # General utilities
│   │   ├── common.rs                    # Common helper functions
│   │   ├── error.rs                     # Global error definitions
│   │   ├── logging.rs                   # Logging utilities
│   │   ├── metrics.rs                   # Performance and usage metrics
│   │   └── mod.rs                       # Utils module entry point
│   └── main.rs                          # Main entry point of the application
├── tests                                # Integration and unit tests
│   ├── encryption.rs                    # Tests for encryption module
│   ├── obfuscation.rs                   # Tests for obfuscation module
│   └── transport.rs                     # Tests for transport module
├── Cargo.lock                           # Cargo dependency lockfile
├── Cargo.toml                           # Project manifest
├── LICENSE                              # License information
├── README.md                            # Project documentation
├── structNew.txt                        # New structure proposal
└── structOLD.txt                        # Old structure reference

```

## modes of cli interface

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
- libaries that pointed in cargo.toml

### building

for linux:

```bash
./install_linux.sh
```

for windows (64, x86): 

```powershell
./install_win64.bat
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

- CLI interfaces ❌ (1 done) 
- DPI obfuscations ❌
- wireguard through shadowsocks obfuscation ❌
- http/https/socks4/socks5 proxy support ✔️
- shadowsocks protocol support ✔️
- install_linux , install_win64, install_mac shell scripts for installation ❌
- most popular encryption methods ✔️
- openvpn protocol support ❌
- killswitch for unix/windows ❌

## license 

Distributed under the MIT License. See [LICENSE](LICENSE) file for details.
