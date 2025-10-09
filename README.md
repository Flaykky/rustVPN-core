# rustVPN-core

A VPN client in CLI mode for private use, DPI bypassing written in rust.

## Features
- Works in CLI
- Popular protocols support (wireguard, openVPN, shadowsocks)
- basic DPI bypassing by jitter, fake sni, encrypted DOH and other
- All proxys protocols support
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
- rust compiler 
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




## Connect through proxy
```bash
./vpnCore --proxy=https tcp 1.1.1.1:443
```

Help information
```bash
./VpnCore help
```


## TODO

### 🟢 Priority 1: Core & Foundation
- [ ] **CLI interfaces**
  - [✔️] 1. Minimal mode
  - [ ] 2. Detailed mode (maybe remove)
  - [ ] 3. Clean mode (maybe remove)
  - [ ] 4. GUI-like mode (TUI with ratatui)
- [ ] **Configuration system**
  - [✔️] Config loading (TOML/YAML/JSON)
  - [ ] Profile management
  - [ ] Remote config fetching
- [ ] **Core VPN lifecycle**
  - [ ] Connection manager
  - [ ] State tracking
  - [ ] Graceful startup/shutdown
- [ ] **Logging & metrics**
  - [✔️] Structured logging (tracing)
  - [ ] Performance metrics (bandwidth, latency)
  - [ ] Error reporting

## 🟡 Priority 2: Protocols & Obfuscation
- [✔️] **WireGuard protocol support** (MVP)
- [✔️] **Shadowsocks protocol support** (MVP)
- [ ] **OpenVPN protocol support**
- [ ] **VLESS + Reality protocol support** (with xray-core integration)
- [ ] **DPI evasion & obfuscation**
  - [ ] Packet fragmentation
  - [ ] Header masquerading
  - [ ] Timing delays/jitter
  - [ ] Protocol shifting
- [ ] **WireGuard through Shadowsocks** (obfuscation wrapper)
- [✔️] **Proxy support**
  - [✔️] HTTP/HTTPS proxy
  - [✔️] SOCKS4/5 proxy
- [ ] **Custom DNS resolver**

## 🔵 Priority 3: Security & Privacy
- [ ] **Kill-switch for Unix/Windows**
- [ ] **Quantum-resistant encryption** (future-ready)
- [ ] **Secure key storage**
- [ ] **Certificate pinning**
- [ ] **IP leak protection**
- [ ] **split tunneling**

## 🟠 Priority 4: Deployment & Platforms
- [ ] **Installation scripts**
  - [ ] `install_linux.sh`
  - [ ] `install_win64.ps1`
  - [ ] `install_mac.sh`
- [ ] **Cross-platform TUN/TAP** (Linux, macOS, Windows)
- [ ] **Android support** (via Termux)
- [ ] **Docker image**
- [ ] **CI/CD pipeline**

## 🟣 Priority 5: Advanced Features
- [ ] **Plugin system** (for custom protocols/obfuscations)
- [ ] **Server-side software** (rustVPN-server)
- [ ] **Auto-update mechanism**
- [ ] **QR code generator** for config sharing
- [ ] **Performance benchmarks**

## 🟤 Priority 6: Documentation & Testing
- [ ] **README.md**
- [ ] **CONTRIBUTING.md**
- [ ] **docs/** folder with guides
- [ ] **Unit & integration tests**
- [ ] **Examples/** folder


## license 

Distributed under the MIT License. See [LICENSE](LICENSE) file for details.
