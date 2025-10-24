# rustVPN-core

A VPN client in CLI mode for private use, DPI bypassing written in Rust.

## Features
- Works in CLI
- Popular protocols support (wireguard, openVPN, shadowsocks)
- basic DPI bypassing by jitter, fake sni, encrypted DOH and other
- All proxys protocols support
- Many cli-interface modes
- avaible all most secure algorithms of encryption 


## to contributers
all info about project, struct, code base and etc will be in docs/

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
- rust compiler (last version)
- cargo (last version)


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
- [✔️] **docs/** folder with guides
- [ ] **Unit & integration tests**
- [ ] **Examples/** folder


## license 

Distributed under the MIT License. See [LICENSE](LICENSE) file for details.
