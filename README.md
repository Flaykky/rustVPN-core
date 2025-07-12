# rustVPN-core

A full VPN client in CLI mode, 

(core means only logic of connecting)

## Features
- Basic TCP&UDP tunneling
- Connect with HTTPS proxies
- Cross-platform support (Windows/Linux)
- obfuscation (udp over tcp, comming soon: mine own obfuscation against dpi)
- Shadowsocks protocol support
- PFS support
- WireGuard protocol support
- smart defence against DPI

## Struct of project
```text
src/
├── connection/
│ ├── protocols/
│ │ ├── proxy/
│ │ │ ├── http.rs # HTTP proxy implementation
│ │ │ ├── https.rs # HTTPS proxy implementation
│ │ │ ├── socks4.rs # SOCKS4 proxy implementation
│ │ │ ├── socks5.rs # SOCKS5 proxy implementation
│ │ │ └── mod.rs # Exports proxy modules
│ │ ├── wireguard.rs # WireGuard protocol implementation
│ │ ├── shadowsocks.rs # Shadowsocks protocol implementation
│ │ ├── openvpn.rs # OpenVPN protocol implementation
│ │ ├── basic_tcp.rs # Generic TCP-based tunneling
│ │ ├── basic_udp.rs # Generic UDP-based tunneling
│ │ ├── plugin.rs # Plugin interface for custom protocols
│ │ └── mod.rs # Exports protocol modules
│ ├── manager.rs # Manages connection lifecycle (start, stop, reconnect)
│ └── mod.rs # Exports connection modules
├── tunneling/
│ ├── device.rs # Manages TUN/TAP virtual network interfaces
│ ├── routing.rs # Configure OS routing tables and split tunneling
│ └── mod.rs # Exports tunneling modules
├── obfuscation/
│ ├── dpi_bypass/
│ │ ├── fragment.rs # Packet fragmentation to bypass DPI
│ │ ├── masquerade.rs # Protocol masquerade (e.g. HTTPS)
│ │ ├── timing.rs # Random delays between packets
│ │ ├── chain.rs # Chain DPI Bypasses (composite pattern)
│ │ └── mod.rs # Export DPI Bypass modules
│ ├── protocol_obfuscation/
│ │ ├── tunnel.rs # Tunneling (e.g. Shadowsocks via WireGuard)
│ │ ├── header.rs # Header obfuscation (e.g. SIP003/SIP022)
│ │ ├── encryption.rs # Additional encryption (e.g. AEAD)
│ │ └── mod.rs # Export protocol obfuscations
│ ├── timing/
│ │ ├── jitter.rs # Randomize intervals between packets
│ │ ├── delay.rs # Artificial delay before sending
│ │ └── mod.rs # Export timing modules
│ ├── plugin/
│ │ ├── loader.rs # Dynamic loading of plugins (v2ray-plugin, etc.)
│ │ ├── interface.rs # Interface for plugins
│ │ └── mod.rs # Export plugin modules
│ ├── preset/
│ │ ├── basic.rs # Basic profiles (HTTP/HTTPS)
│ │ ├── advanced.rs # Advanced profiles (SIP003, AEAD, DPI-Bypass)
│ │ ├── custom.rs # Custom profiles
│ │ └── mod.rs # Profile export
│ ├── utils/
│ │ ├── packet.rs # Utilities for working with packets
│ │ ├── crypto.rs # Auxiliary cryptographic functions
│ │ └── mod.rs # Utilities export
│ ├── common.rs # Common types and errors for obfuscation
│ └── mod.rs # Global export of all modules
├── encryption/
│ ├── cipher.rs # Manages encryption algorithms (AES, ChaCha20)
│ ├── key_manager.rs # Handles key generation and rotation
│ └── mod.rs # Exports encryption modules
├──config/
│ ├── parser.rs # Parses and validates JSON config files
│ ├── model.rs # Structs for config representation
│ └── mod.rs # Exports config modules
├──utils/
│ ├── logging.rs # Configures logging with levels and formats
│ ├── metrics.rs # Collects connection stats (bandwidth, latency)
│ ├── error.rs # Custom error types
│ ├── common.rs # Shared utilities (e.g., IP parsing, base64 helpers)
│ └── mod.rs # Exports utility modules
├──cli/
│ ├── commands.rs # CLI command definitions (connect, add-server, etc.)
│ ├── interface.rs # CLI argument parsing and interaction
│ └── mod.rs # Exports CLI modules
├── plugin/
│ ├── loader.rs # Dynamically loads protocol/obfuscation plugins
│ └── mod.rs # Exports plugin modules
└── main.rs # Entry point for CLI application
```

## levels of cliInterface

- first: Minimum, only important info
- second: minimum with details
- third: just comfort interface  
- fourth: most similar to GUI

---

### **1. Minimal interface**

```bash
[VPN Status] → Connected
[Server] → 🇨🇭 Switzerland
[Protocol] → WireGuard
[IP in/out] → 1.1.1.1:443 → 1.1.1.2

[Net] ↑ 100KB ↓ 250KB Speed: ~50mb/s
```

**Controls:**

* `vpn connect` / `vpn disconnect`
* `vpn status`
* `vpn switch --server=Switzerland`

---

### **2. Almost minimal but nice interface with details**

```bash
╭─[VPN]─ ... 1.1.1.1:443 │
│ Exit IP: 1.1.1.2 │
│ Obfuscation : ✅ Shadowsocks │
│ Custom DNS: ✅ 1.1.1.1 │
├────────────────────────── ───────────────────────────┤
│ ↑ Uploaded : 125KB │
│ ↓ Downloaded : 3.2MB │
│ ↔ Speed: ~75mb/s │
╰─ ...��
```

---

### **3. Just a nice CLI interface**

```bash
┌─ ... │
├────────────────────── ──────────────────────┤
│ [✓] Connected │
│ │
│ 🔹 Server: 🇬🇧 UK, London │
│ 🔹 Protocol: OpenVPN TCP │
│ 🔹 Entry IP: 2.1.1.1:1300 │
│ 🔹 Exit IP: 2.1.1.2 │
│ │
│ ⚙ Features: │
│ [+] Custom DNS: 8.8.8.8 │
│ [+] Obfuscation: Disabled │
│ │
│ 📈 Data: │
│ ↑ 120KB ↓ 300KB ~60mb/s │
└────────────────────────────────────────────┘
```

---

### **4. GUI-like CLI interface**

```bash
┌─────────────────────────────┐
│ [main page] [servers] │
│ [about] │
└────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ VPN STATUS: CONNECTED ┃
┃ ┃
┃ Server: 🇨🇭 Switzerland ┃
┃ Protocol: WireGuard ┃
┃ Entry IP: 1.1.1.1:443 ┃
┃ Exit IP: 1.1.1.2 ┃
┃ ┃
┃ [+] Obfuscation: Yes ┃
┃ [+] Custom DNS: 1.1.1.1 ┃
┃ [+] Quantum-Resistant: ❌┃
┃ ┃
┃ Network Data: ┃
┃ ↑ Uploaded : 100KB ┃
┃ ↓ Downloaded : 0KB ┃
┃ ↔ Speed : [speedTest] ┃
━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

#### 🔄 Navigation:

* `Tab`/`← →` — between \[main page], \[servers], \[about], \[speedTest]
* `↑ ↓` — scroll by elements
* `Enter` — activation

---

#### 📄 Page `servers`

```bash
┌──────────────────────────── ────────────────────────────┐
│ [servers page] [back] │
└──────────────────────────── ────────────────────────────┘

1.Server: 
├ Location: 🇨🇭 Switzerland, Zurich 
├ Entry IP: 1.1.1.1:51902 
├ Exit IP: 1.1.1.2 
├Protocol: WireGuard 
└Features: 
[+] Custom DNS: 1.1.1.1 
[+] Obfuscation: Shadowsocks 
[+] Quantum Resistant: ✅

2.Server: 
├ Location: 🇬🇧 UK, London 
├ Entry IP: 2.1.1.1:1300 
├ Exit IP: 2.1.1.2 
└ Protocol: OpenVPN TCP

3.Server: 
├ Location: 🇩🇪 Germany, Frankfurt 
├ Entry IP: 2.2.1.1:443 
├ Exit IP: 2.2.1.3 
└Protocol: V2rayN
```

---

#### ℹ️ `about` page

```bash
┌────────────────────────────┐
│ [about page] [back] │
└────────────────────────────┘

release: beta 1.0

📎 GitHub Repository:
https://github.com/Flaykky/rustVPN-core

```

---
## installation && building

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

- CLI interface ❌
- DPI obfuscations ❌
- wireguard through shadowsocks obfuscation ❌
- http/https/socks4/socks5 proxy support ✔️
- shadowsocks protocol support ✔️
- install_linux , install_win64, install_mac bash scripts for installations ❌
- encryption methods ❌
- openvpn protocol support ❌

## license 

Distributed under the MIT License. See [LICENSE](LICENSE) file for details.
