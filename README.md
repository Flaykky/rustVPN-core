# rustVPN-core

A full VPN client in CLI mode.

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
rustVPN-core/
├── src/
│
│   ├── cli/                         # CLI-interfaces
│   │   ├── interface.rs             # Parsing arguments
│   │   ├── handler.rs               # Work with cli commands 
│   │   ├── output.rs                # Format output and etc
│   │   └── mod.rs
│
│   ├── core/                        # Main logic
│   │   ├── controller.rs            # Start/stop VPN
│   │   ├── state.rs                 # Runtime-status
│   │   ├── lifecycle.rs             # Initialization, graceful shutdown
│   │   └── mod.rs
│
│   ├── config/                      # Load and pars configs
│   │   ├── loader.rs
│   │   ├── parser.rs
│   │   ├── model.rs
│   │   └── mod.rs
│
│   ├── connection/                  # Connections and protocols 
│   │   ├── manager.rs               # Session manager 
│   │   ├── transport/               # Transport 
│   │   │   ├── tcp.rs
│   │   │   ├── udp.rs
│   │   │   ├── quic.rs              # QUIC transport
│   │   │   └── mod.rs
│   │   ├── protocols/               # VPN-protocols 
│   │   │   ├── wireguard.rs
│   │   │   ├── openvpn.rs
│   │   │   ├── shadowsocks.rs
│   │   │   ├── plugin.rs
│   │   │   └── mod.rs
│   │   ├── proxy/                   # Proxy protocols
│   │   │   ├── http.rs
│   │   │   ├── https.rs
│   │   │   ├── socks4.rs
│   │   │   ├── socks5.rs
│   │   │   └── mod.rs
│   │   └── mod.rs
│
│   ├── encryption/                 # Ciphers 
│   │   ├── cipher/                 # AES, ChaCha, AEAD and etc.
│   │   │   ├── aes-128-cfb.rs 
│   │   │   ├── aes-128-cfb1.rs 
│   │   │   ├── aes-128-cfb128.rs 
│   │   │   ├── aes-128-cfb8.rs 
│   │   │   ├── aes-128-gcm.rs 
│   │   │   ├── aes-128-pmac-siv.rs 
│   │   │   ├── aes-256-cfb.rs 
│   │   │   ├── aes-256-cfb1.rs 
│   │   │   ├── aes-256-cfb128.rs 
│   │   │   ├── aes-256-cfb8.rs 
│   │   │   ├── aes-256-gcm.rs 
│   │   │   ├── aes-256-pmac-siv.rs 
│   │   │   ├── cacha20.rs 
│   │   │   ├── cacha20-ietf.rs 
│   │   │   ├── cacha20-ietf-poly1305.rs 
│   │   │   ├── rc4.rs 
│   │   │   ├── rc4-md5.rs 
│   │   │   ├── sasla20.rs 
│   │   │   ├── xcacha20-ietf-poly1305.rs 
│   │   │   └── mod.rs 
│   │   ├── key/                    # KDF, key manager
│   │   │   ├── kdf.rs 
│   │   │   ├── manager.rs
│   │   │   ├── mod.rs 
│   │   │   └── store.rs
│   │   ├── traits.rs
│   │   ├── error.rs
│   │   └── mod.rs
│
│   ├── obfuscation/                # DPI-byoass
│   │   ├── wrappers/               # UDP-over-TCP, udp2raw, obfs4
│   │   │   ├── wireguard2tcp.rs
│   │   │   ├── udp2raw.rs
│   │   │   ├── quic_wrap.rs
│   │   │   └── mod.rs
│   │   ├── dpi/                    # DPI techniques
│   │   │   ├── fragment.rs
│   │   │   ├── protocol_shift.rs
│   │   │   ├── timing.rs
│   │   │   ├── masquerade.rs
│   │   │   └── mod.rs
│   │   ├── plugin/                 # loader third party plugins 
│   │   │   ├── interface.rs
│   │   │   ├── loader.rs
│   │   │   └── mod.rs
│   │   ├── utils/                  # utils 
│   │   │   ├── packet.rs
│   │   │   ├── crypto.rs
│   │   │   └── mod.rs
│   │   └── mod.rs
│
│   ├── tunneling/                  # Virtual devices
│   │   ├── device.rs               # TUN/TAP
│   │   ├── routing.rs              # Tables routes
│   │   └── mod.rs
│
│   ├── plugin/                     # Main plugin API
│   │   ├── loader.rs
│   │   └── mod.rs
│
│   ├── utils/                      # Main utils
│   │   ├── logging.rs                
│   │   ├── error.rs
│   │   ├── metrics.rs
│   │   └── mod.rs
│
│   ├── lib.rs
│   └── main.rs
│
├── Cargo.toml
├── Cargo.lock
├── README.md
└── LICENSE
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
│ [✓] Connected                              │
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
┌────────────────────────────┐
│ [main page]  [servers]     │
│ [about]                    │
└────────────────────────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃ VPN STATUS: CONNECTED     ┃
┃                          ┃
┃ Server: 🇨🇭 Switzerland    ┃
┃ Protocol: WireGuard       ┃
┃ Entry IP: 1.1.1.1:443     ┃
┃ Exit IP:  1.1.1.2         ┃
┃                          ┃
┃ [+] Obfuscation: Yes      ┃
┃ [+] Custom DNS: 1.1.1.1   ┃
┃ [+] Quantum-Resistant: ❌┃
┃                          ┃
┃ Network Data:            ┃
┃   ↑ Uploaded   : 100 KB   ┃
┃   ↓ Downloaded : 0 KB     ┃
┃   ↔ Speed      : [speedTest] ┃
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

```

#### 🔄 Navigation:

* `Tab`/`← →` — between \[main page], \[servers], \[about], \[speedTest]
* `↑ ↓` — scroll by elements
* `Enter` — activation

---

#### 📄 Page `servers`

```bash
┌────────────────────────────────────────────────────────┐
│ [servers page]                              [back]     │
└────────────────────────────────────────────────────────┘

1. Server:
 ├ Location : 🇨🇭 Switzerland, Zurich
 ├ Entry IP : 1.1.1.1:51902
 ├ Exit IP  : 1.1.1.2
 ├ Protocol : WireGuard
 └ Features :
     [+] Custom DNS: 1.1.1.1
     [+] Obfuscation: Shadowsocks
     [+] Quantum Resistant: ✅

2. Server:
 ├ Location : 🇬🇧 UK, London
 ├ Entry IP : 2.1.1.1:1300
 ├ Exit IP  : 2.1.1.2
 └ Protocol : OpenVPN TCP

3. Server:
 ├ Location : 🇩🇪 Germany, Frankfurt
 ├ Entry IP : 2.2.1.1:443
 ├ Exit IP  : 2.2.1.3
 └ Protocol : V2rayN

```



#### ℹ️ `about` page

```bash
┌────────────────────────────┐
│ [about page] [back]        │
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
