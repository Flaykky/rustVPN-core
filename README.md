# rustVPN-core

A full VPN client in CLI mode.

## Features
- Works in CLI
- Popular protocols support (wireguard, openVPN, shadowsocks)
- DPI bypassing by obfuscations
- Proxy support
- Many cli-interface modes

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
│   ├── encryption
│   │   ├── cipher
│   │   │   ├── aes
│   │   │   │   ├── cfb.rs
│   │   │   │   ├── gcm.rs
│   │   │   │   ├── mod.rs
│   │   │   │   └── pmac-siv.rs
│   │   │   └── stream
│   │   │       ├── chacha.rs
│   │   │       ├── mod.rs
│   │   │       ├── rc4.rs
│   │   │       └── salsa.rs
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
