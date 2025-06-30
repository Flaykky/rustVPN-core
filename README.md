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
│   ├── protocols/
│   │   ├── proxy/
│   │   │   ├── http.rs        # HTTP proxy implementation
│   │   │   ├── https.rs       # HTTPS proxy implementation
│   │   │   ├── socks4.rs      # SOCKS4 proxy implementation
│   │   │   ├── socks5.rs      # SOCKS5 proxy implementation
│   │   │   └── mod.rs         # Exports proxy modules
│   │   ├── wireguard.rs       # WireGuard protocol implementation
│   │   ├── shadowsocks.rs     # Shadowsocks protocol implementation
│   │   ├── openvpn.rs         # OpenVPN protocol implementation
│   │   ├── basic_tcp.rs       # Generic TCP-based tunneling
│   │   ├── basic_udp.rs       # Generic UDP-based tunneling
│   │   ├── plugin.rs          # Plugin interface for custom protocols
│   │   └── mod.rs             # Exports protocol modules
│   ├── manager.rs             # Manages connection lifecycle (start, stop, reconnect)
│   └── mod.rs                 # Exports connection modules
├── tunneling/
│   ├── device.rs              # Manages TUN/TAP virtual network interfaces
│   ├── routing.rs             # Configures OS routing tables and split tunneling
│   └── mod.rs                 # Exports tunneling modules
├── obfuscation/
│   ├── dpi_bypass/
│   │   ├── fragment.rs        # Packet fragmentation to evade DPI
│   │   ├── masquerade.rs      # Protocol masquerading (e.g., mimic HTTPS)
│   │   ├── timing.rs          # Randomize packet timing
│   │   └── mod.rs             # Exports DPI bypass modules
│   ├── shadowsocks_over_wg.rs # Shadowsocks tunneled through WireGuard
│   ├── preset.rs              # Predefined obfuscation profiles
│   └── mod.rs                 # Exports obfuscation modules
├── encryption/
│   ├── cipher.rs              # Manages encryption algorithms (AES, ChaCha20)
│   ├── key_manager.rs         # Handles key generation and rotation
│   └── mod.rs                 # Exports encryption modules
├── config/
│   ├── parser.rs              # Parses and validates JSON config files
│   ├── model.rs               # Structs for config representation
│   └── mod.rs                 # Exports config modules
├── utils/
│   ├── logging.rs             # Configures logging with levels and formats
│   ├── metrics.rs             # Collects connection stats (bandwidth, latency)
│   ├── error.rs               # Custom error types
│   ├── common.rs              # Shared utilities (e.g., IP parsing, base64 helpers)
│   └── mod.rs                 # Exports utility modules
├── cli/
│   ├── commands.rs            # CLI command definitions (connect, add-server, etc.)
│   ├── interface.rs           # CLI argument parsing and interaction
│   └── mod.rs                 # Exports CLI modules
├── plugin/
│   ├── loader.rs              # Dynamically loads protocol/obfuscation plugins
│   └── mod.rs                 # Exports plugin modules
└── main.rs                    # Entry point for CLI application
```

## installation
```bash
git clone https://github.com/Flaykky/rustVPN-core
cd rustVPN-core
./install_linux.sh
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


## TODO:

- CLI interface ❌
- DPI obfuscation ❌
- wireguard through shadowsocks ❌
- http/https/socks4/socks5 proxy support ✔️
- shadowsocks protocol support ✔️
- install_linux , install_win64, install_mac bash scripts ❌

## license 

Distributed under the MIT License. See [LICENSE](LICENSE) file for details.
