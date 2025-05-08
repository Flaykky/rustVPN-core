# rustVPN-core

A minimalistic VPN client for private use.

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

## license 

MIT
