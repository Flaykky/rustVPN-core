# contributing 

## struct of project:

```text
rustVPN-core/
├── docs
│   └── contributing.md
├── src
│   ├── bin
│   │   ├── rustVPN-core-server.rs
│   │   └── rustVPN-core.rs
│   ├── cli
│   │   ├── handlers
│   │   │   ├── connect_handler.rs
│   │   │   ├── disconnect_handler.rs
│   │   │   ├── mod.rs
│   │   │   └── server__handler.rs
│   │   ├── interface
│   │   │   ├── components
│   │   │   │   ├── input_fields.rs
│   │   │   │   ├── mod.rs
│   │   │   │   ├── server_card.rs
│   │   │   │   └── status_bar.rs
│   │   │   ├── about_page.rs
│   │   │   ├── main_page.rs
│   │   │   ├── mod.rs
│   │   │   ├── servers_page.rs
│   │   │   └── settings_page.rs
│   │   ├── app.rs
│   │   ├── commands.rs
│   │   └── mod.rs
│   ├── config
│   │   ├── presets
│   │   │   ├── mod.rs
│   │   │   ├── openvpn.rs
│   │   │   ├── shadowsocks.rs
│   │   │   └── wireguard.rs
│   │   ├── loader.rs
│   │   ├── mod.rs
│   │   ├── models.rs
│   │   ├── parser.rs
│   │   └── validator.rs
│   ├── core
│   │   ├── connection_manager.rs
│   │   ├── controller.rs
│   │   ├── event_bus.rs
│   │   ├── mod.rs
│   │   ├── plugin_manager.rs
│   │   └── state.rs
│   ├── encryption
│   │   ├── algorithms
│   │   │   ├── asymmetric
│   │   │   │   ├── curve25519
│   │   │   │   │   ├── ed25519.rs
│   │   │   │   │   ├── mod.rs
│   │   │   │   │   └── x25519.rs
│   │   │   │   ├── ecdh
│   │   │   │   │   ├── custom.rs
│   │   │   │   │   ├── mod.rs
│   │   │   │   │   ├── secp256k1.rs
│   │   │   │   │   └── secp256r1.rs
│   │   │   │   ├── ecdsa
│   │   │   │   │   ├── mod.rs
│   │   │   │   │   ├── secp256k1.rs
│   │   │   │   │   └── secp256r1.rs
│   │   │   │   ├── post-quantum
│   │   │   │   │   ├── dilithium
│   │   │   │   │   │   ├── dilithium2.rs
│   │   │   │   │   │   ├── dilithium3.rs
│   │   │   │   │   │   ├── dilithium5.rs
│   │   │   │   │   │   └── mod.rs
│   │   │   │   │   └── kyber
│   │   │   │   │       ├── kyber1024.rs
│   │   │   │   │       ├── kyber512.rs
│   │   │   │   │       ├── kyber768.rs
│   │   │   │   │       └── mod.rs
│   │   │   │   ├── rsa
│   │   │   │   │   ├── mod.rs
│   │   │   │   │   ├── rsa_2048.rs
│   │   │   │   │   ├── rsa_3072.rs
│   │   │   │   │   └── rsa_4096.rs
│   │   │   │   └── mod.rs
│   │   │   └── symmetric
│   │   │       ├── aes
│   │   │       │   ├── aes_128
│   │   │       │   │   ├── cbc.rs
│   │   │       │   │   ├── cfb.rs
│   │   │       │   │   ├── ecb.rs
│   │   │       │   │   ├── gcm.rs
│   │   │       │   │   ├── mod.rs
│   │   │       │   │   └── pmac_siv.rs
│   │   │       │   └── aes_256
│   │   │       │       ├── cbc.rs
│   │   │       │       ├── cfb.rs
│   │   │       │       ├── ecb.rs
│   │   │       │       ├── gcm.rs
│   │   │       │       ├── mod.rs
│   │   │       │       └── pmac_siv.rs
│   │   │       ├── chacha
│   │   │       │   ├── chaсha20-ietf-poly1305.rs
│   │   │       │   ├── chacha20-ietf.rs
│   │   │       │   ├── mod.rs
│   │   │       │   └── xchacha20-ietf-poly1305.rs
│   │   │       ├── salsa
│   │   │       │   ├── mod.rs
│   │   │       │   ├── salsa20.rs
│   │   │       │   └── xsalsa20.rs
│   │   │       ├── stream
│   │   │       │   ├── custom.rs
│   │   │       │   ├── mod.rs
│   │   │       │   └── rc4.rs
│   │   │       └── mod.rs
│   │   ├── cipher
│   │   │   ├── modes
│   │   │   │   ├── cbc.rs
│   │   │   │   ├── ccm.rs
│   │   │   │   ├── cfb.rs
│   │   │   │   ├── ecb.rs
│   │   │   │   ├── gcm.rs
│   │   │   │   └── mod.rs
│   │   │   ├── aead.rs
│   │   │   ├── block.rs
│   │   │   ├── mod.rs
│   │   │   └── stream.rs
│   │   ├── handshake
│   │   │   ├── dh.rs
│   │   │   ├── mod.rs
│   │   │   ├── noise.rs
│   │   │   ├── tls.rs
│   │   │   └── x25519.rs
│   │   ├── key
│   │   │   ├── derivation
│   │   │   │   ├── argon2.rs
│   │   │   │   ├── hkdf.rs
│   │   │   │   ├── mod.rs
│   │   │   │   ├── pbkdf.rs
│   │   │   │   └── scrypt.rs
│   │   │   ├── formats
│   │   │   │   ├── der.rs
│   │   │   │   ├── mod.rs
│   │   │   │   ├── pem.rs
│   │   │   │   └── raw.rs
│   │   │   ├── exchange.rs
│   │   │   ├── manager.rs
│   │   │   ├── mod.rs
│   │   │   └── storage.rs
│   │   ├── random
│   │   │   ├── entropy.rs
│   │   │   ├── mod.rs
│   │   │   └── secure.rs
│   │   ├── tests
│   │   │   ├── asymmetric_tests.rs
│   │   │   ├── key_exchange_tests.rs
│   │   │   ├── mod.rs
│   │   │   └── symmetric_tests.rs
│   │   ├── utils
│   │   │   ├── conversion.rs
│   │   │   ├── mod.rs
│   │   │   ├── padding.rs
│   │   │   └── timing.rs
│   │   ├── error.rs
│   │   ├── mod.rs
│   │   └── traits.rs
│   ├── network
│   │   ├── dns
│   │   │   ├── doh.rs
│   │   │   ├── dot.rs
│   │   │   ├── mod.rs
│   │   │   └── resolver.rs
│   │   ├── firewall
│   │   │   ├── mod.rs
│   │   │   ├── unix.rs
│   │   │   └── windows.rs
│   │   ├── transport
│   │   │   ├── mod.rs
│   │   │   ├── quic.rs
│   │   │   ├── tcp.rs
│   │   │   ├── udp.rs
│   │   │   └── websocket.rs
│   │   ├── tunnel
│   │   │   ├── device.rs
│   │   │   ├── mod.rs
│   │   │   └── routing.rs
│   │   └── mod.rs
│   ├── obfuscation
│   ├── protocols
│   │   ├── base
│   │   │   ├── connection.rs
│   │   │   ├── error.rs
│   │   │   ├── mod.rs
│   │   │   └── traits.rs
│   │   ├── openvpn
│   │   │   ├── client.rs
│   │   │   ├── crypto.rs
│   │   │   ├── mod.rs
│   │   │   └── server.rs
│   │   ├── shadowsocks
│   │   │   ├── client.rs
│   │   │   ├── crypto.rs
│   │   │   ├── mod.rs
│   │   │   └── server.rs
│   │   ├── trojan
│   │   │   ├── client.rs
│   │   │   ├── crypto.rs
│   │   │   └── mod.rs
│   │   ├── vless
│   │   │   ├── client.rs
│   │   │   ├── mod.rs
│   │   │   ├── reality.rs
│   │   │   └── tls.rs
│   │   ├── wireguard
│   │   │   ├── client.rs
│   │   │   ├── crypto.rs
│   │   │   ├── handshake.rs
│   │   │   ├── mod.rs
│   │   │   └── server.rs
│   │   └── mod.rs
│   ├── proxy
│   │   ├── forwarder.rs
│   │   ├── http.rs
│   │   ├── https.rs
│   │   ├── mod.rs
│   │   ├── socks4.rs
│   │   └── socks5.rs
│   ├── system
│   │   ├── platform
│   │   │   ├── android.rs
│   │   │   ├── mod.rs
│   │   │   ├── unix.rs
│   │   │   └── windows.rs
│   │   ├── service
│   │   │   ├── mod.rs
│   │   │   ├── unix.rs
│   │   │   └── windows.rs
│   │   ├── killswitch.rs
│   │   ├── mod.rs
│   │   └── permissions.rs
│   ├── utils
│   │   ├── error.rs
│   │   ├── helpers.rs
│   │   ├── logging.rs
│   │   ├── metrics.rs
│   │   ├── mod.rs
│   │   └── validation.rs
│   ├── lib.rs
│   └── main.rs
├── .gitignore
├── Cargo.lock
├── Cargo.toml
└── readme.md
```

src/obfuscation isn't completed yet


## dependencies

info about all dependencies that used in this project

