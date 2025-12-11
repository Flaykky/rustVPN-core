# obfuscations.md — DPI Evasion Mechanisms

This document provides a technical overview of Deep Packet Inspection (DPI)–based censorship and evasion mechanisms, focusing primarily on Russia's network filtering system from 2012 to 2025.  
It aims to serve as reference material for developers of VPN clients and network researchers analyzing the evolution of censorship and obfuscation.

---

## 1. History of DPI and Internet Control in Russia (2012–2025)

### 2012–2014 — Legal foundations for content filtering
- **2012:** Russia introduced the Unified Register of Prohibited Websites (`Единый реестр запрещённых сайтов`), managed by **Roskomnadzor (RKN)**.  
  Initially, blocking was domain- or IP-based and targeted child protection, drug-related content, and extremist materials.
- **2013–2014:** Mandatory **ISP-level filtering infrastructure** began forming.  
  Providers were required to deploy filtering systems capable of blocking IPs and URLs from the RKN registry.

### 2015–2017 — Start of centralized technical control
- **2015:** The “Yarovaya Law” introduced new surveillance obligations (data retention, interception, SORM upgrades).  
- **2016–2017:** RKN began experimenting with **DNS and HTTP-based filtering**, gradually requiring ISPs to install DPI hardware from vendors like **Protei**, **RDP.ru**, **Norsi-Trans**, and **MFI Soft**.

### 2018 — Telegram blocking attempt
- RKN attempted to block **Telegram** by banning millions of IPs belonging to **Google Cloud** and **Amazon AWS**.  
  This led to massive **collateral damage** (hundreds of unrelated sites and services were disrupted).  
- The attempt failed due to Telegram's **domain fronting** and **frequent IP rotation**, and public backlash eventually forced RKN to lift the ban in **2020**.

### 2019–2020 — Transition to centralized DPI
- Introduction of the **“Sovereign Internet” Law** (2019), mandating ISPs to install **centralized RKN-controlled DPI units** (“technical means of countering threats”).  
  This created a **federated DPI network** across Russian ISPs.  
- Pilot deployments began in Moscow and several regions; initial targets included **proxies**, **anonymizers**, and **Tor nodes**.

### 2021–2022 — DPI maturity and VPN blocking
- RKN expanded its DPI capabilities to detect **VPN protocols** by analyzing TLS handshakes, JA3 fingerprints, and packet timing.  
- **Early 2022:** Mass blocking of commercial VPNs and popular protocols (OpenVPN, L2TP/IPsec, PPTP, SSTP).  
  DPI systems began active probing suspected VPN endpoints.  
- **Summer 2022:** Start of **WireGuard** and **Shadowsocks** detection campaigns; UDP-based protocols became primary targets.

### 2023–2025 — Advanced protocol detection and regional shutdowns
- **2023:** RKN began coordinated blocking of **QUIC**, **DoH/DoT resolvers**, and **Google/Youtube CDN ranges**.
            mass detect of openvpn and wireguard protocols 
  
- **2024:**  
  Some ISPs started injecting **RST packets** or bandwidth throttling for encrypted traffic.  
  Youtube,Discord,Viber blocked
  
- **2025:** DPI upgraded with **active traffic shaping and AI-assisted classification**.  
  IP blocking extended to major hosting providers (Hetzner, OVH, DigitalOcean, AEZA, etc.).  
  Laws introduced fines for searching “extremist” content, with additional penalties if VPN use is detected.
  Reports of **mobile internet shutdowns** outside Moscow and selective **whitelisting** (only VK, Yandex, Gosuslugi and other pro-government/government's services).
  Telegram and WhatsApp **voice/video calls** were intermittently blocked using DPI pattern detection.

late 2025:

whatsapp block (slowing down)
roblox, facetime, snapchat block.
**myth about RKN successfully detected VLESS protocol**

---

## 2. Current DPI Mechanisms in Russia (as of 2025)

| Type | Technique | Notes |
|------|------------|-------|
| **Protocol fingerprinting** | JA3/JA3S (TLS), packet timing, QUIC/HTTP3 fingerprinting | Used to detect VPN frameworks (OpenVPN, WireGuard, V2Ray, Shadowsocks). |
| **Active probing** | DPI connects to suspicious IPs/ports and tests handshake patterns | Known to target Shadowsocks, V2Ray, WireGuard servers. |
| **DNS & SNI filtering** | Blocking by domain name, Server Name Indication (SNI), or DNS responses | Common for domain-based censorship and HTTPS blocking. |
| **IP range blocking** | Subnet-level bans on hosting providers or CDNs | Often affects legitimate Russian services as collateral. |
| **Rate limiting / Throttling** | Bandwidth reduction for encrypted traffic | Used when direct blocking is not feasible. |
| **Regional shutdowns / whitelisting** | Complete internet shutdown with few allowed sites | Observed in several regions during protests or maintenance. |

---

## 3. Known Working Evasion Techniques (2024–2025)

| Mechanism | Description | Status |
|------------|-------------|--------|
| **WireGuard-over-QUIC (Mullvad)** | Encapsulates WireGuard UDP in QUIC/HTTP3 | Reported stable and stealthy. |
| **VLESS + Reality (Xray-core)** | Uses TLS mimicry with browser-like fingerprints (uTLS) and “reality” handshake | Currently one of the most effective methods. |
| **GoodbyeDPI / zapret** | Local packet filtering tool that modifies TCP streams to bypass censorship at the client side | Works partially, mostly against SNI/DNS blocking. |
| **UDP-over-TCP tunnel** | Wraps UDP traffic (WireGuard) inside TCP stream | Deprecated — easy to detect and throttle. |
| **Shadowsocks (simple-obfs, v2ray-plugin)** | Encrypted proxy protocol; simple obfuscation no longer effective | Detected by active probing since ~semptember of 2025. |
| **Tor with obfs4 / meek bridges** | Bridges use domain fronting or TLS mimicry | Still works intermittently; bridge IPs often blacklisted. |

---

## 4. Hosting and Infrastructure Notes

When deploying VPN or proxy infrastructure in Russia-targeted environments:
- Avoid IP ranges of **major hosting providers** (Hetzner, OVH, Azure, AWS, Google Cloud, AEZA).  
  These are regularly scanned and blocked.
- Prefer **smaller VPS providers** registered outside *Five Eyes / Nine Eyes* jurisdictions (e.g., Iceland, Malaysia, Finland, or some EU micro-hosters).
- Use **DNS-01 ACME certificates (Let’s Encrypt)** to obtain valid TLS without open ports.
- Serve **normal HTTPS web content** on your domain to make it appear legitimate.
- Implement **uTLS fingerprint randomization** and **TLS 1.3 with ALPN = "h2" / "http/1.1"** for realistic traffic patterns.

---

## 5. Observed Trends

- DPI detection increasingly relies on **behavioral and statistical patterns**, not just packet signatures.  
- **Active probing** is automated and continuous: IPs of known VPN endpoints are rechecked daily.
- **Mobile ISPs** use **layer-7 filtering** and **policy-based routing** to enforce regional whitelists.
- **Collateral blocking** remains a problem — banking apps, game servers, and CDN assets are often disrupted.

---

## 6. References (technical and open sources)

- Roskomsvoboda reports (2012–2024)  
- MullvadVPN, ProtonVPN transparency reports  
- OONI (Open Observatory of Network Interference) data  
- RDP.ru, Norsi-Trans DPI product documentation (public marketing material)  
- Telegram blocking case studies (2018–2020)  
- IETF drafts: [MASQUE](https://datatracker.ietf.org/wg/masque/documents/), [ECH](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)  

---

_Last updated: November 2025_


