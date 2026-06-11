# Common Use Cases & Scenarios

This guide describes common scenarios where `beam-rs` shines and which mode to use for each.

## 1. No Internet Access (LAN / Air-gapped)
**Scenario**: You need to transfer files without using the public internet, with both machines on the same LAN.

**Solution**: **Local-only Mode** (`beam-rs send --local-only`)
- **Why**: Same iroh transport as the default mode, but with relays disabled. The receiver resolves the sender on the LAN with mDNS and connects directly, so no data leaves your local network and no relay/internet is contacted.
- **Command**:
  ```bash
  # Sender
  beam-rs send --local-only /path/to/file

  # Receiver (paste the printed beam code; local-only is auto-detected)
  beam-rs receive --code <BEAM_CODE>
  ```
- **Experience**: The sender prints a beam code once it has a local address. Share the code out-of-band; the receiver auto-detects local-only mode from the code (no relay URL) and connects directly.

---

## 2. Cross-Subnet / VPN Discovery Issues
**Scenario**: mDNS discovery doesn't work because peers are on different subnets, across VPNs, or on networks that block multicast.

**Solution**: **iroh Mode**
- **Why**: iroh connects peers across network boundaries using relay infrastructure—no manual IP input required. Requires internet access.
- **Command**:
  ```bash
  # Sender
  beam-rs send /path/to/file

  # Receiver (iroh code)
  beam-rs receive --code <BEAM_CODE>
  ```
- **Experience**: Share the beam code via any channel (chat, paper, verbal). iroh handles NAT traversal automatically without needing IP addresses.

---

## 3. Cannot Copy-Paste (Cross-device / Remote Terminal)
**Scenario**: You are sending a file from a laptop to a friend's phone, or to a remote server console where you cannot easily copy and paste the long "Beam Code". Typing a huge base64 string is impossible.

**Solution A**: **PIN Mode** (Recommended when copy-paste is hard)
- **Why**: Uses a short 12-character PIN instead of a long code. The PIN is exchanged via Nostr relays, while the actual file transfer uses the default iroh transport. Requires internet for the Nostr exchange.
- **Command**:
  ```bash
  # Sender (default iroh transport with PIN exchange)
  beam-rs send --pin /path/to/file

  # Receiver (default iroh transport, prompts for PIN)
  beam-rs receive --pin
  ```
- **Experience**:
  1. Sender sees: `PIN: A1b2C3d4E5f6` (example)
  2. Receiver runs the matching `receive --pin` command and types `A1b2C3d4E5f6`.

**Solution B**: **Local-only Mode** (Same network, no internet)
- **Why**: Stays entirely on the LAN (relays disabled; sender discovery uses mDNS). Note this still requires moving the beam code between devices — handy when you can scan/share the code but want zero internet involvement.
- **Command**:
  ```bash
  # Sender
  beam-rs send --local-only /path/to/file

  # Receiver (paste the printed beam code)
  beam-rs receive --code <BEAM_CODE>
  ```

---

## 4. Strict Firewalls / Restricted Networks
**Scenario**: You are on a corporate or university network that blocks UDP, non-standard ports, and direct P2P connections. Standard transfers hang or fail.

**Solution A**: **iroh Mode** (Recommended)
- **Why**: iroh uses QUIC with automatic relay fallback. It tries direct P2P first, then falls back to iroh's relay servers if needed.
- **Command**:
  ```bash
  beam-rs send /path/to/file
  ```

**Solution B**: **Tor Mode** (for anonymity)
- **Why**: When you need anonymous transfers where neither party's IP is revealed. Uses Tor hidden services.
- **Command**:
  ```bash
  beam-rs-tor send /path/to/file
  ```

---

## 5. Maximum Anonymity
**Scenario**: You want to transfer a file without revealing your IP address to the peer or any relay servers.

**Solution**: **Tor Mode** (`beam-rs-tor send`)
- **Why**: Creates a Tor Hidden Service for the transfer. Traffic is routed through the Tor network, masking locations of both parties.
- **Command**:
  ```bash
  beam-rs-tor send /path/to/file
  ```

---

## 6. Large File Transfer
**Scenario**: Transferring a massive dataset (GBs) over the internet.

**Solution**: **iroh Mode** (Recommended)
- **Why**: Uses QUIC, optimized for high throughput and congestion control. Automatic relay fallback ensures reliable delivery.
  ```bash
  beam-rs send /path/to/large-video.mp4
  ```

---

## 7. Self-Hosted Infrastructure (Zero Third-Party Dependency)
**Scenario**: You require complete control over the network infrastructure and cannot rely on public relays due to policy or privacy concerns.

**Solution A**: **iroh Mode + Custom DERP Relays** (Recommended)
- **Why**: iroh allows you to run your own lightweight relay (DERP). By pointing `beam-rs` to your own infrastructure, you achieve a true peer-to-peer connection where no third-party relays are involved.
- **Resources**: Implementation for the relay server is available in the [iroh repository](https://github.com/n0-computer/iroh).
- **Command**:
  ```bash
  beam-rs send --relay-url https://my-private-relay.com /path/to/file
  ```

**Solution B**: **Local-only Mode** (Same network)
- **Why**: Uses mDNS discovery with relays disabled and no external dependencies. Works completely offline.
- **Command**:
  ```bash
  beam-rs send --local-only /path/to/file
  ```

---

## 8. Planned / Future Scenarios

See [ROADMAP.md](ROADMAP.md) for planned features and development priorities.
