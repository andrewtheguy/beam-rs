# Common Use Cases & Scenarios

This guide describes common scenarios where `beam-rs` shines and which mode to use for each.

## 1. No Third-Party Server (LAN / Air-gapped)
**Scenario**: You need to transfer files without relying on any third-party server (relay or Nostr), typically on a shared LAN or an air-gapped network.

**Solution**: **Serverless Mode** (`beam-rs send --serverless`)
- **Why**: Same iroh transport as the default mode, but with relays disabled. The sender embeds the direct addresses discovered before the code is printed (LAN interfaces and any public/port-mapped addresses) in the beam code, so the receiver attempts them all directly, with mDNS as a fallback. No relay or Nostr server is contacted. The expected use case is a shared LAN — it is not *strictly* local-only (enforcing that would be an unnecessary burden), so a WAN connection can succeed if a public/port-mapped address happens to be reachable, but NAT/firewalls usually prevent it.
- **Command**:
  ```bash
  # Sender
  beam-rs send --serverless /path/to/file

  # Receiver (paste the printed beam code at the prompt; serverless is auto-detected)
  beam-rs receive
  ```
- **Experience**: The sender waits briefly for direct address discovery and then prints a beam code. Share the code out-of-band; the receiver auto-detects serverless mode from the code (no relay URL) and connects directly via the embedded addresses or mDNS.

---

## 2. Cross-Subnet / VPN Discovery Issues
**Scenario**: mDNS discovery doesn't work because peers are on different subnets, across VPNs, or on networks that block multicast.

**Solution**: **Default Iroh mode**
- **Why**: iroh connects peers across network boundaries using relay infrastructure—no manual IP input required. Requires internet access.
- **Command**:
  ```bash
  # Sender
  beam-rs send /path/to/file

  # Receiver (paste the iroh code at the prompt)
  beam-rs receive
  ```
- **Experience**: Share the beam code via any channel (chat, paper, verbal). iroh handles NAT traversal automatically without needing IP addresses.

---

## 3. Cannot Copy-Paste (Cross-device / Remote Terminal)
**Scenario**: You are sending a file from a laptop to a friend's phone, or to a remote server console where you cannot easily copy and paste the long "Beam Code". Typing a huge base64 string is impossible.

**Solution A**: **PIN Mode** (Recommended when copy-paste is hard)
- **Why**: Uses a short 12-character PIN instead of typing a long code. The receiver uses the PIN to find and decrypt the beam code from Nostr, then the peers derive the content-encryption key with SPAKE2 over the default iroh transport. Requires internet for the Nostr exchange.
- **Command**:
  ```bash
  # Sender (default iroh transport with PIN exchange)
  beam-rs send --pin /path/to/file

  # Receiver (default iroh transport; just run receive and enter the PIN)
  beam-rs receive
  ```
- **Experience**:
  1. Sender sees: `PIN: A1b2C3d4E5f6` (example)
  2. Receiver runs `receive` and enters `A1b2C3d4E5f6` at the prompt — the PIN is
     auto-detected (vs. a full beam code) and resolved via Nostr.

**Solution B**: **Serverless Mode** (No third-party server)
- **Why**: Contacts no relay or Nostr server (relays disabled); the sender embeds its discovered direct addresses in the beam code and the receiver connects directly, with mDNS as a fallback. Note this still requires moving the beam code between devices — handy when you can scan/share the code but want zero third-party involvement.
- **Command**:
  ```bash
  # Sender
  beam-rs send --serverless /path/to/file

  # Receiver (paste the printed beam code at the prompt)
  beam-rs receive
  ```

---

## 4. Strict Firewalls / Restricted Networks
**Scenario**: You are on a corporate or university network that blocks UDP, non-standard ports, and direct P2P connections. Standard transfers hang or fail.

**Solution A**: **Default Iroh mode** (Recommended)
- **Why**: iroh uses QUIC with automatic relay fallback. It tries direct P2P first, then falls back to iroh's relay servers if needed.
- **Command**:
  ```bash
  beam-rs send /path/to/file
  ```

**Solution B**: **Tor Mode** (for anonymity)
- **Why**: When you need anonymous transfers where neither party's IP is revealed. Uses Tor hidden services.
- **Command**:
  ```bash
  beam-rs send --tor /path/to/file
  ```

---

## 5. Maximum Anonymity
**Scenario**: You want to transfer a file without revealing your IP address to the peer or any relay servers.

**Solution**: **Tor Mode** (`beam-rs send --tor`)
- **Why**: Creates a Tor Hidden Service for the transfer. Traffic is routed through the Tor network, masking locations of both parties.
- **Command**:
  ```bash
  beam-rs send --tor /path/to/file
  ```

---

## 6. Large File Transfer
**Scenario**: Transferring a massive dataset (GBs) over the internet.

**Solution**: **Default Iroh mode** (Recommended)
- **Why**: Uses QUIC, optimized for high throughput and congestion control. Automatic relay fallback ensures reliable delivery.
  ```bash
  beam-rs send /path/to/large-video.mp4
  ```

---

## 7. Self-Hosted Infrastructure (Zero Third-Party Dependency)
**Scenario**: You require complete control over the network infrastructure and cannot rely on public relays due to policy or privacy concerns.

**Solution A**: **Default Iroh mode + Custom DERP Relays** (Recommended)
- **Why**: iroh allows you to run your own relay. By pointing `beam-rs` to your own infrastructure, you avoid public third-party relays; iroh still attempts direct P2P first and uses your relay as fallback if needed.
- **Resources**: Implementation for the relay server is available in the [iroh repository](https://github.com/n0-computer/iroh).
- **Command**:
  ```bash
  beam-rs send --relay-url https://my-private-relay.com /path/to/file
  ```
  The relay is embedded in the beam code, so the receiver adopts it
  automatically — just run `beam-rs receive`, no relay flag needed.

**Solution B**: **Serverless Mode** (No third-party server)
- **Why**: Relays disabled and no external dependencies; the sender's discovered direct addresses are embedded in the beam code, with mDNS as a fallback. Works completely offline on a shared LAN.
- **Command**:
  ```bash
  beam-rs send --serverless /path/to/file
  ```

---

## 8. Planned / Future Scenarios

See [ROADMAP.md](ROADMAP.md) for planned features and development priorities.
