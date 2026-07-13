# Common Use Cases & Scenarios

This guide describes common scenarios where `beam-rs` shines and which mode to use for each.

## 1. No Third-Party Server (LAN / Air-gapped)
**Scenario**: You need to transfer files without relying on any third-party server (relay or Nostr), typically on a shared LAN or an air-gapped network.

**Solution**: **Serverless Mode** (`beam-rs send --serverless`)
- **Why**: Same iroh transport as the default mode, but with relays and internet discovery disabled. The sender's pasted beam code embeds its node ID, a 256-bit session secret, and discovered direct addresses. The receiver attempts those addresses directly, with mDNS as a fallback. No relay or Nostr server is contacted.
- **Command**:
  ```bash
  # Sender
  beam-rs send --serverless /path/to/file

  # Receiver (paste the printed beam code; it is auto-detected)
  beam-rs receive
  ```
- **Experience**: The sender waits for direct address discovery and prints a self-contained code. Share it out-of-band; the receiver connects via its embedded addresses or mDNS and authenticates its copied secret with SPAKE2.

**Short-code alternative**: When copying is inconvenient, use the same serverless transport with LAN-only PIN discovery:

```bash
beam-rs send --serverless --pin /path/to/file
beam-rs receive
```

The `B` at the start of the PIN makes the receiver disable Nostr, relays, and
internet-backed DNS automatically. The node-ID record travels only over mDNS.
The PIN lasts 120 seconds and does not refresh.

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
**Scenario**: You are sending a file to another device or remote console where copying and pasting a long code is inconvenient.

**Solution A**: **PIN Mode** (Recommended when copy-paste is hard)
- **Why**: Uses a short ten-character PIN instead of a long code. Its leading `A` tells the receiver to race an encrypted node-ID lookup over Nostr and mDNS, then the peers derive the content-encryption key with SPAKE2. It works across the internet or offline when both devices share a LAN.
- **Command**:
  ```bash
  # Sender (default iroh transport with PIN exchange)
  beam-rs send --pin /path/to/file

  # Receiver (default iroh transport; just run receive and enter the PIN)
  beam-rs receive
  ```
- **Experience**:
  1. Sender sees: `PIN: AK7P2-9QXMT` (example).
  2. Receiver enters that PIN. It is auto-detected and resolved over Nostr or mDNS.
  3. The PIN is available for one 120-second window; the sender exits instead of refreshing it.

**Solution B**: **Serverless Mode** (No third-party server)
- **Why**: Contacts no relay, Nostr, or internet discovery service. The copied code embeds direct address hints and a full session secret. If copying is impossible, combine `--serverless --pin`; its leading `B` tells a normal receiver to remain LAN-only.
- **Command**:
  ```bash
  # Sender
  beam-rs send --serverless /path/to/file

  # Receiver (paste the beam code)
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
- **Why**: Relays and internet discovery are disabled; the sender's discovered direct addresses are embedded in the beam code, with mDNS as a fallback. Works completely offline on a shared LAN. Add `--pin` on both commands when a short code is preferable to copy/paste.
- **Command**:
  ```bash
  beam-rs send --serverless /path/to/file
  # or: beam-rs send --serverless --pin /path/to/file
  # receiver for either form: beam-rs receive
  ```

---

## 8. Planned / Future Scenarios

See [ROADMAP.md](ROADMAP.md) for planned features and development priorities.
