# beam-rs

> [!NOTE]
> This project is still work in progress (0.0.x). No backward compatibility is guaranteed between versions.

A secure, cross-platform, single-binary peer-to-peer file transfer tool with direct connectivity and AES-256-GCM end-to-end encryption.

## Features

- **End-to-end encryption** - All transfers use AES-256-GCM encryption
- **Resumable file transfers** - Interrupted file downloads can resume from receiver partial state (folder transfers are streamed tar archives and are not resumable)
- **File and folder transfers** - Send individual files or entire directories (automatically archived)
- **Multiple transport modes** - iroh (recommended) and Tor
- **Serverless transfers** - direct transfers with no third-party server; a copy/paste code embeds the node ID, a fresh session secret, and discovered direct addresses, with mDNS as a fallback (`beam-rs send --serverless`)
- **LAN-only PIN pairing** - `--serverless --pin` discovers the sender over mDNS without a relay, Nostr, DNS publisher, or copied long code
- **NAT traversal** - Automatic relay fallback for iroh
- **Anonymous transfers** - Tor hidden services via `beam-rs send --tor` for anonymity
- **Cross-platform** - Standalone release binaries for Linux x86_64/aarch64, macOS Apple Silicon, and Windows x86_64 (stable releases)

## Installation

The release installers fetch a native, standalone executable. You only need the binary in your PATH; no runtime dependencies or package managers are required.

### Quick Install (Linux & macOS)

The shell installer supports Linux x86_64/aarch64 and macOS Apple Silicon.

```bash
curl -sSL https://andrewtheguy.github.io/beam-rs/install.sh | bash
```

By default the installer pulls the latest **stable** release. Use `--prerelease` for the newest prerelease, or pass an explicit tag to pin to a specific build. Examples:

```bash
# Latest prerelease
curl -sSL https://andrewtheguy.github.io/beam-rs/install.sh | bash -s -- --prerelease

# Pin to a specific tag
curl -sSL https://andrewtheguy.github.io/beam-rs/install.sh | bash -s <release-tag>
```

### Quick Install (Windows)

The Windows installer supports x86_64 stable releases. Prerelease release jobs
do not publish a Windows binary.

```powershell
irm https://andrewtheguy.github.io/beam-rs/install.ps1 | iex
```

By default the PowerShell installer pulls the latest **stable** release. Pass an explicit tag to pin to a specific stable build. Examples (args-only parser):

```powershell
# Pin to a specific tag
$env:BEAM_INSTALL_ARGS='<release-tag>'; irm https://andrewtheguy.github.io/beam-rs/install.ps1 | iex
```

### From Source

```bash
# Single binary with both the iroh and Tor transports
cargo build --release
```

## Usage

### 1. Default Iroh mode (Recommended) - `send`
*Direct P2P transport using QUIC/TLS with automatic relay fallback. Most reliable for both small and large files. Requires internet access.*

```bash
# Send file
beam-rs send /path/to/file

# Send folder
beam-rs send /path/to/folder --folder
```

#### Custom Iroh Relays

- Default behavior uses iroh's public relay fallback plus direct P2P.
- For self-hosted setups, set the relay(s) on the **sender** only — they are
  embedded in the beam code, so the receiver adopts them automatically:
    ```bash
    beam-rs send --relay-url https://relay1.example.com /path/to/file
    beam-rs receive   # picks up the sender's relay(s) from the code
    ```
- Multiple `--relay-url` flags are supported for failover.

### 2. PIN Mode - `send --pin`

*Short-lived PIN discovery over Nostr and the local network, with SPAKE2 authentication.*

```bash
# Sender
beam-rs send --pin /path/to/file

# Receiver (enter the displayed PIN)
beam-rs receive
```

The sender advertises only its encrypted ephemeral node ID, never a beam code or
content key. An `A` at the start of the ten-character PIN tells the receiver to
race Nostr and mDNS lookups, so same-LAN pairing can still work without
internet. The displayed `AXXXX-XXXXX` PIN is valid for one
120-second window. If no receiver starts connecting, the sender exits instead of
refreshing it.

### 3. Serverless Mode - `send --serverless`

*No third-party server, primarily for same-network/LAN transfers.*

Use this mode to transfer without any third-party server (no iroh relay, Nostr,
or internet-backed DNS discovery). It uses iroh with relays disabled and prints
a self-contained beam code carrying the ephemeral node ID, a fresh
256-bit session secret, and every direct address discovered before the code is
printed. The receiver tries those addresses immediately and retains mDNS as a
fallback. The embedded addresses make the mode more robust on networks where
mDNS is unavailable. A public/port-mapped address may also work across networks,
but typical NAT and firewall rules make a shared LAN the expected environment.

```bash
# Send without a server
beam-rs send --serverless /path/to/file

# Send folder without a server
beam-rs send --serverless /path/to/folder --folder

# Receive (paste the printed beam code; it is auto-detected)
beam-rs receive

# Same serverless transport, but exchange only a short PIN over mDNS
beam-rs send --serverless --pin /path/to/file
beam-rs receive
```

`--serverless --pin` publishes no payload or secret: mDNS carries an encrypted
node-ID rendezvous record, and SPAKE2 authenticates the PIN in-band. The sender
uses a `BXXXX-XXXXX` PIN so the receiver automatically disables Nostr, iroh
relays, and internet-backed DNS. It uses one PIN for 120 seconds and exits if
nobody connects; it does not refresh.
`--serverless` cannot be combined with `--relay-url` because relays are disabled.

### 4. Tor Mode - `send --tor`

*Anonymous transfers via Tor hidden services. Use when anonymity is required. Requires internet access.*

```bash
beam-rs send --tor /path/to/file
```

### Receiving

`beam-rs receive` handles iroh, serverless, Tor, and PIN inputs. Serverless beam
codes are auto-detected. PINs beginning with `A` use normal Nostr+LAN discovery;
PINs beginning with `B` automatically use LAN-only discovery with relays and
internet-backed DNS disabled.

```bash
beam-rs receive
# Prompts for a beam code or 10-character PIN.

# Optional output directory
beam-rs receive --output /path/to/downloads

# Disable file resume state for this receive
beam-rs receive --no-resume
```

## Common Use Cases

See [USE_CASES.md](docs/USE_CASES.md) for detailed scenarios including:
- **No Internet** - Air-gapped / Local LAN transfers
- **Restricted Networks** - Firewall/NAT traversal options
- **Anonymity** - Tor mode for anonymous transfers
- **Self-Hosted** - Zero third-party dependency setups

For protocol details and wire formats, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security

All modes provide end-to-end encryption.
- **Default iroh**: The beam code carries a one-time secret and sender address. SPAKE2 proves secret possession, binds it to the receiver's authenticated iroh node ID, and derives the content-encryption key before metadata is sent.
- **Tor**: The beam code carries the content-encryption key and onion address.
- **Serverless**: The copied beam code carries a 256-bit session secret and direct address hints; SPAKE2 derives the content-encryption key.
- **PIN mode (`send --pin`)**: Nostr and mDNS carry only an encrypted ephemeral node ID. After connection, SPAKE2 proves PIN possession and derives the content-encryption key. The leading `A` selects normal discovery; `--serverless --pin` emits a leading `B`, which makes the receiver limit discovery to mDNS and disable relays/DNS automatically.

| Mode | Type | Key Exchange | Transport Encryption | Content Encryption |
|------|------|--------------|---------------------|-------------------|
| iroh | Internet | Beam Code secret + SPAKE2 node-ID authorization | QUIC/TLS 1.3 | AES-256-GCM with SPAKE2-derived key |
| iroh (`--pin`) | Internet or LAN | Encrypted node-ID rendezvous + SPAKE2 | QUIC/TLS 1.3 | AES-256-GCM with SPAKE2-derived key |
| iroh (`--serverless`) | Direct (LAN/public) | Copied 256-bit secret + SPAKE2 | QUIC/TLS 1.3 | AES-256-GCM with SPAKE2-derived key |
| iroh (`--serverless --pin`) | Direct (LAN) | mDNS node-ID rendezvous + SPAKE2 | QUIC/TLS 1.3 | AES-256-GCM with SPAKE2-derived key |
| Tor (`send --tor`) | Internet | Beam Code | Tor circuits | AES-256-GCM |

All modes use dual-layer encryption (transport + content). `--serverless` is the
same iroh transport with relays disabled, so it keeps QUIC/TLS 1.3 on the wire.

Relay servers (iroh, Tor) never see decrypted content or encryption keys. Nostr
relays used by PIN mode see only an encrypted ephemeral iroh node ID under a
PIN-derived author key. Serverless modes contact neither kind of server.

For detailed security model, see [ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model).

## License

MIT
