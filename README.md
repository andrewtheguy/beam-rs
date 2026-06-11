# beam-rs

> [!NOTE]
> This project is still work in progress (0.0.x). No backward compatibility is guaranteed between versions.

A secure, cross-platform, single-binary peer-to-peer file transfer tool with direct connectivity and AES-256-GCM end-to-end encryption.

## Features

- **End-to-end encryption** - All transfers use AES-256-GCM encryption
- **Resumable file transfers** - Interrupted file downloads can resume from where they left off
- **File and folder transfers** - Send individual files or entire directories (automatically archived)
- **Multiple transport modes** - iroh (recommended) and Tor
- **Serverless transfers** - direct transfers with no third-party server; all discovered IPs (LAN and public) are embedded in the beam code, with mDNS as a fallback (`beam-rs send --no-server`)
- **NAT traversal** - Automatic relay fallback for iroh
- **Anonymous transfers** - Tor hidden services via `beam-rs-tor` for anonymity
- **Cross-platform** - Standalone binary for macOS, Linux, and Windows

## Installation

The release installers fetch a native, standalone executable. You only need the binary in your PATH; no runtime dependencies or package managers are required.

### Quick Install (Linux & macOS)

```bash
curl -sSL https://andrewtheguy.github.io/beam-rs/install.sh | bash
```

By default the installer pulls the latest **stable** release. Use `--prerelease` for the newest prerelease, or pass an explicit tag to pin to a specific build. Examples:

```bash
# Latest prerelease
curl -sSL https://andrewtheguy.github.io/beam-rs/install.sh | bash -s -- --prerelease

# Pin to a specific tag
curl -sSL https://andrewtheguy.github.io/beam-rs/install.sh | bash -s 20251210172710
```

### Quick Install (Windows)

```powershell
irm https://andrewtheguy.github.io/beam-rs/install.ps1 | iex
```

By default the PowerShell installer pulls the latest **stable** release. Use `-PreRelease` for the newest prerelease, or pass an explicit tag to pin to a specific build. Examples (args-only parser):

```powershell
# Latest prerelease
$env:BEAM_INSTALL_ARGS='-PreRelease'; irm https://andrewtheguy.github.io/beam-rs/install.ps1 | iex

# Pin to a specific tag
$env:BEAM_INSTALL_ARGS='20251210172710'; irm https://andrewtheguy.github.io/beam-rs/install.ps1 | iex
```

### From Source

```bash
# Main binary (iroh transport)
cargo build --release

# Tor binary (separate crate, anonymous transfers)
cargo build --release -p beam-rs-tor
```

## Usage

### Internet Transfers

Use these modes for transfers over the internet. They all use a **Beam Code** for connection.

#### 1. iroh Mode (Recommended) - `send`
*Direct P2P transport using QUIC/TLS with automatic relay fallback. Most reliable for both small and large files.*

```bash
# Send file
beam-rs send /path/to/file

# Send folder
beam-rs send /path/to/folder --folder
```

##### Custom Iroh Relays
- Default behavior uses iroh's public relay fallback plus direct P2P.
- For self-hosted setups, set the relay(s) on the **sender** only — they are
  embedded in the beam code, so the receiver adopts them automatically:
    ```bash
    beam-rs send --relay-url https://relay1.example.com /path/to/file
    beam-rs receive   # picks up the sender's relay(s) from the code
    ```
- Multiple `--relay-url` flags are supported for failover.

#### 2. Tor Mode - `beam-rs-tor send`
*Anonymous transfers via Tor hidden services. Use when anonymity is required.*
> Built as a separate binary: `cargo build -p beam-rs-tor`.

```bash
beam-rs-tor send /path/to/file
```

#### Receiving (Internet)
`beam-rs receive` receives iroh codes and `beam-rs-tor receive` receives Tor codes.

```bash
beam-rs receive
# Prompts for the beam code or PIN (a 12-character PIN is auto-detected and
# resolved via Nostr).
```

---

### Serverless Transfers

**No third-party server (primarily for same-network/LAN transfers)**
- `beam-rs send --no-server`: iroh transport with relays disabled; the sender
  embeds all of its discovered IPs (LAN and any public/port-mapped addresses) in
  the beam code, with mDNS kept as a discovery fallback
- No relay or Nostr server is contacted; share the printed beam code with the receiver
- The expected use case is a shared LAN. It is not *strictly* local-only —
  enforcing that would be an unnecessary burden — so a WAN connection can
  succeed if a public/port-mapped address happens to be reachable, but NAT and
  firewalls usually prevent that.

> **Note**: Tor mode requires internet access. iroh mode can be air‑gapped when you self‑host the relay and point the sender at it via `--relay-url` (the receiver picks it up from the code); the default public relay requires internet access.

#### No-server (`--no-server`)

Use this mode to transfer without any third-party server (no relay, no Nostr).
It uses the same iroh transport and beam code as the default mode, but disables
relays entirely: the beam code carries the sender endpoint ID plus every direct
address iroh discovered — LAN interfaces and any public or port-mapped (UPnP/
PCP/NAT-PMP) addresses — so the receiver attempts them all directly, with mDNS
as a fallback. It is primarily intended for transfers on the same LAN; it is not
strictly local-only (enforcing that would be an unnecessary burden), so a WAN
connection may also succeed when a public/port-mapped address is reachable,
though NAT and firewalls commonly prevent it. The receiver auto-detects
no-server mode from the code (no flag needed).

```bash
# Send without a server
beam-rs send --no-server /path/to/file

# Send folder without a server
beam-rs send --no-server /path/to/folder --folder

# Receive (paste the printed beam code)
beam-rs receive
```

> `--no-server` cannot be combined with `--pin` (PIN exchange uses Nostr, a
> third-party server) or `--relay-url` (relays are disabled).

## Common Use Cases

See [USE_CASES.md](docs/USE_CASES.md) for detailed scenarios including:
- **No Internet** - Air-gapped / Local LAN transfers
- **Restricted Networks** - Firewall/NAT traversal options
- **Anonymity** - Tor mode for anonymous transfers
- **Self-Hosted** - Zero third-party dependency setups

For protocol details and wire formats, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security

All modes provide end-to-end encryption.
- **All modes (iroh, iroh `--no-server`, Tor)**: The **Beam Code** carries the key/address information.

| Mode | Type | Key Exchange | Transport Encryption | Content Encryption |
|------|------|--------------|---------------------|-------------------|
| iroh | Internet | Beam Code | QUIC/TLS 1.3 | AES-256-GCM |
| iroh (`--no-server`) | Direct (LAN/public) | Beam Code | QUIC/TLS 1.3 | AES-256-GCM |
| Tor (`beam-rs-tor`) | Internet | Beam Code | Tor circuits | AES-256-GCM |

All modes use dual-layer encryption (transport + content). `--no-server` is the
same iroh transport with relays disabled, so it keeps QUIC/TLS 1.3 on the wire.

Relay servers (iroh, Tor) never see decrypted content or encryption keys.

For detailed security model, see [ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model).

## License

MIT
