# beam-rs

> [!NOTE]
> This project is still work in progress (0.0.x). No backward compatibility is guaranteed between versions.

A secure, cross-platform, single-binary peer-to-peer file transfer tool with direct connectivity and AES-256-GCM end-to-end encryption.

## Features

- **End-to-end encryption** - All transfers use AES-256-GCM encryption
- **Resumable file transfers** - Interrupted file downloads can resume from where they left off
- **File and folder transfers** - Send individual files or entire directories (automatically archived)
- **Multiple transport modes** - iroh (recommended) and Tor
- **Local-only transfers** - same-network transfers without internet via mDNS discovery (`beam-rs send --local-only`)
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
- For self-hosted setups, point both sides at your own DERP relay(s):
    ```bash
    beam-rs send --relay-url https://relay1.example.com /path/to/file
    beam-rs receive --relay-url https://relay1.example.com
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
# Or with code directly
beam-rs receive --code <BEAM_CODE>

# Receive using PIN
beam-rs receive --pin
```

---

### Local/Offline Transfers

**LAN direct (recommended when both devices share a network)**
- `beam-rs send --local-only`: iroh transport with relays disabled; the
  sender is discovered by mDNS and connected to directly
- Fast, no internet required; share the printed beam code with the receiver

> **Note**: Tor mode requires internet access. iroh mode can be air‑gapped when you self‑host the relay and point both sides at it via `--relay-url`; the default public relay requires internet access.

#### LAN direct (`--local-only`)

Use this mode for transfers on the same network (no internet required). It uses
the same iroh transport and beam code as the default mode, but disables relays
entirely: the beam code carries the sender endpoint ID without relay URLs, and
the receiver resolves that endpoint on the LAN with mDNS. The receiver
auto-detects local-only mode from the code (no flag needed).

```bash
# Send locally
beam-rs send --local-only /path/to/file

# Send folder locally
beam-rs send --local-only /path/to/folder --folder

# Receive locally (paste the printed beam code)
beam-rs receive
```

> `--local-only` cannot be combined with `--pin` (PIN exchange uses Nostr, which
> requires internet) or `--relay-url` (relays are disabled).

## Common Use Cases

See [USE_CASES.md](docs/USE_CASES.md) for detailed scenarios including:
- **No Internet** - Air-gapped / Local LAN transfers
- **Restricted Networks** - Firewall/NAT traversal options
- **Anonymity** - Tor mode for anonymous transfers
- **Self-Hosted** - Zero third-party dependency setups

For protocol details and wire formats, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security

All modes provide end-to-end encryption.
- **All modes (iroh, iroh `--local-only`, Tor)**: The **Beam Code** carries the key/address information.

| Mode | Type | Key Exchange | Transport Encryption | Content Encryption |
|------|------|--------------|---------------------|-------------------|
| iroh | Internet | Beam Code | QUIC/TLS 1.3 | AES-256-GCM |
| iroh (`--local-only`) | LAN | Beam Code | QUIC/TLS 1.3 | AES-256-GCM |
| Tor (`beam-rs-tor`) | Internet | Beam Code | Tor circuits | AES-256-GCM |

All modes use dual-layer encryption (transport + content). `--local-only` is the
same iroh transport with relays disabled, so it keeps QUIC/TLS 1.3 on the wire.

Relay servers (iroh, Tor) never see decrypted content or encryption keys.

For detailed security model, see [ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model).

## License

MIT
