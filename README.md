# beam-rs

> [!NOTE]
> This project is still work in progress (0.0.x). No backward compatibility is guaranteed between versions.

A secure, cross-platform, single-binary peer-to-peer file transfer tool with direct connectivity and AES-256-GCM end-to-end encryption.

## Features

- **End-to-end encryption** - All transfers use AES-256-GCM encryption
- **Resumable file transfers** - Interrupted file downloads can resume from receiver partial state (folder transfers are streamed tar archives and are not resumable)
- **File and folder transfers** - Send individual files or entire directories (automatically archived)
- **Multiple transport modes** - iroh (recommended) and Tor
- **Serverless transfers** - direct transfers with no third-party server; currently discovered direct addresses (LAN and any public/port-mapped addresses) are embedded in the beam code, with mDNS as a fallback (`beam-rs send --serverless`)
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

### 2. Serverless Mode - `send --serverless`
*No third-party server (primarily for same-network/LAN transfers). The only mode that works without internet access.*

Use this mode to transfer without any third-party server (no relay, no Nostr).
It uses the same iroh transport and beam code as the default mode, but disables
relays entirely: the beam code carries the sender endpoint ID plus the direct
addresses discovered before the code is printed — LAN interfaces and any public
or port-mapped (UPnP/PCP/NAT-PMP) addresses — so the receiver attempts them all
directly, with mDNS as a fallback. The sender waits briefly for direct address
discovery, then prints the code even if discovery is still catching up. This mode
is primarily intended for transfers on the same LAN; it is not strictly
local-only (enforcing that would be an unnecessary burden), so a WAN connection
may also succeed when a public/port-mapped address is reachable, though NAT and
firewalls commonly prevent it. The receiver auto-detects serverless mode from the
code (no flag needed).

```bash
# Send without a server
beam-rs send --serverless /path/to/file

# Send folder without a server
beam-rs send --serverless /path/to/folder --folder

# Receive (paste the printed beam code)
beam-rs receive
```

> `--serverless` cannot be combined with `--pin` (PIN exchange uses Nostr, a
> third-party server) or `--relay-url` (relays are disabled).

### 3. Tor Mode - `send --tor`
*Anonymous transfers via Tor hidden services. Use when anonymity is required. Requires internet access.*

```bash
beam-rs send --tor /path/to/file
```

### Receiving
`beam-rs receive` handles iroh, serverless, and Tor codes — the transport is
auto-detected from the beam code.

```bash
beam-rs receive
# Prompts for the beam code or PIN (a 12-character PIN is auto-detected and
# resolved via Nostr).

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
- **Non-PIN modes (iroh, iroh `--serverless`, Tor)**: The **Beam Code** carries the key/address information.
- **PIN mode (`send --pin`)**: Nostr relays store an encrypted beam code so the receiver can find the sender; after the iroh connection is established, SPAKE2 derives the content-encryption key from the PIN.

| Mode | Type | Key Exchange | Transport Encryption | Content Encryption |
|------|------|--------------|---------------------|-------------------|
| iroh | Internet | Beam Code | QUIC/TLS 1.3 | AES-256-GCM |
| iroh (`--pin`) | Internet | Nostr code lookup + SPAKE2 | QUIC/TLS 1.3 | AES-256-GCM with SPAKE2-derived key |
| iroh (`--serverless`) | Direct (LAN/public) | Beam Code | QUIC/TLS 1.3 | AES-256-GCM |
| Tor (`send --tor`) | Internet | Beam Code | Tor circuits | AES-256-GCM |

All modes use dual-layer encryption (transport + content). `--serverless` is the
same iroh transport with relays disabled, so it keeps QUIC/TLS 1.3 on the wire.

Relay servers (iroh, Tor) never see decrypted content or encryption keys. Nostr
relays used by PIN mode see only the encrypted beam code and lookup tags.

For detailed security model, see [ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model).

## License

MIT
