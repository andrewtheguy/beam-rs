# beam-rs

> [!NOTE]
> This project is still work in progress (0.0.x). No backward compatibility is guaranteed between versions.

A secure, cross-platform, single-binary peer-to-peer tool that sends **one file** at a time, with direct connectivity, resumable downloads, and AES-256-GCM end-to-end encryption.

For folders, use [pTransfer](https://github.com/andrewtheguy/ptransfer).

## Features

- **End-to-end encryption** - All transfers use AES-256-GCM encryption
- **Resumable file transfers** - Interrupted downloads resume from the receiver's partial state
- **Single-file transfers** - Send one regular file per session
- **Serverless transfers** - direct transfers with no third-party server; a copy/paste code embeds the node ID, a fresh session secret, and discovered direct addresses, with mDNS as a fallback (`beam-rs send --serverless`)
- **LAN-only PIN pairing** - `--pin` discovers the sender over mDNS without a relay, internet-backed DNS publisher, or copied long code
- **NAT traversal** - Automatic relay fallback for iroh
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
cargo build --release
```

## Usage

### 1. Default Iroh mode (Recommended) - `send`
*Direct P2P transport using QUIC/TLS with automatic relay fallback. Most reliable for both small and large files. Requires internet access.*

```bash
beam-rs send /path/to/file
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

*Short-lived, serverless PIN discovery over the local network, with SPAKE2 authentication.*

```bash
# Sender
beam-rs send --pin /path/to/file

# Receiver (enter the displayed PIN)
beam-rs receive
```

The sender advertises only its encrypted ephemeral node ID, never a beam code or
content key. Discovery uses mDNS, and both iroh relays and internet-backed DNS
are disabled. The displayed ten-character PIN is valid for one 120-second
window. If no receiver starts connecting, the sender exits instead of refreshing
it. Both devices must be on the same local network.

### 3. Serverless Mode - `send --serverless`

*No third-party server, primarily for same-network/LAN transfers using a copied code.*

Use this mode to transfer without any third-party server (no iroh relay or
internet-backed DNS discovery). It uses iroh with relays disabled and prints
a self-contained beam code carrying the ephemeral node ID, a fresh
256-bit session secret, and every direct address discovered before the code is
printed. The receiver tries those addresses immediately and retains mDNS as a
fallback. The embedded addresses make the mode more robust on networks where
mDNS is unavailable. A public/port-mapped address may also work across networks,
but typical NAT and firewall rules make a shared LAN the expected environment.

```bash
# Send without a server
beam-rs send --serverless /path/to/file

# Receive (paste the printed beam code; it is auto-detected)
beam-rs receive

```

For the same serverless transport with a short mDNS PIN instead of a copied
code, use `beam-rs send --pin` as described above.
`send` takes at most one mode flag (`--serverless` or `--pin`); with none it uses
the default iroh mode. `--relay-url` applies only to the default mode, because
the other two disable relays.

### Receiving

`beam-rs receive` handles iroh, serverless, and PIN inputs. Serverless beam
codes and PINs are auto-detected. PINs always use LAN-only discovery with relays
and internet-backed DNS disabled.

```bash
beam-rs receive
# Prompts for a beam code or 10-character PIN.

# Optional output directory
beam-rs receive --output /path/to/downloads

# Disable file resume state for this receive
beam-rs receive --no-resume
```

### Resuming

If a receive is interrupted (Ctrl+C, network loss, crash), the partial download
is kept next to the destination as `<file>.beam-rs.partial`. Start a new send of
the same file (any mode) and receive it into the same directory; the receiver
verifies the partial file against the sender's size and xxHash64 checksum and
continues from the saved offset. A mismatched partial file is discarded and the
transfer restarts from zero.

## Common Use Cases

See [USE_CASES.md](docs/USE_CASES.md) for detailed scenarios including:
- **No Internet** - Air-gapped / Local LAN transfers
- **Restricted Networks** - Firewall/NAT traversal options
- **Self-Hosted** - Zero third-party dependency setups

For protocol details and wire formats, see [ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security

All modes provide end-to-end encryption.
- **Default iroh**: The beam code carries a one-time secret and sender address. SPAKE2 proves secret possession, binds it to the receiver's authenticated iroh node ID, and derives the content-encryption key before metadata is sent.
- **Serverless**: The copied beam code carries a 256-bit session secret and direct address hints; SPAKE2 derives the content-encryption key.
- **PIN mode (`send --pin`)**: mDNS carries only an encrypted ephemeral node ID. After connection, SPAKE2 proves PIN possession and derives the content-encryption key. Iroh relays and internet-backed DNS are disabled.

| Mode | Type | Key Exchange | Transport Encryption | Content Encryption |
|------|------|--------------|---------------------|-------------------|
| iroh | Internet | Beam Code secret + SPAKE2 node-ID authorization | QUIC/TLS 1.3 | AES-256-GCM with SPAKE2-derived key |
| iroh (`--pin`) | Direct (LAN) | mDNS node-ID rendezvous + SPAKE2 | QUIC/TLS 1.3 | AES-256-GCM with SPAKE2-derived key |
| iroh (`--serverless`) | Direct (LAN/public) | Copied 256-bit secret + SPAKE2 | QUIC/TLS 1.3 | AES-256-GCM with SPAKE2-derived key |

All modes use dual-layer encryption (transport + content). `--serverless` is the
same iroh transport with relays disabled, so it keeps QUIC/TLS 1.3 on the wire.

Iroh relay servers never see decrypted content or encryption keys.
Serverless and PIN modes contact neither kind of server.

For detailed security model, see [ARCHITECTURE.md](docs/ARCHITECTURE.md#security-model).

## License

MIT
