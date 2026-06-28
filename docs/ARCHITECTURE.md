# Beam-rs Architecture

## Overview

This document provides a detailed walkthrough of the beam-rs implementation.

beam-rs supports the following transfer modes (all beam code based):

1. **Default Iroh mode** (Recommended) - Direct P2P transfers using iroh's QUIC/TLS stack (automatic relay fallback) via `beam-rs send`. Requires internet access.
2. **Serverless Mode** - transfers using the iroh QUIC/TLS stack with relays disabled (no third-party server) via `beam-rs send --serverless`. The sender embeds the direct addresses discovered before the code is printed (LAN and any public/port-mapped addresses) in the beam code so the receiver connects directly, with mDNS as a fallback. Uses the same beam code format as iroh mode; the only mode that works without internet access.
3. **Tor Mode** - Anonymous transfers via Tor hidden services (uses `arti`) via `beam-rs send --tor`. Requires internet access.

## Transfer Flows

### 1. iroh Transfers

#### Default Iroh mode (Recommended) - QUIC / Direct + Relay

iroh uses a "hole punching" strategy that attempts direct connections via UDP/QUIC while simultaneously establishing a fallback path through a Relay (DERP) server.

```mermaid
sequenceDiagram
    participant Sender
    participant Relay as iroh Relay
    participant Receiver

    Sender->>Sender: 1. Create iroh Node (Random NodeID)
    Sender->>Relay: 2. Connect to Home Relay

    Sender->>Sender: 3. Generate beam code
    Note over Sender: Code = base64url(JSON token: version, protocol, created_at, AES_key, minimal addr)
    Note over Sender: Minimal addr = NodeID + selected relay URL + optional custom relay list

    Receiver->>Receiver: 4. Parse Code -> NodeAddr
    Receiver->>Relay: 5. Connect to Relay

    par Connection Attempts
        Receiver->>Relay: A. Dial via Relay (Guaranteed)
        Receiver->>Sender: B. Dial Direct UDP (Optimization)
    end

    Note over Sender,Receiver: iroh selects best path (Direct > Relay)

    Sender->>Receiver: 6. Handshake (ALPN "beam-transfer/1")
    Sender->>Receiver: 7. Send Encrypted Header (AES-256-GCM)
    Note over Receiver: Check file existence, prompt user

    alt User accepts transfer
        Receiver->>Sender: 8. Send Encrypted PROCEED
    else User declines or file conflict
        Receiver->>Sender: 8. Send Encrypted ABORT
        Note over Sender,Receiver: Transfer cancelled
    end

    loop 16KB chunks
        Sender->>Receiver: Send Encrypted Chunk (QUIC Stream)
    end

    Receiver->>Sender: 9. Send Encrypted ACK
```

#### Serverless Mode (iroh with relays disabled)

Serverless mode is for transfers without any third-party server (no relay, no
Nostr), and is primarily intended for the same LAN. It is the **same** iroh
transport and beam code as the default mode, with one difference: relays are
disabled (`RelayMode::Disabled`). The sender waits up to 10 seconds for direct
address discovery, then prints a beam code containing the endpoint ID plus the
direct addresses discovered so far (LAN interfaces and any public/port-mapped
addresses) and no relay URL. If no direct address is available yet, the sender
warns and still prints the code; the receiver may still connect after mDNS
propagates. The receiver auto-detects this mode from the missing relay URL and
connects directly to the embedded addresses, falling back to mDNS. It is not
strictly local-only — enforcing that would be an unnecessary burden — so a WAN
connection may succeed when a public/port-mapped address is reachable, though
NAT and firewalls commonly prevent it. (In serverless mode DNS is not used at
all — mDNS handles address lookup — so relay hostname resolution never applies.)

```mermaid
sequenceDiagram
    participant Sender
    participant Receiver

    Sender->>Sender: 1. Bind iroh endpoint (RelayMode::Disabled)
    Sender->>Sender: 2. Wait briefly for direct address discovery
    Sender->>Sender: 3. Print beam code
    Note over Sender: Beam code has endpoint id + discovered direct addresses (LAN/public), no relay URL

    Note over Sender: User shares beam code out-of-band

    Receiver->>Receiver: 4. Parse code, detect no relay -> serverless
    Receiver->>Sender: 5. Connect directly to embedded IPs (mDNS fallback) over QUIC (ALPN beam-transfer/1)

    Note over Sender,Receiver: From here identical to iroh mode
    Sender->>Receiver: 6. Encrypted header / chunks / ACK (AES-256-GCM)
```

### 2. Tor Transfers

#### Tor Mode

```mermaid
sequenceDiagram
    participant Sender
    participant Tor as Tor Network
    participant Receiver

    Sender->>Sender: 1. Bootstrap Tor client (ephemeral)
    Sender->>Tor: 2. Create .onion hidden service
    Sender->>Sender: 3. Generate beam code
    Note over Sender: Code = base64url(JSON token: version, protocol, created_at, AES_key, onion_addr)

    Receiver->>Receiver: 4. Bootstrap Tor client
    Receiver->>Tor: 5. Connect to .onion address
    Note over Receiver: Retries up to 5 times on timeout

    Tor-->>Sender: 6. Tor circuit established
    Note over Sender,Receiver: End-to-end encrypted via Tor

    Sender->>Receiver: 7. Send Encrypted Header (AES-256-GCM)
    Note over Receiver: Check file existence, prompt user

    alt User accepts transfer
        Receiver->>Sender: 8. Send Encrypted PROCEED
    else User declines or file conflict
        Receiver->>Sender: 8. Send Encrypted ABORT
        Note over Sender,Receiver: Transfer cancelled
    end

    loop 16KB chunks
        Sender->>Receiver: Send Encrypted Chunk
        Receiver->>Receiver: Write to disk
    end

    Receiver->>Sender: 9. Send Encrypted ACK
```

## Connection Types/Modes

### Default Iroh mode (`beam-rs send`) - Recommended
- **Transport**: QUIC / TLS 1.3
- **Discovery**: Selected relay URL embedded in the beam code, optional custom relay list from `--relay-url`, plus mDNS for local network.
- **Relay**: iroh relays (DERP) - automatically used if direct P2P connection fails.
- **Failover**: Uses multiple relays for redundancy; monitors latency to select the best path.
- **Connection**: "Hole punching" attempts to establish a direct UDP connection; falls back to relay if NATs are strict.
- **Protocol**: ALPN `beam-transfer/1`.
- **PIN Support**: Yes (`beam-rs send --pin`; the receiver runs `beam-rs receive` and enters the PIN at the prompt — it is auto-detected vs. a full beam code)
- **Encryption**: Always AES-256-GCM encrypted at the application layer, plus QUIC/TLS encryption.

### Serverless Mode (`beam-rs send --serverless`)
- **Transport**: QUIC / TLS 1.3 (same as iroh mode)
- **Discovery**: Direct addresses embedded in the beam code (the IPs iroh discovered before the code was printed — LAN and any public/port-mapped addresses), with mDNS address lookup as a fallback; relays disabled (`RelayMode::Disabled`)
- **Key Exchange**: Beam code (carries the AES key and an endpoint address with embedded IPs and no relay URL)
- **PIN Support**: No; PIN exchange uses Nostr, a third-party server
- **Encryption**: Always AES-256-GCM at the application layer, plus QUIC/TLS encryption
- **Reachability**: Primarily intended for the same LAN. The sender waits briefly for direct address discovery before printing the code, but it does not wait forever because there is no relay to wait on. Not strictly local-only — a WAN connection may succeed when a public/port-mapped address is reachable, but NAT/firewalls commonly prevent it. Incompatible with `--pin` and `--relay-url`.

### Tor Mode (`beam-rs send --tor`)
- **Transport**: Tor Onion Services
- **Discovery**: Onion Address
- **PIN Support**: No
- **Encryption**: Tor circuit encryption plus mandatory AES-256-GCM at the application layer.

## Security Model

### Default Iroh mode Encryption (Dual Layer)
Default Iroh mode uses two encryption layers for defense in depth:

**Transport Layer (iroh/QUIC)**:
- TLS 1.3/QUIC encryption (cipher negotiated by iroh/quinn)
- Mutual authentication via iroh node identities (NodeID in beam code)

**Application Layer (beam-rs)**:
- AES-256-GCM encryption for all data: headers, chunks, and control signals
- 256-bit key generated per transfer, embedded in beam code

### PIN-based Key Exchange (PIN Mode)
PIN mode is available for the default iroh transport (`beam-rs send --pin`). It
is not available for iroh `--serverless` or Tor.

PIN mode exchanges the beam code through Nostr keyed by a short PIN, then runs
a SPAKE2 handshake over the established QUIC stream to derive the session key.
PIN mode requires internet access for Nostr lookup.

- **Format**: 12 characters (11 random + 1 checksum) from an unambiguous charset; the checksum catches typos before attempting a connection.
- **Nostr lookup**: The sender publishes an encrypted beam code as event kind `24243` with a time-bucketed PIN hint. Events expire after 2 hours; receivers query the current and previous hourly bucket.
- **Key Derivation**: The PIN is the SPAKE2 password, with fixed `beam-rs-sender`/`beam-rs-receiver` identities; the handshake derives the session key. The transfer_id is exchanged alongside the handshake and validated separately (constant-time compare), not folded into the key.
- **Security**: SPAKE2 prevents offline dictionary attacks, and a mismatched transfer_id is rejected before the key is used.
- **Confidentiality**: All data (headers, chunks, and control signals) is AES-256-GCM encrypted with the SPAKE2-derived key, on top of the transport encryption.

### Tor Mode Security
- **Anonymity**: Sender/Receiver IPs hidden.
- **Encryption**: End-to-end via Tor circuit encryption plus mandatory AES-256-GCM at application layer for all data (headers, chunks, and control signals).
- **Timeouts**: The sender waits up to 10 minutes for a receiver to connect. The receiver retries retryable Tor connection failures up to 5 times and applies a 30-minute transfer timeout by default; set `BEAM_TRANSFER_TIMEOUT_SECS` to override it.

### TTL (Time-To-Live) Validation

All beam codes include a creation timestamp and are validated against a TTL to prevent replay attacks and stale session establishment.

**Implementation:**
- **Token Version**: v4 tokens include a `created_at` Unix timestamp
- **TTL Duration**: 60 minutes (`SESSION_TTL_SECS = 3600`)
- **Clock Skew**: Allows up to 60 seconds into the future to handle minor clock drift

**Validation Points:**
1. **Beam Codes** (iroh, iroh `--serverless`, Tor): Validated in `parse_code()` before connection. Serverless codes use the same v4 token format and are validated the same way.
2. **PIN Mode**: The Nostr event can live for up to 2 hours to survive hourly hint bucket boundaries, but the decrypted beam code is still parsed through the same 60-minute TTL validation.

**Error Messages:**
- Expired codes: "Token expired: code is X minutes old (max 60 minutes). Please request a new code from the sender."
- Future timestamps: "Invalid token: created_at is in the future. Check system clock."

## Wire Protocol Format

### Encrypted Message Format (Stream-based transports)

All encrypted messages (used by Iroh, iroh `--serverless`, and Tor modes) follow this format:

```
[length: 4 bytes BE][encrypted_payload]
```

- **length**: Big-endian u32 indicating total size of `encrypted_payload`
- **encrypted_payload**: `nonce (12 bytes) || ciphertext || tag (16 bytes)`

### Control Signals

Control signals are encrypted messages sent over the same length-prefixed framing as data:

- **PROCEED**: receiver accepts transfer
- **ABORT**: receiver declines transfer
- **ACK**: receiver confirms all expected bytes were received
- **RESUME:<offset>**: receiver requests resume from a byte offset (files only)

These signals are not tied to chunk numbers and use fresh random nonces like all other encrypted messages.

### Resumable File On-Disk Flow

Resumable state is only used for **file** transfers (not folders) when resume is enabled.
The receiver `--no-resume` flag disables this state for file transfers.

- Receiver writes incoming bytes to a resume temp file in the target directory:
  `<final_path>.beam-rs.partial`
- That temp file contains a fixed-size metadata header (checksum, expected size,
  bytes received, filename) followed by file data.

When the transfer completes successfully:

1. Receiver writes payload bytes (without metadata header) to a staging file:
   `<final_path>.partial` in the same directory.
2. Receiver syncs the staging file and parent directory.
3. Receiver atomically renames staging to the final destination path.
4. Receiver removes `<final_path>.beam-rs.partial`.

Keeping both temp/staging files in the same directory ensures the final rename
is on the same filesystem, which enables atomic replacement semantics.

### Nonce Derivation

AES-256-GCM requires a unique 12-byte nonce for each encryption operation with
the same key. beam-rs generates a fresh random 96-bit nonce per message and
prefixes it to the ciphertext, so the receiver can decrypt directly. With 16KB
chunks and a per-transfer key, the conservative 2^32 random-nonce limit
corresponds to ~64 TiB per transfer.

### Confirmation Handshake

Before data transfer begins, the receiver validates the incoming transfer:

1. **Sender** sends encrypted file header containing filename, size, and transfer type
2. **Receiver** checks:
   - If file already exists at destination
   - If user wants to proceed (interactive prompt)
3. **Receiver** responds with:
   - **PROCEED**: Accept transfer, sender begins sending data chunks
   - **ABORT**: Decline transfer, connection is closed

This handshake prevents:
- Accidental file overwrites without user consent
- Wasted bandwidth on declined transfers
- Sender continuing after receiver has disconnected
