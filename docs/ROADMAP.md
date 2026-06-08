# Project Roadmap

## Backlog

Ideas and feature requests for future consideration.

### Browser-Accessible Tor Downloads
**Domain:** Tor Mode
- **Feature:** Enable `beam-rs-tor send` to serve files via standard HTTP over the Onion network.
- **Benefit:** Allows receivers to download files using just the **Tor Browser**, eliminating the need to install the `beam-rs` CLI on the receiving machine.

### Zero-Config mDNS Discovery (browse + PIN)
**Domain:** Local Connection
- **Status:** Removed. The standalone `beam-rs-local` binary that did this was removed when local LAN transfers were folded into `beam-rs send --local-only` (iroh with relays disabled, sharing a beam code).
- **What it was:** The receiver browsed mDNS for advertised senders, picked one from a list, and entered a short PIN — no beam code copied between the two machines.
- **Why removed:** Lack of a clear use case. `--local-only` covers no-internet LAN transfers, and `--pin` covers short-code exchange (via Nostr).
- **Add back if:** There is a need for transfers with **no copy-paste between sender and receiver** (e.g. a remote console or second device where pasting a long beam code is impractical) while staying fully offline — the one gap `--local-only` and `--pin` don't jointly cover.
