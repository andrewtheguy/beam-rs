# Project Roadmap

## Backlog

Ideas and feature requests for future consideration.

### Non-Interactive / Scripting Mode (flow refactor)
**Domain:** CLI / Scripting
- **Feature:** A coherent non-interactive mode for scripted/piped use, where the tool never blocks on a terminal prompt.
- **Scope — cross-cutting, not a single flag:** This touches *every* interactive prompt, not just code input:
  - Beam code / PIN entry on `receive` (the `--code`/`-c` argument was removed, so receivers currently always prompt).
  - The overwrite-existing-file confirmation, and any other `prompt_line` / confirm calls.
  Each of these needs a defined non-interactive behavior (read from stdin, or a safe default such as fail-closed on overwrite) — designing one in isolation would leave the others inconsistent.
- **Open question — mechanism is undecided:**
  - Could be *implied* by the existing `--no-tui` flag (which already means "no interactive terminal"), rather than a new dedicated flag.
  - Or an explicit flag (e.g. reading the code/PIN from stdin: `echo <CODE> | beam-rs receive`). Stdin keeps the secret out of `argv` (avoids leaking into process listings / shell history).
  - Decision deferred until the whole flow is designed together.
- **Applies to:** both the iroh and Tor (`--tor`) transports of `beam-rs`.
- **Also in scope for that effort:** user-facing documentation for non-interactive usage (not written yet).
- **Status:** Deferred — design only when the larger prompt/flow refactor is taken up.

### Interactive TUI Wizard for the iroh Sender
**Domain:** CLI / UX
- **Feature:** An interactive TUI wizard for `beam-rs send` (iroh) that guides the user through the available options instead of requiring them to know the flags up front.
- **Why:** The iroh sender has several options that interact in non-obvious ways and have real trade-offs (third-party server vs. not, copy-paste vs. short PIN, LAN vs. internet). A wizard can ask plain-language questions and pick the right flags, rather than making the user read `--help` and reason about combinations.
- **Options the wizard would cover:**
  - `--folder` — single file vs. folder (could also be auto-detected from the path).
  - `--pin` — short PIN exchange via Nostr vs. sharing the full beam code.
  - `--no-server` — no third-party server (relays/Nostr disabled), primarily for same-LAN transfers.
  - `--relay-url` — custom relay servers.
- **Should encode the constraints:** e.g. `--no-server` is mutually exclusive with `--pin` and `--relay-url`, so the wizard should prevent invalid combinations rather than erroring after the fact.
- **Builds on:** the existing inline TUI (the `tui` module in `beam-rs`); honors `--no-tui` (wizard disabled / falls back to flags when there's no interactive terminal).

### Browser-Accessible Tor Downloads
**Domain:** Tor Mode
- **Feature:** Enable `beam-rs send --tor` to serve files via standard HTTP over the Onion network.
- **Benefit:** Allows receivers to download files using just the **Tor Browser**, eliminating the need to install the `beam-rs` CLI on the receiving machine.

### Zero-Config mDNS Discovery (browse + PIN)
**Domain:** Local Connection
- **Status:** Removed. The standalone `beam-rs-local` binary that did this was removed when local LAN transfers were folded into `beam-rs send --no-server` (iroh with relays disabled, sharing a beam code).
- **What it was:** The receiver browsed mDNS for advertised senders, picked one from a list, and entered a short PIN — no beam code copied between the two machines.
- **Why removed:** Lack of a clear use case. `--no-server` covers transfers with no third-party server, and `--pin` covers short-code exchange (via Nostr).
- **Add back if:** There is a need for transfers with **no copy-paste between sender and receiver** (e.g. a remote console or second device where pasting a long beam code is impractical) while staying fully offline — the one gap `--no-server` and `--pin` don't jointly cover.
