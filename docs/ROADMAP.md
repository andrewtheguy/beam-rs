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
  - An explicit flag or reading the code/PIN from stdin (e.g. `echo <CODE> | beam-rs receive`). Stdin keeps the secret out of `argv` (avoids leaking into process listings / shell history).
  - Decision deferred until the whole flow is designed together.
- **Applies to:** both the iroh and Tor (`--tor`) transports of `beam-rs`.
- **Also in scope for that effort:** user-facing documentation for non-interactive usage (not written yet).
- **Status:** Deferred — design only when the larger prompt/flow refactor is taken up.

### Browser-Accessible Tor Downloads
**Domain:** Tor Mode
- **Feature:** Enable `beam-rs send --tor` to serve files via standard HTTP over the Onion network.
- **Benefit:** Allows receivers to download files using just the **Tor Browser**, eliminating the need to install the `beam-rs` CLI on the receiving machine.
