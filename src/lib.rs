//! beam-rs library: core transfer/crypto/protocol, the UI sink abstraction,
//! and the inline terminal UI. The `beam-rs` binary (see `main.rs`) builds its
//! transports (iroh, Tor) on top of these modules.

pub mod core;
pub mod ui;
pub mod tui;
