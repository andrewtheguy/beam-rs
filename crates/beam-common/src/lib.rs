//! beam-common: Shared library for beam-rs transports
//!
//! This crate provides the core functionality shared across all beam-rs
//! transport implementations (iroh, Tor, mDNS).

pub mod core;
pub mod ui;

#[cfg(feature = "tui")]
pub mod tui;
