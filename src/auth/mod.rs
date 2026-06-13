pub mod nostr_pin;
pub mod pin;
pub mod spake2;

/// PIN and transfer ID pair for SPAKE2 handshake in PIN mode.
pub struct PinInfo {
    pub pin: String,
    pub transfer_id: String,
}
