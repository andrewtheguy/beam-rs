pub mod lan;
pub mod pin;
pub mod pin_record;
pub mod rendezvous;
pub mod serverless_code;
pub mod spake2;

/// One-time secret and session context used to authorize an iroh receiver.
pub struct PairingAuth {
    pub secret: String,
    pub session_id: String,
}
