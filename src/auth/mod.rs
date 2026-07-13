pub mod lan;
pub mod pin;
pub mod pin_record;
pub mod rendezvous;
pub mod serverless_code;
pub mod spake2;

/// Secret and session context used by PIN and serverless pairing authentication.
pub struct PairingAuth {
    pub secret: String,
    pub session_id: String,
}
