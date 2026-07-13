//! Serverless pairing codes carry an ephemeral iroh node ID, discovered direct IP
//! addresses, and a fresh session secret. Nothing is published through a
//! signaling service; the user carries the entire payload to the receiver.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use iroh::{EndpointAddr, EndpointId};
use serde::{Deserialize, Serialize};

const CODE_PREFIX: &str = "serverless:";
const SERVERLESS_CODE_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerlessPayload {
    version: u8,
    node_id: String,
    secret: String,
    ip_addrs: Vec<String>,
}

pub struct ServerlessTarget {
    pub addr: EndpointAddr,
    pub secret: String,
}

pub fn encode(addr: &EndpointAddr, secret: &[u8; 32]) -> Result<String> {
    let payload = ServerlessPayload {
        version: SERVERLESS_CODE_VERSION,
        node_id: addr.id.to_string(),
        secret: URL_SAFE_NO_PAD.encode(secret),
        ip_addrs: addr.ip_addrs().map(ToString::to_string).collect(),
    };
    let payload = serde_json::to_vec(&payload).context("serializing serverless pairing code")?;
    Ok(format!("{CODE_PREFIX}{}", URL_SAFE_NO_PAD.encode(payload)))
}

pub fn decode(input: &str) -> Result<Option<ServerlessTarget>> {
    let Some(encoded) = input.trim().strip_prefix(CODE_PREFIX) else {
        return Ok(None);
    };
    let payload = URL_SAFE_NO_PAD
        .decode(encoded)
        .context("serverless pairing code is not valid base64url")?;
    let payload: ServerlessPayload =
        serde_json::from_slice(&payload).context("serverless pairing code has an invalid payload")?;
    if payload.version != SERVERLESS_CODE_VERSION {
        anyhow::bail!(
            "unsupported serverless pairing code version {} (expected {})",
            payload.version,
            SERVERLESS_CODE_VERSION
        );
    }
    let node_id: EndpointId = payload
        .node_id
        .parse()
        .context("serverless pairing code has an invalid node ID")?;
    let secret_bytes = URL_SAFE_NO_PAD
        .decode(&payload.secret)
        .context("serverless pairing code has an invalid session secret")?;
    if secret_bytes.len() != 32 {
        anyhow::bail!("serverless pairing code has an invalid session secret length");
    }
    let mut addr = EndpointAddr::new(node_id);
    for ip_addr in payload.ip_addrs {
        addr = addr.with_ip_addr(
            ip_addr
                .parse()
                .with_context(|| format!("serverless pairing code has invalid address {ip_addr}"))?,
        );
    }
    Ok(Some(ServerlessTarget {
        addr,
        secret: payload.secret,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_round_trips_with_direct_addresses() {
        let node_id = iroh::SecretKey::generate().public();
        let addr = EndpointAddr::new(node_id)
            .with_ip_addr("192.168.1.10:4433".parse().unwrap())
            .with_ip_addr("[2001:db8::1]:4433".parse().unwrap());
        let secret = [42u8; 32];
        let code = encode(&addr, &secret).unwrap();
        let decoded = decode(&code).unwrap().unwrap();
        assert_eq!(decoded.addr.id, node_id);
        assert_eq!(decoded.secret, URL_SAFE_NO_PAD.encode(secret));
        let decoded_addrs: Vec<_> = decoded.addr.ip_addrs().copied().collect();
        assert_eq!(decoded_addrs.len(), 2);
    }

    #[test]
    fn non_serverless_input_is_not_claimed() {
        assert!(decode("ordinary-beam-code").unwrap().is_none());
    }

    #[test]
    fn malformed_serverless_code_is_rejected() {
        assert!(decode("serverless:not-base64!").is_err());
    }
}
