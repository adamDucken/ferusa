use crate::auth::{
    AuthRequest, AuthResponse, PairingActivate, PairingActivateAck, PairingCommit,
    PairingCommitAck, PairingHello, PairingPrepared, PairingReady,
};
use crate::error::{FerusaError, Result};
use serde::{Deserialize, Serialize};

/// Both iroh endpoints negotiate this ALPN string.
pub const FERUSA_ALPN: &[u8] = b"ferusa/auth/4";

/// Sent by the phone after it observes the CLI's pairing-completion EOF.
pub const PAIRING_COMPLETE_CLOSE_CODE: u32 = 0;
pub const PAIRING_COMPLETE_CLOSE_REASON: &[u8] = b"pairing complete";

/// Every message on the wire is one of these.
/// Wire format: 4-byte LE length prefix + JSON bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FerusaMessage {
    Ping,
    Pong { path_info: Option<String> },
    Request(AuthRequest),
    Response(AuthResponse),
    PairingHello(PairingHello),
    PairingPrepared(PairingPrepared),
    PairingReady(PairingReady),
    PairingCommit(PairingCommit),
    PairingCommitAck(PairingCommitAck),
    PairingActivate(PairingActivate),
    PairingActivateAck(PairingActivateAck),
}

impl FerusaMessage {
    /// Encode to length-prefixed JSON bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let json = match serde_json::to_vec(self) {
            Ok(json) => json,
            Err(e) => {
                return Err(FerusaError::Json {
                    details: e.to_string(),
                })
            }
        };
        let len = checked_payload_len(json.len())?;
        let mut out = Vec::with_capacity(4 + json.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&json);
        Ok(out)
    }

    /// Decode from a length-prefixed JSON byte slice (the 4-byte header included).
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(FerusaError::MessageTooShort);
        }
        let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let total_len = len.checked_add(4).ok_or(FerusaError::MessageTruncated {
            expected: len,
            got: bytes.len() - 4,
        })?;
        if bytes.len() < total_len {
            return Err(FerusaError::MessageTruncated {
                expected: len,
                got: bytes.len() - 4,
            });
        }
        if bytes.len() > total_len {
            return Err(FerusaError::MessageTrailingBytes {
                expected: total_len,
                got: bytes.len(),
            });
        }
        match serde_json::from_slice(&bytes[4..total_len]) {
            Ok(message) => Ok(message),
            Err(e) => Err(FerusaError::Json {
                details: e.to_string(),
            }),
        }
    }
}

fn checked_payload_len(len: usize) -> Result<u32> {
    u32::try_from(len).map_err(|_| FerusaError::Protocol {
        kind: "message_too_large",
        details: format!(
            "encoded JSON payload is {len} bytes; maximum is {}",
            u32::MAX
        ),
    })
}

// send_message / recv_message over iroh streams are implemented in Phase 4
// when iroh is added as a dependency to cli and app.

#[cfg(test)]
mod tests {
    use super::checked_payload_len;
    use crate::error::FerusaError;

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn rejects_payload_lengths_above_u32_max() {
        let err = checked_payload_len(u32::MAX as usize + 1).unwrap_err();

        assert!(matches!(
            err,
            FerusaError::Protocol {
                kind: "message_too_large",
                ..
            }
        ));
        assert_eq!(err.code(), "protocol.failed");
    }
}
