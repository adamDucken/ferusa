#[cfg(test)]
mod tests {
    use crate::twofa::{ensure_pairing_generation, validate_auth_exchange, TwofaError};
    use ferusa_core::auth::{AuthRequest, AuthResponse, AUTH_TIMESTAMP_MAX_SKEW_MS};
    use ferusa_core::types::VaultAction;
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn sample_exchange(timestamp: u64) -> (AuthRequest, AuthResponse) {
        let req = AuthRequest {
            pairing_id: Uuid::new_v4(),
            request_id: Uuid::new_v4(),
            correlation_code: 1234,
            action: VaultAction::Read,
            entry_title: None,
            unlock_share_requested: false,
            timestamp,
        };
        let resp = AuthResponse {
            pairing_id: req.pairing_id,
            request_id: req.request_id,
            correlation_code: req.correlation_code,
            action: req.action,
            approved: true,
            unlock_share: None,
            timestamp,
            signature: Vec::new(),
        };
        (req, resp)
    }

    #[test]
    fn twofa_error_messages_are_stable() {
        let cases = [
            (TwofaError::SignatureMismatch, "signature"),
            (TwofaError::PairingGenerationMismatch, "pairing"),
            (TwofaError::UnknownRequest, "unknown"),
            (TwofaError::ActionMismatch, "action"),
            (TwofaError::CorrelationCodeMismatch, "correlation"),
            (TwofaError::Denied, "denied"),
            (TwofaError::MissingUnlockShare, "share"),
            (TwofaError::TimestampSkew, "timestamp"),
        ];

        for (err, needle) in cases {
            assert!(err.to_string().to_lowercase().contains(needle));
        }
    }

    #[test]
    fn pairing_generation_validation_rejects_stale_requests_and_responses() {
        let active = Uuid::new_v4();
        let stale = Uuid::new_v4();

        assert!(ensure_pairing_generation(active, active, active).is_ok());
        assert!(matches!(
            ensure_pairing_generation(active, stale, active),
            Err(TwofaError::PairingGenerationMismatch)
        ));
        assert!(matches!(
            ensure_pairing_generation(active, active, stale),
            Err(TwofaError::PairingGenerationMismatch)
        ));
    }

    #[test]
    fn auth_exchange_validation_accepts_fresh_timestamps() {
        let (req, resp) = sample_exchange(now_ms());

        assert!(validate_auth_exchange(&req, &resp).is_ok());
    }

    #[test]
    fn auth_exchange_validation_rejects_stale_response_timestamp() {
        let fresh = now_ms();
        let stale = fresh - AUTH_TIMESTAMP_MAX_SKEW_MS - 1;
        let (req, mut resp) = sample_exchange(fresh);
        resp.timestamp = stale;

        assert!(matches!(
            validate_auth_exchange(&req, &resp),
            Err(TwofaError::TimestampSkew)
        ));
    }
}
