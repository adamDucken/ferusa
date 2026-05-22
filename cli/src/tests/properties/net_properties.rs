#[cfg(test)]
mod tests {
    use ferusa_core::auth::{AuthRequest, AuthResponse};
    use ferusa_core::transport::FerusaMessage;
    use ferusa_core::types::VaultAction;
    use proptest::prelude::*;
    use uuid::Uuid;

    fn action_strategy() -> impl Strategy<Value = VaultAction> {
        prop_oneof![
            Just(VaultAction::Read),
            Just(VaultAction::Create),
            Just(VaultAction::Update),
            Just(VaultAction::Delete),
            Just(VaultAction::Passwd),
            Just(VaultAction::Pair),
            Just(VaultAction::Unlock),
            Just(VaultAction::List),
        ]
    }

    fn text_strategy(max_len: usize) -> impl Strategy<Value = String> {
        prop::collection::vec(any::<u8>(), 0..=max_len)
            .prop_map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
    }

    fn auth_request_strategy() -> impl Strategy<Value = AuthRequest> {
        (
            any::<u128>(),
            any::<u128>(),
            any::<u16>(),
            action_strategy(),
            prop::option::of(text_strategy(96)),
            any::<bool>(),
            any::<u64>(),
        )
            .prop_map(
                |(
                    pairing_id,
                    request_id,
                    correlation_code,
                    action,
                    entry_title,
                    unlock_share_requested,
                    timestamp,
                )| AuthRequest {
                    pairing_id: Uuid::from_u128(pairing_id),
                    request_id: Uuid::from_u128(request_id),
                    correlation_code,
                    action,
                    entry_title,
                    unlock_share_requested,
                    timestamp,
                },
            )
    }

    fn auth_response_strategy() -> impl Strategy<Value = AuthResponse> {
        (
            any::<u128>(),
            any::<u128>(),
            any::<u16>(),
            action_strategy(),
            any::<bool>(),
            prop::option::of(any::<[u8; 32]>()),
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..=128),
        )
            .prop_map(
                |(
                    pairing_id,
                    request_id,
                    correlation_code,
                    action,
                    approved,
                    unlock_share,
                    timestamp,
                    signature,
                )| AuthResponse {
                    pairing_id: Uuid::from_u128(pairing_id),
                    request_id: Uuid::from_u128(request_id),
                    correlation_code,
                    action,
                    approved,
                    unlock_share,
                    timestamp,
                    signature,
                },
            )
    }

    fn message_strategy() -> impl Strategy<Value = FerusaMessage> {
        prop_oneof![
            Just(FerusaMessage::Ping),
            text_strategy(64).prop_map(|path_info| FerusaMessage::Pong {
                path_info: Some(path_info)
            }),
            auth_request_strategy().prop_map(FerusaMessage::Request),
            auth_response_strategy().prop_map(FerusaMessage::Response),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn wire_decoder_handles_arbitrary_network_bytes(data in prop::collection::vec(any::<u8>(), 0..=2048)) {
            let _ = FerusaMessage::decode(&data);
        }

        #[test]
        fn wire_decoder_rejects_truncated_declared_lengths(payload in prop::collection::vec(any::<u8>(), 0..=1024), extra in 1usize..=128) {
            let claimed_len = payload.len().saturating_add(extra).min(u32::MAX as usize);
            let mut frame = Vec::with_capacity(4 + payload.len());
            frame.extend_from_slice(&(claimed_len as u32).to_le_bytes());
            frame.extend_from_slice(&payload);

            prop_assert!(FerusaMessage::decode(&frame).is_err());
        }

        #[test]
        fn valid_wire_messages_roundtrip(message in message_strategy()) {
            let encoded = message.encode().unwrap();
            prop_assert!(FerusaMessage::decode(&encoded).is_ok());
        }
    }
}
