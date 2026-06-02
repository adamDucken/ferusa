#![no_main]

use ferusa_core::transport::FerusaMessage;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = FerusaMessage::decode(data);

    if data.len() >= 4 {
        let declared = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let result = FerusaMessage::decode(data);
        if declared > data.len().saturating_sub(4) {
            assert!(result.is_err());
        }
    }

    if let Ok(message) = FerusaMessage::decode(data) {
        let encoded = message.encode().expect("message encodes");
        assert!(FerusaMessage::decode(&encoded).is_ok());
    }
});
