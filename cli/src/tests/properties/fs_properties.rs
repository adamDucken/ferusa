#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use proptest::prelude::*;
    use tempfile::TempDir;

    use crate::storage::paths::{write_private_file, PairingStatus, Paths};

    fn paths(dir: &TempDir) -> Paths {
        let p = dir.path().to_path_buf();
        Paths {
            data_dir: p.clone(),
            vault_enc: p.join("vault.enc"),
            vault_salt: p.join("vault.salt"),
            peer_id: p.join("peer.id"),
            phone_id: p.join("phone.id"),
            hmac_key: p.join("hmac.key"),
            clipboard_cmd: p.join("clipboard.cmd"),
        }
    }

    #[cfg(unix)]
    fn file_name_strategy() -> impl Strategy<Value = std::ffi::OsString> {
        use std::os::unix::ffi::OsStringExt;

        prop::collection::vec(any::<u8>(), 0..=64).prop_map(|bytes| {
            let mut bytes = bytes
                .into_iter()
                .map(|b| if b == 0 || b == b'/' { b'_' } else { b })
                .collect::<Vec<_>>();
            if bytes.is_empty() || bytes == b"." || bytes == b".." {
                bytes = b"fuzz-file".to_vec();
            }
            std::ffi::OsString::from_vec(bytes)
        })
    }

    #[cfg(not(unix))]
    fn file_name_strategy() -> impl Strategy<Value = std::ffi::OsString> {
        prop::collection::vec(any::<u8>(), 0..=64).prop_map(|bytes| {
            let mut name = String::from_utf8_lossy(&bytes)
                .chars()
                .map(|c| match c {
                    '\0' | '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
                    c if c.is_control() => '_',
                    c => c,
                })
                .collect::<String>();
            if name.is_empty() || name == "." || name == ".." {
                name = "fuzz-file".to_owned();
            }
            name.into()
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn private_file_write_roundtrips_contents(name in file_name_strategy(), contents in prop::collection::vec(any::<u8>(), 0..=4096)) {
            let dir = TempDir::new().unwrap();
            let file = PathBuf::from(dir.path()).join(name);

            write_private_file(&file, &contents).unwrap();

            prop_assert_eq!(std::fs::read(&file).unwrap(), contents);
            prop_assert!(std::fs::metadata(&file).unwrap().is_file());

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
                prop_assert_eq!(mode, 0o600);
            }
        }

        #[test]
        fn vault_exists_tracks_encrypted_vault_file(write_enc in any::<bool>(), write_salt in any::<bool>(), enc in prop::collection::vec(any::<u8>(), 0..=128), salt in prop::collection::vec(any::<u8>(), 0..=128)) {
            let dir = TempDir::new().unwrap();
            let p = paths(&dir);
            std::fs::create_dir_all(&p.data_dir).unwrap();

            if write_enc {
                std::fs::write(&p.vault_enc, enc).unwrap();
            }
            if write_salt {
                std::fs::write(&p.vault_salt, salt).unwrap();
            }

            prop_assert_eq!(p.vault_exists(), write_enc);
        }

        #[test]
        fn legacy_split_pairing_files_are_never_ready(phone in prop::collection::vec(any::<u8>(), 0..=256), hmac in prop::collection::vec(any::<u8>(), 0..=256), write_phone in any::<bool>(), write_hmac in any::<bool>()) {
            let dir = TempDir::new().unwrap();
            let p = paths(&dir);
            std::fs::create_dir_all(&p.data_dir).unwrap();

            if write_phone {
                std::fs::write(&p.phone_id, &phone).unwrap();
            }
            if write_hmac {
                std::fs::write(&p.hmac_key, &hmac).unwrap();
            }

            match p.pairing_status() {
                PairingStatus::Ready => prop_assert!(false, "legacy split pairing must not be ready"),
                PairingStatus::MissingPhoneId => prop_assert!(!write_phone && !write_hmac),
                PairingStatus::Pending | PairingStatus::InvalidPhoneId(_) | PairingStatus::InvalidPairing(_) => {}
            }
        }
    }
}
