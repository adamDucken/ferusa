use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::{env, fs};

use assert_cmd::Command;
use ferusa_core::crypto::{
    combine_vault_key, decrypt_vault, derive_keys, encrypt_vault, new_salt, EncryptedBlob,
};
use ferusa_core::types::{Entry, Vault};
use tempfile::TempDir;
use uuid::Uuid;

pub struct TestContext {
    temp_dir: TempDir,
}

pub const TEST_PHONE_SHARE: [u8; 32] = [0xD3; 32];

fn vault_key(local_secret: &[u8; 32]) -> [u8; 32] {
    combine_vault_key(local_secret, &TEST_PHONE_SHARE).expect("combine vault key")
}

impl TestContext {
    pub fn new() -> Self {
        Self {
            temp_dir: TempDir::new().expect("create temp dir"),
        }
    }

    pub fn cmd(&self, args: &[&str]) -> Command {
        Command::from_std(self.process_cmd(args))
    }

    pub fn process_cmd(&self, args: &[&str]) -> ProcessCommand {
        let bin = Command::cargo_bin("ferusa")
            .expect("build ferusa binary")
            .get_program()
            .to_string_lossy()
            .into_owned();

        let mut parts = vec![
            format!(
                "XDG_DATA_HOME={} ",
                sh_quote(self.temp_dir.path().to_string_lossy().as_ref())
            )
            .trim_end()
            .to_string(),
            sh_quote(&bin),
        ];
        parts.extend(args.iter().map(|arg| sh_quote(arg)));

        let mut cmd = ProcessCommand::new("script");
        cmd.args(["-qec", &parts.join(" "), "/dev/null"]);
        cmd.env("PATH", self.test_path());
        cmd.env("NO_COLOR", "1");
        #[cfg(feature = "dev-2fa-stub")]
        cmd.env("FERUSA_ALLOW_DEV_2FA_STUB", "1");
        cmd
    }

    pub fn data_dir(&self) -> PathBuf {
        self.temp_dir.path().join("ferusa")
    }

    pub fn configure_fake_clipboard(&self) {
        fs::create_dir_all(self.clipboard_bin_dir()).expect("create clipboard bin dir");
        fs::create_dir_all(self.data_dir()).expect("create data dir");

        let clipboard = self.clipboard_bin_dir().join("wl-copy");
        fs::write(&clipboard, "#!/bin/sh\ncat >/dev/null\n").expect("write fake clipboard");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&clipboard, fs::Permissions::from_mode(0o700))
                .expect("chmod fake clipboard");
        }

        fs::write(self.data_dir().join("clipboard.cmd"), b"wl-copy")
            .expect("write clipboard config");
        fs::write(self.data_dir().join("clipboard.clear-seconds"), b"0")
            .expect("disable delayed clipboard helper in tests");
    }

    pub fn vault_enc(&self) -> PathBuf {
        self.data_dir().join("vault.enc")
    }

    pub fn vault_salt(&self) -> PathBuf {
        self.data_dir().join("vault.salt")
    }

    pub fn phone_id(&self) -> PathBuf {
        self.data_dir().join("phone.id")
    }

    pub fn hmac_key(&self) -> PathBuf {
        self.data_dir().join("hmac.key")
    }

    pub fn pairing_state(&self) -> PathBuf {
        self.data_dir().join("pairing.json")
    }

    pub fn dev_2fa_stub_marker(&self) -> PathBuf {
        self.data_dir().join("dev-2fa-stub.json")
    }

    pub fn init_vault(&self, password: &str) {
        self.write_vault(password, Vault::default());
    }

    pub fn write_vault(&self, password: &str, vault: Vault) {
        fs::create_dir_all(self.data_dir()).expect("create data dir");

        let salt = new_salt();
        let keys = derive_keys(password.as_bytes(), &salt).expect("derive keys");
        let plaintext = serde_json::to_vec(&vault).expect("serialize vault");
        let blob =
            encrypt_vault(&vault_key(&keys.local_secret), salt, &plaintext).expect("encrypt vault");

        fs::write(self.vault_salt(), salt).expect("write vault.salt");
        fs::write(self.vault_enc(), blob.to_bytes()).expect("write vault.enc");
        #[cfg(feature = "dev-2fa-stub")]
        fs::write(
            self.dev_2fa_stub_marker(),
            br#"{
  "version": 1,
  "warning": "This vault was created with the deterministic dev 2FA stub and is not production-compatible."
}"#,
        )
        .expect("write dev 2FA stub marker");
    }

    pub fn read_vault(&self, password: &str) -> anyhow::Result<Vault> {
        let blob_bytes = fs::read(self.vault_enc())?;
        let blob = EncryptedBlob::from_bytes(&blob_bytes)?;
        let keys = derive_keys(password.as_bytes(), &blob.salt())?;
        let plaintext = decrypt_vault(&vault_key(&keys.local_secret), &blob)?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    fn clipboard_bin_dir(&self) -> PathBuf {
        self.temp_dir.path().join("bin")
    }

    fn test_path(&self) -> std::ffi::OsString {
        let mut entries = vec![self.clipboard_bin_dir()];
        if let Some(path) = env::var_os("PATH") {
            entries.extend(env::split_paths(&path));
        }
        env::join_paths(entries).expect("join PATH")
    }
}

pub fn sample_entry(title: &str, username: Option<&str>, password: &str) -> Entry {
    sample_entry_full(title, username, password, None, None, vec![])
}

pub fn sample_entry_full(
    title: &str,
    username: Option<&str>,
    password: &str,
    url: Option<&str>,
    notes: Option<&str>,
    tags: Vec<&str>,
) -> Entry {
    Entry {
        id: Uuid::new_v4(),
        title: title.to_string(),
        username: username.map(str::to_string),
        password: password.into(),
        url: url.map(str::to_string),
        notes: notes.map(str::to_string),
        tags: tags.into_iter().map(str::to_string).collect(),
        created_at: 1_700_000_000_000,
        updated_at: 1_700_000_000_000,
    }
}

pub fn vault_with_entries(entries: Vec<Entry>) -> Vault {
    Vault {
        version: 1,
        entries,
    }
}

pub fn exists(path: &Path) -> bool {
    path.exists()
}

fn sh_quote(value: &str) -> String {
    format!(
        "'{}'",
        value
            .replace('"' as char, "\"")
            .replace('\'' as char, "'\\''")
    )
}
