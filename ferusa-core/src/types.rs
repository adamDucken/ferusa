use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const VAULT_VERSION: u32 = 1;
pub const MAX_VAULT_ENTRIES: usize = 10_000;
pub const MAX_VAULT_PLAINTEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_VAULT_FIELD_BYTES: usize = 64 * 1024;
const MAX_VAULT_NOTES_BYTES: usize = 1024 * 1024;
const MAX_VAULT_TAGS_PER_ENTRY: usize = 64;
const MAX_VAULT_TAG_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vault {
    pub version: u32,
    pub entries: Vec<Entry>,
}

impl Default for Vault {
    fn default() -> Self {
        Self {
            version: VAULT_VERSION,
            entries: Vec::new(),
        }
    }
}

impl Vault {
    /// Reject vault data this version cannot safely interpret or process.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.version != VAULT_VERSION {
            return Err(format!(
                "unsupported vault schema version {} (expected {})",
                self.version, VAULT_VERSION
            ));
        }
        if self.entries.len() > MAX_VAULT_ENTRIES {
            return Err(format!(
                "vault contains too many entries (maximum {MAX_VAULT_ENTRIES})"
            ));
        }

        for (index, entry) in self.entries.iter().enumerate() {
            validate_field(index, "title", &entry.title, MAX_VAULT_FIELD_BYTES)?;
            if let Some(username) = &entry.username {
                validate_field(index, "username", username, MAX_VAULT_FIELD_BYTES)?;
            }
            validate_field(
                index,
                "password",
                entry.password.as_str(),
                MAX_VAULT_FIELD_BYTES,
            )?;
            if let Some(url) = &entry.url {
                validate_field(index, "url", url, MAX_VAULT_FIELD_BYTES)?;
            }
            if let Some(notes) = &entry.notes {
                validate_field(index, "notes", notes, MAX_VAULT_NOTES_BYTES)?;
            }
            if entry.tags.len() > MAX_VAULT_TAGS_PER_ENTRY {
                return Err(format!(
                    "vault entry {index} has too many tags (maximum {MAX_VAULT_TAGS_PER_ENTRY})"
                ));
            }
            for tag in &entry.tags {
                validate_field(index, "tag", tag, MAX_VAULT_TAG_BYTES)?;
            }
        }

        Ok(())
    }
}

fn validate_field(index: usize, field: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.len() > max_bytes {
        return Err(format!(
            "vault entry {index} {field} exceeds the {max_bytes}-byte limit"
        ));
    }
    Ok(())
}

impl Zeroize for Vault {
    fn zeroize(&mut self) {
        self.version.zeroize();
        for entry in &mut self.entries {
            entry.zeroize();
        }
        self.entries.clear();
    }
}

impl ZeroizeOnDrop for Vault {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub title: String,
    pub username: Option<String>,
    pub password: SecretString,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Zeroize for Entry {
    fn zeroize(&mut self) {
        self.id = Uuid::nil();
        self.title.zeroize();
        if let Some(username) = &mut self.username {
            username.zeroize();
        }
        self.username = None;
        self.password.zeroize();
        if let Some(url) = &mut self.url {
            url.zeroize();
        }
        self.url = None;
        if let Some(notes) = &mut self.notes {
            notes.zeroize();
        }
        self.notes = None;
        for tag in &mut self.tags {
            tag.zeroize();
        }
        self.tags.clear();
        self.created_at.zeroize();
        self.updated_at.zeroize();
    }
}

impl ZeroizeOnDrop for Entry {}

/// Secret-bearing string for vault fields that contain passwords.
#[derive(Default, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString(<redacted>)")
    }
}

impl PartialEq<&str> for SecretString {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<SecretString> for &str {
    fn eq(&self, other: &SecretString) -> bool {
        *self == other.as_str()
    }
}

impl PartialEq for SecretString {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for SecretString {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VaultAction {
    /// Unlock the encrypted vault before a command-specific action is known.
    Unlock,
    /// List entry metadata.
    List,
    Read,
    Create,
    Update,
    Delete,
    /// NOTE: short, command-aligned protocol name. User-facing UI may render this as CHANGE_PASSWORD.
    Passwd,
    /// Replace an existing paired phone.
    Pair,
}
