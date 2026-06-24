use ferusa_core::FerusaError;
use serde::Serialize;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Debug, Clone, Serialize)]
pub struct AppErrorPayload {
    pub code: &'static str,
    pub message: String,
    pub detail: Option<String>,
    pub retryable: bool,
    pub retry_after_ms: Option<u64>,
}

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum AppError {
    #[error(transparent)]
    Core(#[from] FerusaError),

    #[error("Android Keystore error during {operation}: {details}")]
    Keystore {
        operation: &'static str,
        details: String,
    },

    #[error("biometric auth failed: {details}")]
    Biometric { details: String },

    #[error("approval key authentication required: {details}")]
    ApprovalKeyAuthRequired { details: String },

    #[error("setup input error: {details}")]
    SetupInput { details: String },

    #[error("pairing replacement authorization is missing or expired")]
    PairingReplacementAuthorization,

    #[error("Tauri event emit failed: {details}")]
    EventEmit { details: String },

    #[error("app data dir error: {details}")]
    AppDataDir { details: String },

    #[error("pending request error: {kind}")]
    PendingRequest { kind: &'static str },

    #[error("biometric session expired")]
    SessionExpired,

    #[error("PIN error during {operation}: {details}")]
    Pin {
        operation: &'static str,
        details: String,
    },

    #[error("PIN cooldown active for {retry_after_ms}ms: {details}")]
    PinCooldown {
        retry_after_ms: u64,
        details: String,
    },

    #[error(transparent)]
    AnyhowCompat(#[from] anyhow::Error),
}

impl AppError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Core(err) => err.code(),
            Self::Keystore { operation, .. } => match *operation {
                "get" => "app.keystore.get",
                "set" => "app.keystore.set",
                "delete" => "app.keystore.delete",
                "clear" => "app.keystore.clear",
                _ => "app.keystore",
            },
            Self::Biometric { .. } => "app.biometric",
            Self::ApprovalKeyAuthRequired { .. } => "app.approval_key_auth_required",
            Self::SetupInput { .. } => "app.setup_input",
            Self::PairingReplacementAuthorization => "app.pairing_replacement.authorization",
            Self::EventEmit { .. } => "app.event_emit",
            Self::AppDataDir { .. } => "app.data_dir",
            Self::PendingRequest { kind } => match *kind {
                "locked" => "app.locked",
                "missing" => "app.pending_missing",
                "mismatch" => "app.pending_mismatch",
                _ => "app.pending_request",
            },
            Self::SessionExpired => "app.session_expired",
            Self::Pin { operation, .. } => match *operation {
                "validate" => "app.pin.invalid",
                "hash" => "app.pin.hash",
                "verify" => "app.pin.verify",
                "incorrect" => "app.pin.incorrect",
                "too_many_attempts" => "app.pin.too_many_attempts",
                _ => "app.pin",
            },
            Self::PinCooldown { .. } => "app.pin.cooldown",
            Self::AnyhowCompat(_) => "app.unclassified",
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(
            self.code(),
            "network.connect"
                | "network.timeout"
                | "internal.invariant"
                | "app.pin.invalid"
                | "app.pin.incorrect"
                | "app.pin.cooldown"
                | "app.biometric"
                | "app.approval_key_auth_required"
                | "app.pairing_replacement.authorization"
                | "app.pending_missing"
        )
    }

    pub fn message(&self) -> String {
        match self {
            Self::Core(err) => err.user_message().to_string(),
            Self::Keystore { .. } => "Could not access secure phone storage.".into(),
            Self::Biometric { .. } => "Biometric authentication failed.".into(),
            Self::ApprovalKeyAuthRequired { .. } => {
                "Biometric approval signing expired. Try again.".into()
            }
            Self::SetupInput { .. } => "Setup input is invalid.".into(),
            Self::PairingReplacementAuthorization => {
                "Pairing replacement authorization expired. Start replacement again.".into()
            }
            Self::EventEmit { .. } => "Could not update the app screen.".into(),
            Self::AppDataDir { .. } => "Could not access the app data directory.".into(),
            Self::PendingRequest { kind: "locked" } => "Unlock the app before approving.".into(),
            Self::PendingRequest { kind: "missing" } => "No pending request is available.".into(),
            Self::PendingRequest { kind: "mismatch" } => {
                "This approval no longer matches the pending request.".into()
            }
            Self::PendingRequest { .. } => "Pending request state is invalid.".into(),
            Self::SessionExpired => "Biometric session expired. Unlock again.".into(),
            Self::Pin {
                operation: "incorrect",
                ..
            } => "Incorrect PIN. Please try again.".into(),
            Self::Pin {
                operation: "too_many_attempts",
                ..
            } => "Too many incorrect PIN attempts.".into(),
            Self::PinCooldown { retry_after_ms, .. } => {
                let seconds = retry_after_ms.div_ceil(1000);
                format!("Too many incorrect PIN attempts. Try again in {seconds}s.")
            }
            Self::Pin {
                operation: "validate",
                ..
            } => "PIN must contain the expected number of digits.".into(),
            Self::Pin { .. } => "Could not process PIN.".into(),
            Self::AnyhowCompat(err) => err.to_string(),
        }
    }

    pub fn retry_after_ms(&self) -> Option<u64> {
        match self {
            Self::PinCooldown { retry_after_ms, .. } => Some(*retry_after_ms),
            _ => None,
        }
    }

    pub fn payload(&self) -> AppErrorPayload {
        AppErrorPayload {
            code: self.code(),
            message: self.message(),
            detail: Some(self.to_string()),
            retryable: self.retryable(),
            retry_after_ms: self.retry_after_ms(),
        }
    }
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.payload().serialize(serializer)
    }
}
