use ferusa_core::FerusaError;
use thiserror::Error;

use crate::interface::ui;

pub type Result<T> = std::result::Result<T, CliError>;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum CliError {
    #[error(transparent)]
    Core(#[from] FerusaError),

    #[error("terminal input failed: {details}")]
    Terminal { details: String },

    #[error("QR rendering failed: {details}")]
    Qr { details: String },

    #[error("data directory error: {details}")]
    DataDir { details: String },

    #[error("private file error: {details}")]
    PrivateFile { details: String },

    #[error("logger init failed: {details}")]
    Logger { details: String },

    #[error("password generation config failed: {details}")]
    PasswordGeneration { details: String },

    #[error(transparent)]
    AnyhowCompat(#[from] anyhow::Error),
}

impl CliError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Core(err) => err.code(),
            Self::Terminal { .. } => "cli.terminal",
            Self::Qr { .. } => "cli.qr",
            Self::DataDir { .. } => "cli.data_dir",
            Self::PrivateFile { .. } => "cli.private_file",
            Self::Logger { .. } => "cli.logger",
            Self::PasswordGeneration { .. } => "cli.password_generation",
            Self::AnyhowCompat(_) => "cli.unclassified",
        }
    }

    pub fn user_message(&self) -> String {
        match self {
            Self::Core(err) => err.user_message().to_string(),
            Self::Terminal { .. } => "Could not read terminal input.".into(),
            Self::Qr { .. } => "Could not render the pairing QR code.".into(),
            Self::DataDir { .. } => "Could not prepare the Ferusa data directory.".into(),
            Self::PrivateFile { .. } => "Could not securely write a Ferusa private file.".into(),
            Self::Logger { .. } => "Could not initialize file logging.".into(),
            Self::PasswordGeneration { .. } => {
                "Password generation configuration is invalid.".into()
            }
            Self::AnyhowCompat(err) => err.to_string(),
        }
    }

    pub fn render(&self) {
        ui::failed(&self.user_message());
        log::error!("[ferusa:cli]: {}: {:#}", self.code(), self);
    }
}
