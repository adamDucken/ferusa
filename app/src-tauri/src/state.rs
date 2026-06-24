use log::{debug, info};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};
use zeroize::ZeroizeOnDrop;

pub const MAX_CONCURRENT_ARGON2_JOBS: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinKind {
    FourDigit,
    SixDigit,
}

#[derive(ZeroizeOnDrop)]
pub struct Secrets {
    #[zeroize(skip)]
    pub pairing_id: uuid::Uuid,
    #[zeroize(skip)]
    pub approval_key_alias: String,
    #[zeroize(skip)]
    pub approval_public_key_der: Vec<u8>,
    pub phone_share: [u8; 32],
    pub pin4_hash: String,
    pub pin6_hash: String,
    #[zeroize(skip)]
    pub cli_node_id: [u8; 32],
}

pub struct AppState {
    pub secrets: Arc<Mutex<Option<Secrets>>>,
    pub is_setup: Arc<Mutex<bool>>,
    pub endpoint: Arc<Mutex<Option<iroh::Endpoint>>>,
    pub pairing_replacement_authorized_at: Arc<Mutex<Option<Instant>>>,
    pub unlocked_at: Arc<Mutex<Option<Instant>>>,
    pub approval_key_authenticated_at: Arc<Mutex<Option<Instant>>>,
    pub setup_pairing_code: Arc<Mutex<Option<u16>>>,
    pub session_generation: Arc<Mutex<u64>>,
    is_foreground: Arc<AtomicBool>,
    pin4_attempt_gate: Arc<Mutex<()>>,
    pin6_attempt_gate: Arc<Mutex<()>>,
    argon2_jobs: Arc<Semaphore>,
}

impl AppState {
    pub fn new() -> Self {
        debug!("[ferusa:app]: AppState::new");
        Self {
            secrets: Arc::new(Mutex::new(None)),
            is_setup: Arc::new(Mutex::new(false)),
            endpoint: Arc::new(Mutex::new(None)),
            pairing_replacement_authorized_at: Arc::new(Mutex::new(None)),
            unlocked_at: Arc::new(Mutex::new(None)),
            approval_key_authenticated_at: Arc::new(Mutex::new(None)),
            setup_pairing_code: Arc::new(Mutex::new(None)),
            session_generation: Arc::new(Mutex::new(0)),
            is_foreground: Arc::new(AtomicBool::new(false)),
            pin4_attempt_gate: Arc::new(Mutex::new(())),
            pin6_attempt_gate: Arc::new(Mutex::new(())),
            argon2_jobs: Arc::new(Semaphore::new(MAX_CONCURRENT_ARGON2_JOBS)),
        }
    }

    pub fn pin_attempt_gate(&self, kind: PinKind) -> Arc<Mutex<()>> {
        match kind {
            PinKind::FourDigit => self.pin4_attempt_gate.clone(),
            PinKind::SixDigit => self.pin6_attempt_gate.clone(),
        }
    }

    pub fn argon2_jobs(&self) -> Arc<Semaphore> {
        self.argon2_jobs.clone()
    }

    pub fn is_foreground(&self) -> bool {
        self.is_foreground.load(Ordering::Acquire)
    }

    pub fn set_foreground(&self, foreground: bool) {
        self.is_foreground.store(foreground, Ordering::Release);
    }

    pub async fn lock(&self) {
        info!("[ferusa:app]: AppState::lock clearing secrets");
        *self.secrets.lock().await = None;
        *self.pairing_replacement_authorized_at.lock().await = None;
        *self.unlocked_at.lock().await = None;
        *self.approval_key_authenticated_at.lock().await = None;
        *self.setup_pairing_code.lock().await = None;
        let mut generation = self.session_generation.lock().await;
        *generation = generation.saturating_add(1);
        debug!("[ferusa:app]: AppState::lock secrets cleared");
    }

    pub async fn start_session(&self) -> u64 {
        *self.unlocked_at.lock().await = Some(Instant::now());
        let mut generation = self.session_generation.lock().await;
        *generation = generation.saturating_add(1);
        *generation
    }
}
