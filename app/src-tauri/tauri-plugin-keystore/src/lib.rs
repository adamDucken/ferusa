use serde::Deserialize;
#[cfg(target_os = "android")]
use serde::Serialize;
#[cfg(target_os = "android")]
use tauri::plugin::PluginHandle;
use tauri::{
    plugin::{Builder, TauriPlugin},
    AppHandle, Manager, Runtime,
};

#[cfg(target_os = "android")]
const PLUGIN_IDENTIFIER: &str = "com.plugin.keystore";

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[cfg(target_os = "android")]
    #[error(transparent)]
    MobileInvoke(#[from] tauri::plugin::mobile::PluginInvokeError),
    #[cfg(not(target_os = "android"))]
    #[error("keystore plugin is only available on Android")]
    UnsupportedPlatform,
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(target_os = "android")]
#[derive(Serialize)]
struct SecretKeyPayload<'a> {
    key: &'a str,
}

#[cfg(target_os = "android")]
#[derive(Serialize)]
struct SetSecretPayload<'a> {
    key: &'a str,
    value: &'a str,
}

#[cfg(target_os = "android")]
#[derive(Serialize)]
struct ApprovalKeyPayload<'a> {
    alias: &'a str,
}

#[cfg(target_os = "android")]
#[derive(Serialize)]
struct SignApprovalPayload<'a> {
    alias: &'a str,
    #[serde(rename = "payloadHex")]
    payload_hex: &'a str,
}

#[cfg(target_os = "android")]
#[derive(Deserialize)]
struct SecretResponse {
    value: Option<String>,
}

#[cfg(target_os = "android")]
#[derive(Deserialize)]
struct HexResponse {
    value: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClockSnapshot {
    pub elapsed_realtime_ms: u64,
    pub boot_count: u64,
}

#[cfg(target_os = "android")]
pub struct Keystore<R: Runtime> {
    handle: PluginHandle<R>,
}

#[cfg(not(target_os = "android"))]
pub struct Keystore<R: Runtime>(std::marker::PhantomData<fn() -> R>);

#[cfg(target_os = "android")]
impl<R: Runtime> Keystore<R> {
    fn clock_snapshot(&self) -> Result<ClockSnapshot> {
        self.handle
            .run_mobile_plugin("clockSnapshot", ())
            .map_err(Into::into)
    }

    fn get_secret(&self, key: &str) -> Result<Option<String>> {
        let res: SecretResponse = self
            .handle
            .run_mobile_plugin("getSecret", SecretKeyPayload { key })?;
        Ok(res.value)
    }

    fn set_secret(&self, key: &str, value: &str) -> Result<()> {
        self.handle
            .run_mobile_plugin::<()>("setSecret", SetSecretPayload { key, value })?;
        Ok(())
    }

    fn delete_secret(&self, key: &str) -> Result<()> {
        self.handle
            .run_mobile_plugin::<()>("deleteSecret", SecretKeyPayload { key })?;
        Ok(())
    }

    fn clear_secrets(&self) -> Result<()> {
        self.handle.run_mobile_plugin::<()>("clearSecrets", ())?;
        Ok(())
    }

    fn generate_approval_key(&self, alias: &str) -> Result<String> {
        let res: HexResponse = self
            .handle
            .run_mobile_plugin("generateApprovalKey", ApprovalKeyPayload { alias })?;
        Ok(res.value)
    }

    fn sign_approval(&self, alias: &str, payload_hex: &str) -> Result<String> {
        let res: HexResponse = self
            .handle
            .run_mobile_plugin("signApproval", SignApprovalPayload { alias, payload_hex })?;
        Ok(res.value)
    }

    fn delete_approval_key(&self, alias: &str) -> Result<()> {
        self.handle
            .run_mobile_plugin::<()>("deleteApprovalKey", ApprovalKeyPayload { alias })?;
        Ok(())
    }
}

#[cfg(not(target_os = "android"))]
impl<R: Runtime> Keystore<R> {
    fn clock_snapshot(&self) -> Result<ClockSnapshot> {
        Err(Error::UnsupportedPlatform)
    }

    fn get_secret(&self, _key: &str) -> Result<Option<String>> {
        Err(Error::UnsupportedPlatform)
    }

    fn set_secret(&self, _key: &str, _value: &str) -> Result<()> {
        Err(Error::UnsupportedPlatform)
    }

    fn delete_secret(&self, _key: &str) -> Result<()> {
        Err(Error::UnsupportedPlatform)
    }

    fn clear_secrets(&self) -> Result<()> {
        Err(Error::UnsupportedPlatform)
    }

    fn generate_approval_key(&self, _alias: &str) -> Result<String> {
        Err(Error::UnsupportedPlatform)
    }

    fn sign_approval(&self, _alias: &str, _payload_hex: &str) -> Result<String> {
        Err(Error::UnsupportedPlatform)
    }

    fn delete_approval_key(&self, _alias: &str) -> Result<()> {
        Err(Error::UnsupportedPlatform)
    }
}

pub trait KeystoreExt<R: Runtime> {
    fn keystore(&self) -> &Keystore<R>;
}

impl<R: Runtime, T: Manager<R>> KeystoreExt<R> for T {
    fn keystore(&self) -> &Keystore<R> {
        self.state::<Keystore<R>>().inner()
    }
}

pub fn get_secret<R: Runtime>(app: &AppHandle<R>, key: &str) -> Result<Option<String>> {
    app.keystore().get_secret(key)
}

pub fn clock_snapshot<R: Runtime>(app: &AppHandle<R>) -> Result<ClockSnapshot> {
    app.keystore().clock_snapshot()
}

pub fn set_secret<R: Runtime>(app: &AppHandle<R>, key: &str, value: &str) -> Result<()> {
    app.keystore().set_secret(key, value)
}

pub fn delete_secret<R: Runtime>(app: &AppHandle<R>, key: &str) -> Result<()> {
    app.keystore().delete_secret(key)
}

pub fn clear_secrets<R: Runtime>(app: &AppHandle<R>) -> Result<()> {
    app.keystore().clear_secrets()
}

pub fn generate_approval_key<R: Runtime>(app: &AppHandle<R>, alias: &str) -> Result<String> {
    app.keystore().generate_approval_key(alias)
}

pub fn sign_approval<R: Runtime>(
    app: &AppHandle<R>,
    alias: &str,
    payload_hex: &str,
) -> Result<String> {
    app.keystore().sign_approval(alias, payload_hex)
}

pub fn delete_approval_key<R: Runtime>(app: &AppHandle<R>, alias: &str) -> Result<()> {
    app.keystore().delete_approval_key(alias)
}

#[cfg(target_os = "android")]
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("keystore")
        .setup(|app, _api| {
            let handle = _api.register_android_plugin(PLUGIN_IDENTIFIER, "KeystorePlugin")?;
            app.manage(Keystore { handle });

            Ok(())
        })
        .build()
}

#[cfg(not(target_os = "android"))]
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("keystore").build()
}
