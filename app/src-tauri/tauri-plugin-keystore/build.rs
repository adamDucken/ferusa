const COMMANDS: &[&str] = &[
    "getSecret",
    "setSecret",
    "deleteSecret",
    "clearSecrets",
    "generateApprovalKey",
    "signApproval",
    "deleteApprovalKey",
];

fn main() {
    tauri_plugin::Builder::new(COMMANDS)
        .android_path("android")
        .try_build()
        .expect("failed to build tauri-plugin-keystore");
}
