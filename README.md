# Ferusa

Ferusa is an experimental two-factor password vault. It combines a Unix command-line
client with an Android approval companion so that the local master password alone is
not enough to decrypt the vault.

> [!WARNING]
> Ferusa is a prototype, has not been independently audited, and is not ready for
> irreplaceable secrets. Read the security limitations before using it.

## How it works

The CLI derives a local secret from the master password with Argon2. The Android app
holds a second share protected by Android Keystore and releases it through an
authenticated pairing and approval flow. The shares are combined to decrypt the
local vault, which uses authenticated encryption.

The phone and CLI communicate over an encrypted peer-to-peer connection provided by
iroh. Pairing includes QR-code exchange, a verification code, and signed state
transitions. Read and write requests use separate phone PINs, and sensitive Android
operations can require biometric authentication.

| Path | Purpose |
| --- | --- |
| `ferusa-core/` | Shared protocol, framing, cryptography, and message types |
| `cli/` | Unix CLI and encrypted local vault storage |
| `app/` | Svelte 5 and Tauri 2 Android approval companion |

## Platform support

- Android companion application
- Unix-like CLI environments

iOS, Windows, and a desktop graphical application are not currently supported.
The repository does not distribute compiled APKs; Android builds must be produced
and signed locally.

## Prerequisites

- A current stable Rust toolchain
- `pnpm`
- Android SDK and NDK, `adb`, and a USB-debuggable Android device
- Network connectivity between the CLI and phone, either directly or through the
  transport used by iroh

## Build and install

Install the CLI from the repository root:

```bash
cargo install --path cli --locked
```

Install the app dependencies and run a development build:

```bash
cd app
pnpm install --frozen-lockfile
pnpm tauri android dev
```

See [the Android build and signing guide](app/build_install.md) for release APK
instructions. Signing keys and generated binaries must remain outside Git.

## First setup

1. Install and open the Android app.
2. Run `ferusa init` in a terminal and choose a strong master password.
3. Scan the displayed QR code with the app and confirm that the verification codes
   match.
4. Complete the PIN and biometric setup on the phone.
5. Optionally configure a clipboard command when prompted.

`ferusa init` creates the vault and its initial phone pairing as one transaction.
Use `ferusa pair` only to replace or repair pairing; replacing a healthy pairing
requires approval from the currently paired phone. Start `ferusa pair`, then choose
**Replace paired desktop** in the unlocked phone app. The current generation remains
active until the desktop vault has been re-encrypted with the new phone share and
both devices have durably committed the replacement.

Common commands:

```bash
ferusa add github
ferusa get github
ferusa edit github
ferusa remove github
ferusa list
# `lock` is available inside the interactive `ferusa` shell only.
ferusa
# then enter: lock
ferusa passwd
ferusa config set --clear-after 30 wl-copy
```

Running `ferusa` without a subcommand opens the interactive shell. On Linux, vault
data is normally stored below `~/.local/share/ferusa/`.

## Development checks

The Rust crates are intentionally independent rather than members of a root Cargo
workspace:

```bash
cargo fmt --manifest-path ferusa-core/Cargo.toml --all -- --check
cargo fmt --manifest-path cli/Cargo.toml --all -- --check
cargo fmt --manifest-path app/src-tauri/Cargo.toml --all -- --check

cargo test --manifest-path ferusa-core/Cargo.toml --locked
cargo test --manifest-path cli/Cargo.toml --locked --all-targets
cargo test --manifest-path app/src-tauri/Cargo.toml --locked --all-targets

cd app
pnpm check
pnpm build
pnpm check:csp
```

The fuzz targets have their own instructions in
[`cli/fuzz/README.md`](cli/fuzz/README.md).

## Security model and limitations

- The Android-held share protects the vault while it is locked. After approval and
  unlock, the desktop process receives enough key material to decrypt the vault and
  must be trusted for the lifetime of that unlocked session. The phone cannot
  cryptographically enforce every subsequent entry operation.
- Resetting the Android app, clearing its data, losing its Keystore material, or
  forgetting pairing can make the existing vault permanently inaccessible. Ferusa
  does not currently provide a documented recovery or export mechanism for a lost
  phone-held factor.
- Clearing app data or uninstalling the phone app is destructive; it is not a
  pairing-replacement workflow. Preserve access to the currently paired phone until
  `ferusa pair` reports that replacement has completed.
- Memory zeroization and platform hardening reduce exposure but cannot guarantee
  protection against a compromised operating system or process.
- The source and tests are available for review, but that is not a substitute for an
  independent security audit.

Please avoid real or irreplaceable credentials while evaluating the project.

## License

Ferusa is available under the [MIT License](LICENSE).
