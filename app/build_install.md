# Build, sign, and install the Android APK

Run these commands from the `app/` directory unless stated otherwise.

## Prerequisites

- Android SDK and NDK installed
- `ANDROID_HOME` set
- `adb`, `keytool`, and `pnpm` available in `PATH`
- An Android device connected with USB debugging enabled

Install the JavaScript dependencies and check the device connection:

```bash
cd app
pnpm install --frozen-lockfile
adb devices
```

## Development build

Build, install, and run the development app on the connected device:

```bash
pnpm tauri android dev
```

If the generated Android project is missing, initialize it once:

```bash
pnpm tauri android init
```

## Release APK

Build an unsigned release APK:

```bash
pnpm tauri android build --apk
```

The universal unsigned APK is normally written to:

```text
src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk
```

## Signing key

Choose a private keystore path and alias. Keep the keystore, passwords, and any
generated `keystore.properties` file outside Git.

```bash
export FERUSA_KEYSTORE="$HOME/ferusa-upload-keystore.jks"
export FERUSA_KEY_ALIAS="ferusa"
```

Create a key only when establishing a new signing identity:

```bash
keytool -genkeypair -v \
  -keystore "$FERUSA_KEYSTORE" \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -alias "$FERUSA_KEY_ALIAS"
```

Back up the keystore securely. Losing it prevents future builds from updating an
application installed under that signing identity.

## Sign and verify

Locate `apksigner` from the installed Android build tools:

```bash
APKSIGNER=$(find "$ANDROID_HOME/build-tools" -name apksigner | sort | tail -n 1)
test -n "$APKSIGNER"
```

Sign and verify the APK:

```bash
"$APKSIGNER" sign \
  --ks "$FERUSA_KEYSTORE" \
  --ks-key-alias "$FERUSA_KEY_ALIAS" \
  --out app-universal-release-signed.apk \
  src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk

"$APKSIGNER" verify --verbose app-universal-release-signed.apk
```

`apksigner` should report `Verifies`.

## Install

```bash
adb install -r app-universal-release-signed.apk
```

If Android rejects the update because the signing identity or version is
incompatible, uninstalling first may be necessary:

```bash
adb uninstall com.ferusa.mobile
adb install app-universal-release-signed.apk
```

Warning: uninstalling removes application data, pairing state, PIN hashes, and
Keystore-backed secrets. Existing vault data may become inaccessible.

## Release hygiene

- Never commit APKs, AABs, IDSIG files, keystores, or signing credentials.
- Keep `src-tauri/tauri.conf.json` version metadata and Android `versionCode`
  aligned for distributed builds.
- Record a checksum for every artifact that is distributed.
- Remove local signed output when it is no longer needed:

  ```bash
  rm -f app-universal-release-signed.apk app-universal-release-signed.apk.idsig
  ```
