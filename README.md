# LinAuth

A native Linux (Rust + GTK4/libadwaita) TOTP/HOTP authenticator that imports
**WinAuth** backups directly. Born from migrating a WinAuth setup off Windows
without Wine or .NET — the name is the natural conclusion.

![screenshot placeholder]

## Features

- Imports WinAuth master backups: password-protected `.zip` (ZipCrypto) or
  plain text with one `otpauth://` URI per line
- Exports backups in WinAuth's own format — ZipCrypto-protected zip with a
  `.txt` entry named after the zip (or plain `.txt`), restorable by WinAuth
- Standard `otpauth://` support incl. WinAuth quirks (`+` as space in labels,
  unpadded base32, `icon=`/`serial=`/`deviceid=` extras preserved)
- TOTP (SHA1/256/512, any period/digits) and HOTP (counter advances on use)
- Live codes with countdown, double-click to copy, search
- Optional at-rest encryption of the account store
  (Argon2id → XChaCha20-Poly1305)
- Headless mode for scripts/SSH

## Build & install

```sh
cd app
./install.sh            # installs into ~/.local (absolute Exec; works with any PATH)
```

Requires GTK 4.12+, libadwaita 1.4+ dev packages.

## Usage

- Launch **LinAuth** from your app grid, or run `linauth`
- Import: toolbar ➜ pick your `Winauth Master ….zip`, enter the backup password
- Double-click a row to copy its current code (Enter works too)
- Menu (☰) ➜ **Preferences**: copy-on-single-click, start-on-login, master
  password, store location, export
- Menu (☰) ➜ **Master password…** to encrypt the store at rest, change or
  remove the password; on an unencrypted store the app also asks once at startup
- Autostart: `linauth --install-autostart`

### Headless

```sh
linauth codes                     # print current codes
linauth import backup.zip         # zip pw: $WINAUTH_ZIP_PWD,
                                  # encrypt store with: $WINAUTH_STORE_PWD
linauth export backup.zip         # WinAuth-compatible backup;
                                  # password from $WINAUTH_ZIP_PWD (.txt = plain)
```

## Security notes

- Account store: `~/.local/share/linauth/accounts.json` (mode `0600`) — set a
  master password (☰ menu) to encrypt it at rest with Argon2id +
  XChaCha20-Poly1305; the plaintext copy is deleted when encryption is enabled
- Code generation verified against RFC 4226/6238 vectors and independently
  cross-checked against a second implementation of the WinAuth export format

## Not (yet) supported

- WinAuth's non-standard types: Steam mobile confirmations, Battle.net,
  Guild Wars, Okta push, YubiKey HMAC — standard TOTP/HOTP only
- Tray icon (GTK4 dropped StatusIcon; planned via StatusNotifierItem)

## Credits

- Concept and export format: [WinAuth](https://github.com/winauth/winauth)
  (this project is an independent native reimplementation, not affiliated)

## License

GPL-3.0
