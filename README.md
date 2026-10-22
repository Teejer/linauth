# winauth-gtk

A native Linux (Rust + GTK4/libadwaita) TOTP/HOTP authenticator that imports
**WinAuth** backups directly. Born from migrating a WinAuth setup off Windows
without Wine or .NET.

![screenshot placeholder]

## Features

- Imports WinAuth master backups: password-protected `.zip` (ZipCrypto) or
  plain text with one `otpauth://` URI per line
- Standard `otpauth://` support incl. WinAuth quirks (`+` as space in labels,
  unpadded base32, `icon=`/`serial=`/`deviceid=` extras preserved)
- TOTP (SHA1/256/512, any period/digits) and HOTP (counter advances on use)
- Live codes with countdown, click-to-copy, search
- Optional at-rest encryption of the account store
  (Argon2id → XChaCha20-Poly1305)
- Headless mode for scripts/SSH

## Build & install

```sh
cd app
./install.sh            # installs into ~/.local
```

Requires GTK 4.12+, libadwaita 1.4+ dev packages.

## Usage

- Launch **Codes** from your app grid, or run `winauth-gtk`
- Import: toolbar ➜ pick your `Winauth Master ….zip`, enter the backup password
- Click a row to copy its current code
- Autostart: `winauth-gtk --install-autostart`

### Headless

```sh
winauth-gtk codes                     # print current codes
winauth-gtk import backup.zip         # zip pw: $WINAUTH_ZIP_PWD,
                                      # encrypt store with: $WINAUTH_STORE_PWD
```

## Security notes

- Account store: `~/.local/share/winauth-gtk/accounts.json` (mode `0600`);
  save with a master password to encrypt it (Argon2id + XChaCha20-Poly1305)
- Code generation verified against RFC 4226/6238 vectors and independently
  cross-checked against a second implementation of the WinAuth export format

## Not (yet) supported

- WinAuth's non-standard types: Steam mobile confirmations, Battle.net,
  Guild Wars, Okta push, YubiKey HMAC — standard TOTP/HOTP only
- Tray icon (GTK4 dropped StatusIcon; PPA for a `dbusmenu`-based tray)

## Credits

- Concept and export format: [WinAuth](https://github.com/winauth/winauth)
  (this project is an independent native reimplementation, not affiliated)

## License

GPL-3.0
