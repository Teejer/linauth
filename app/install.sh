#!/usr/bin/env bash
# Install winauth-gtk for the current user.
#   PREFIX=~/.local  ./install.sh          (default)
set -euo pipefail
PREFIX="${PREFIX:-$HOME/.local}"
here="$(cd "$(dirname "$0")" && pwd)"

cargo build --release --manifest-path "$here/Cargo.toml"

install -Dm755 "$here/target/release/winauth-gtk" "$PREFIX/bin/winauth-gtk"
install -Dm644 "$here/data/winauth-gtk.svg" "$PREFIX/share/icons/hicolor/scalable/apps/winauth-gtk.svg"
install -Dm644 "$here/data/winauth-gtk.desktop" "$PREFIX/share/applications/winauth-gtk.desktop"

update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
gtk-update-icon-cache -q "$PREFIX/share/icons/hicolor" 2>/dev/null || true

echo "installed:"
echo "  $PREFIX/bin/winauth-gtk"
echo "  $PREFIX/share/applications/winauth-gtk.desktop"
echo "make sure $PREFIX/bin is in your PATH"
