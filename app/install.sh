#!/usr/bin/env bash
# Install winauth-gtk.
#   ./install.sh                          -> ~/.local  (needs ~/.local/bin on PATH)
#   sudo PREFIX=/usr/local ./install.sh   -> system-wide (recommended: GNOME's
#                                            session PATH may not include ~/.local/bin)
set -euo pipefail
PREFIX="${PREFIX:-$HOME/.local}"
here="$(cd "$(dirname "$0")" && pwd)"
ID=io.github.teejer.WinAuthGtk

cargo build --release --manifest-path "$here/Cargo.toml"

install -Dm755 "$here/target/release/winauth-gtk" "$PREFIX/bin/winauth-gtk"
install -Dm644 "$here/data/$ID.svg" "$PREFIX/share/icons/hicolor/scalable/apps/$ID.svg"
sed "s|@PREFIX@|$PREFIX|g" "$here/data/$ID.desktop.in" > "$PREFIX/share/applications/$ID.desktop"

# hicolor theme in $PREFIX needs an index.theme for icon lookup to find it
if [ ! -f "$PREFIX/share/icons/hicolor/index.theme" ]; then
    cat > "$PREFIX/share/icons/hicolor/index.theme" <<'EOF'
[Icon Theme]
Name=hicolor
Comment=Fallback icon theme
Directories=scalable/apps

[scalable/apps]
Contexts=Applications
MinSize=1
MaxSize=512
Size=48
Type=Scalable
EOF
fi

update-desktop-database "$PREFIX/share/applications" 2>/dev/null || true
gtk-update-icon-cache -q "$PREFIX/share/icons/hicolor" 2>/dev/null || true

echo "installed:"
echo "  $PREFIX/bin/winauth-gtk"
echo "  $PREFIX/share/applications/$ID.desktop"
echo "  $PREFIX/share/icons/hicolor/scalable/apps/$ID.svg"
