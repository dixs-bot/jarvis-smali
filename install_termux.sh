#!/data/data/com.termux/files/usr/bin/bash
set -eu
echo "SMALI JARVIS v0.7.0 — installer"
command -v python >/dev/null 2>&1 || { pkg update; pkg install python; }
ROOT="$HOME/smali-jarvis"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
mkdir -p "$ROOT" "$HOME/storage/shared/SMALI_JARVIS/Logs"
cp "$HERE/main.py" "$HERE/README.md" "$HERE/config.json" "$ROOT/"
chmod 700 "$ROOT/main.py"
echo "Installed: $ROOT"
echo "Run: python $ROOT/main.py"
echo "JSON: python $ROOT/main.py --json \$HOME/storage/shared/SMALI_JARVIS/Logs/audit.json"
