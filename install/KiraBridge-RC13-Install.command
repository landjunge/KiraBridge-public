#!/bin/bash
set -uo pipefail
export PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
ROOT="$HOME/Downloads/KiraBridge-proxy-e818ced"
COMMIT="cd09204504402237cb3c927b7d09c4d012c10f22"
PY="/usr/local/bin/python3.11"
LOG="$HOME/Downloads/KiraBridge-RC13-Install-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1
echo "KiraBridge RC13: $LOG"
die(){ echo "FEHLER: $*"; exit 1; }
test -f "$ROOT/installer/install.py" || die "Quellcode fehlt: $ROOT/installer/install.py"
test -x "$PY" || die "Python 3.11 fehlt: $PY"
command -v git >/dev/null || die "Git fehlt"
ACTUAL="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null)" || die "Git-Commit nicht lesbar"
test "$ACTUAL" = "$COMMIT" || die "Anderer Quellstand: $ACTUAL"
git -C "$ROOT" diff --quiet HEAD -- installer/install.py pyproject.toml src/kirabridge/__init__.py src/kirabridge/threaddesk_dynamic.py uv.lock || die "Installer-Quelldateien wurden lokal veraendert"
"$PY" "$ROOT/installer/install.py" prepare --repo "$ROOT" --ref "$COMMIT" || die "Vorbereitung fehlgeschlagen"
"$PY" "$ROOT/installer/install.py" install --repo "$ROOT" --ref "$COMMIT"
STATUS=$?
if [ "$STATUS" -ne 0 ]; then
 echo "Dienststart fehlgeschlagen (Exit: $STATUS). Diagnosedaten:"
 /bin/launchctl print "gui/$(id -u)/com.kirabridge.bridge" 2>&1 | tail -n 35 || true
 for f in "$HOME/.local/share/kirabridge/install/logs/service.stderr.log" "$HOME/.local/share/kirabridge/install/logs/service.stdout.log"; do
  test -f "$f" && { echo "=== $f ==="; tail -n 60 "$f"; }
 done
 die "RC13 nicht aktiviert. Keine erneute Installation ohne Reparatur."
fi
"$PY" - "$HOME/.local/share/kirabridge/install/current.json" "$COMMIT" <<'PY'
import json,sys
with open(sys.argv[1],encoding="utf-8") as f: state=json.load(f)
if state.get("version")!="0.8.0rc13" or state.get("commit")!=sys.argv[2]:
    raise SystemExit("FEHLER: RC13 nicht als aktiv bestaetigt")
print("RC13 im Installationsstatus bestaetigt.")
PY
