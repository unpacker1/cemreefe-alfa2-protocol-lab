#!/usr/bin/env bash
# Termux: create a FRESH public repo from THIS clean-room directory only.
# Never clones, forks, mirrors or modifies private repositories.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$ROOT"
for cmd in gh git python3; do command -v "$cmd" >/dev/null || { echo "Eksik: $cmd"; exit 2; }; done
python3 tools/public_guard.py .
if ! python3 -c 'import msgpack' >/dev/null 2>&1; then
  echo 'Gerekli: python3 -m pip install -e .'
  exit 2
fi
PYTHONPATH=src python3 -m unittest discover -s tests -v
if [ -d .git ]; then
  echo 'Bu klasörde mevcut Git geçmişi var: güvenlik için işlem durduruldu.'
  exit 2
fi
gh auth status >/dev/null || { echo 'gh auth login yapın.'; exit 2; }
OWNER="$(gh api user --jq .login)"
REMOTE="$OWNER/cemreefe-alfa2-protocol-lab"
if gh repo view "$REMOTE" >/dev/null 2>&1; then
  echo "Repo zaten var; mevcut depoya yanlışlıkla push yapılmasın diye durduruldu: $REMOTE"
  exit 2
fi
printf '\nYalnız %s içindeki TEMİZ sentetik kodlar PUBLIC olacak.\n' "$ROOT"
printf 'Orijinal oyun dosyaları / DB / Git geçmişi yüklenmeyecek.\n'
read -r -p "Devam etmek için PUBLIC yaz: " answer
if [ "$answer" != PUBLIC ]; then echo 'Vazgeçildi.'; exit 0; fi
# Prevent injecting original files after the explicit user confirmation.
python3 tools/public_guard.py .
git init -b main
git config user.name "$(gh api user --jq .login)"
git config user.email "$(gh api user --jq .id)+${OWNER}@users.noreply.github.com"
git add -A
python3 tools/public_guard.py .
git commit -m 'chore: initial sanitized native GC and Alfa2 v12 protocol regression lab'
gh repo create "$REMOTE" --public --source=. --remote=origin --push \
  --description 'Sanitized, clean-room GAME framing and Alfa2 v12 MessagePack test lab; no original game files or secrets'
printf '\nPUBLIC repository: https://github.com/%s\n' "$REMOTE"
