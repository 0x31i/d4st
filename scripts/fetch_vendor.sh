#!/usr/bin/env bash
# Fetch the vendored payload corpora + templates the LFI/RFI adapters depend on.
# Kept out of git (see .gitignore) so the repo stays lean; run once after clone.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$ROOT/vendor"

# PayloadsAllTheThings — File Inclusion + Directory Traversal corpora (sparse, shallow)
if [ ! -d "$ROOT/vendor/PayloadsAllTheThings/File Inclusion" ]; then
  git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/swisskyrepo/PayloadsAllTheThings.git "$ROOT/vendor/PayloadsAllTheThings"
  git -C "$ROOT/vendor/PayloadsAllTheThings" sparse-checkout set \
    "File Inclusion" "Directory Traversal"
fi

# dotdotpwn — vendored Perl traversal engine (bounded single-endpoint adapter)
if [ ! -f "$ROOT/vendor/dotdotpwn/dotdotpwn.pl" ]; then
  git clone --depth 1 https://github.com/wireghoul/dotdotpwn.git "$ROOT/vendor/dotdotpwn"
fi

# nuclei fuzzing-templates — the LFI/RFI payload-breadth lever (into the user templates dir)
FT="${HOME}/nuclei-templates/fuzzing-templates"
if [ ! -d "$FT" ]; then
  git clone --depth 1 https://github.com/projectdiscovery/fuzzing-templates.git "$FT"
fi
echo "vendor fetch complete: PayloadsAllTheThings, dotdotpwn, nuclei fuzzing-templates"
