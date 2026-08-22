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

# Optional PII/PHI engine (Presidio + spaCy model). Enables the industry-grade PII stage
# (emails, SSN, cards w/ Luhn, phones, names via NER, medical IDs). Falls back to a built-in
# email/SSN/card recognizer if skipped.
pip install --only-binary=:all: "spacy==3.7.5" presidio-analyzer >/dev/null 2>&1 && \
  python -m spacy download en_core_web_lg >/dev/null 2>&1 && \
  echo "PII engine (Presidio + en_core_web_lg) installed" || \
  echo "PII engine optional install skipped (built-in fallback will be used)"

# Real-world content-discovery wordlists (SecLists) for feroxbuster.
mkdir -p "$ROOT/vendor/seclists"
for f in common.txt raft-medium-directories.txt; do
  [ -s "$ROOT/vendor/seclists/$f" ] || curl -fsSL -o "$ROOT/vendor/seclists/$f" \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/$f"
done
echo "SecLists wordlists fetched (common.txt, raft-medium-directories.txt)"
