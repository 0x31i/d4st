#!/usr/bin/env bash
# Load the d4st image onto an air-gapped host from the offline Release bundle.
#
# Two ways to feed it:
#   A) Download-and-load (host has GitHub reachability, but not GHCR):
#        scripts/airgap-load.sh --release airgap-latest
#   B) Fully offline — you already copied the bundle parts to a directory:
#        scripts/airgap-load.sh --dir /media/usb/d4st-bundle
#
# The bundle = d4st-core.tar.gz.NN.part files + SHA256SUMS (+ IMAGE_REF.txt), produced
# by the airgap-bundle GitHub Action. This reassembles, verifies, and `docker load`s it.
set -euo pipefail

REPO="${D4ST_REPO:-0x31i/d4st}"
REL=""
DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --release) REL="$2"; shift 2 ;;
    --dir)     DIR="$2"; shift 2 ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }

WORK="${DIR:-$(mktemp -d)}"
if [ -n "$REL" ]; then
  command -v gh >/dev/null 2>&1 || { echo "gh CLI needed for --release (or use --dir)" >&2; exit 1; }
  echo "Downloading bundle '$REL' from $REPO …"
  gh release download "$REL" --repo "$REPO" --pattern '*.part' --pattern 'SHA256SUMS' --pattern 'IMAGE_REF.txt' --dir "$WORK" --clobber
fi

cd "$WORK"
ls d4st-core.tar.gz.*.part >/dev/null 2>&1 || { echo "no bundle parts found in $WORK" >&2; exit 1; }

echo "Verifying checksums …"
sha256sum -c SHA256SUMS

echo "Reassembling + loading image …"
cat d4st-core.tar.gz.*.part | gunzip -c | docker load

REF="$(cat IMAGE_REF.txt 2>/dev/null || true)"
echo "Done.${REF:+  Loaded: $REF}"
echo "Now install the launcher offline:  D4ST_IMAGE_TAR=  D4ST_IMAGE='${REF:-ghcr.io/0x31i/d4st:core}' bash install.sh"
echo "(install.sh will see the image is already loaded and skip the pull.)"
