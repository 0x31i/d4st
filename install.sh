#!/usr/bin/env bash
# d4st one-command installer.
#
#   curl -fsSL https://raw.githubusercontent.com/0x31i/d4st/main/install.sh | bash
#
# What it does (no source checkout required — just Docker):
#   1. checks Docker is installed + running
#   2. acquires the d4st image  (pull from GHCR, or `docker load` an air-gap tarball)
#   3. creates a workspace at ~/.d4st  (data / sessions / results / runs)
#   4. installs a `d4st` command that runs the container for you
#   5. runs `d4st doctor` so you know it's healthy
#
# Air-gapped host?  Drop the release tarball next to this script (or set
#   D4ST_IMAGE_TAR=/path/to/d4st-core.tar.gz) and it loads that instead of pulling.
set -euo pipefail

IMAGE="${D4ST_IMAGE:-ghcr.io/0x31i/d4st:core}"
HOME_DIR="${D4ST_HOME:-$HOME/.d4st}"
BIN_DIR="${D4ST_BIN:-$HOME/.local/bin}"
SHIM="$BIN_DIR/d4st"

c()  { printf '\033[38;5;141m%s\033[0m\n' "$*"; }   # violet
ok() { printf '\033[38;5;114m  ✓ %s\033[0m\n' "$*"; }
warn(){ printf '\033[38;5;179m  ! %s\033[0m\n' "$*"; }
die() { printf '\033[38;5;203m  ✗ %s\033[0m\n' "$*" >&2; exit 1; }

c ""
c "     ██████╗  ██╗  ██╗ ███████╗ ████████╗"
c "     ██╔══██╗ ██║  ██║ ██╔════╝ ╚══██╔══╝"
c "     ██║  ██║ ███████║ ███████╗    ██║   "
c "     ██║  ██║ ╚════██║ ╚════██║    ██║   "
c "     ██████╔╝      ██║ ███████║    ██║   "
c "     ╚═════╝       ╚═╝ ╚══════╝    ╚═╝   "
c "     standalone open-source DAST appliance"
c ""

# 1. Docker ------------------------------------------------------------------
command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install Docker Engine/Desktop first: https://docs.docker.com/get-docker/"
docker info >/dev/null 2>&1 || die "Docker is installed but not running. Start Docker and re-run."
ok "Docker is installed and running"

# 2. Image -------------------------------------------------------------------
TAR="${D4ST_IMAGE_TAR:-}"
if [ -z "$TAR" ]; then
  for cand in "$(dirname "$0")/d4st-core.tar.gz" "./d4st-core.tar.gz" "$HOME_DIR/d4st-core.tar.gz"; do
    [ -f "$cand" ] && { TAR="$cand"; break; }
  done
fi
if docker image inspect "$IMAGE" >/dev/null 2>&1; then
  ok "image already present locally ($IMAGE) — skipping acquisition"
elif [ -n "$TAR" ] && [ -f "$TAR" ]; then
  c "Loading image from air-gap tarball: $TAR"
  if [[ "$TAR" == *.gz ]]; then gunzip -c "$TAR" | docker load; else docker load -i "$TAR"; fi
  ok "image loaded from tarball"
else
  c "Pulling $IMAGE  (~9 GB, first time only)…"
  docker pull "$IMAGE" || die "pull failed. If this host is air-gapped, fetch the release tarball and re-run with D4ST_IMAGE_TAR=/path/to/d4st-core.tar.gz"
  ok "image pulled"
fi

# 3. Workspace ---------------------------------------------------------------
mkdir -p "$HOME_DIR"/{data,sessions,results,runs}
ok "workspace ready at $HOME_DIR"

# 4. `d4st` command ----------------------------------------------------------
mkdir -p "$BIN_DIR"
cat > "$SHIM" <<SHIM_EOF
#!/usr/bin/env bash
# d4st launcher — runs the containerized appliance against your ~/.d4st workspace.
set -euo pipefail
IMAGE="\${D4ST_IMAGE:-$IMAGE}"
HOME_DIR="\${D4ST_HOME:-$HOME_DIR}"
# interactive TTY when attached to a terminal, plain pipe otherwise (keeps --json clean)
TTY=(-i); [ -t 0 ] && [ -t 1 ] && TTY=(-it)
# only 'serve' needs a published port; avoids clashes between concurrent scans
PORT=(); [ "\${1:-}" = "serve" ] && PORT=(-p 8810:8810)
exec docker run --rm "\${TTY[@]}" "\${PORT[@]}" \\
  -v "\$HOME_DIR/data:/data" \\
  -v "\$HOME_DIR/sessions:/app/sessions" \\
  -v "\$HOME_DIR/results:/app/results" \\
  -v "\$HOME_DIR/runs:/app/runs" \\
  -e D4ST_DB=/data/d4st.db \\
  -e "D4ST_VERIFY_EGRESS_IPS=\${D4ST_VERIFY_EGRESS_IPS:-}" \\
  "\$IMAGE" d4st "\$@"
SHIM_EOF
chmod +x "$SHIM"
ok "installed d4st -> $SHIM"

# 5. PATH + health -----------------------------------------------------------
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) warn "$BIN_DIR is not on your PATH. Add it:  export PATH=\"$BIN_DIR:\$PATH\"  (put it in ~/.bashrc or ~/.zshrc)" ;;
esac

c ""
c "Running a quick health check…"
"$SHIM" doctor || true

c ""
c "Done. Try:"
c "   d4st scan example.com            # the easy button: fingerprint + scan + report"
c "   d4st detect example.com          # just fingerprint + tell you what to run"
c "   d4st init --client Acme --target https://app.example.com   # guided authenticated scan"
c "   d4st serve                       # web console at http://localhost:8810"
c ""
c "Files land in $HOME_DIR (results/, sessions/, data/).   Run  d4st --help  any time."
