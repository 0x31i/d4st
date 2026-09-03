# d4st all-in-one scanner image (core subset).
#
# Strategy for painless remote updates: BAKE the heavy, slow-changing scanner tools into
# the image, but install the d4st SOURCE editable (pip install -e) so the docker-compose
# bind-mount makes code live. A fix is then just `git pull && docker compose restart` on the
# host — no image rebuild. Only a tool-binary problem needs a rebuild.
#
# Base on the official ZAP image: it already carries the single hardest dependency (Java +
# ZAP + zap-full-scan.py on PATH). We layer the rest of the core roster + the orchestrator.
FROM ghcr.io/zaproxy/zaproxy:stable

USER root
ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/usr/local/bin:/zap:${PATH}" \
    PIP_BREAK_SYSTEM_PACKAGES=1

# --- system deps ---
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl git unzip ca-certificates perl libpq5 jq \
    && rm -rf /var/lib/apt/lists/*

# --- core Go scanner binaries (latest release resolved at build time) ---
# Resolve the version from the `releases/latest` redirect (github.com), NOT api.github.com:
# the unauthenticated API is rate-limited on shared CI runner IPs, which silently yields a
# null version and a 404. The redirect uses github.com (far higher unauth limits) and we
# fail hard if a version can't be resolved. curl retries absorb transient hiccups.
RUN set -eux; \
    ghver() { curl -sfL --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 30 --speed-limit 2048 --speed-time 30 -o /dev/null -w '%{url_effective}' \
                "https://github.com/$1/releases/latest" | sed -E 's#.*/tag/v?##'; }; \
    dl_pd() { \
      repo="$1"; asset="$2"; ver="$(ghver "$repo")"; \
      test -n "$ver"; \
      curl -sfL --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 30 --speed-limit 2048 --speed-time 30 -o /tmp/t.zip \
        "https://github.com/${repo}/releases/download/v${ver}/${asset}_${ver}_linux_amd64.zip"; \
      unzip -o /tmp/t.zip -d /usr/local/bin "$asset"; rm -f /tmp/t.zip; \
    }; \
    dl_pd projectdiscovery/nuclei nuclei; \
    dl_pd projectdiscovery/katana katana; \
    dl_pd projectdiscovery/interactsh interactsh-client; \
    dver="$(ghver hahwul/dalfox)"; test -n "$dver"; \
    curl -sfL --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 30 --speed-limit 2048 --speed-time 30 -o /tmp/dalfox.tgz \
      "https://github.com/hahwul/dalfox/releases/download/v${dver}/dalfox-v${dver}-linux-x86_64.tar.gz"; \
    mkdir -p /tmp/dx; tar -xzf /tmp/dalfox.tgz -C /tmp/dx; \
    mv "$(find /tmp/dx -type f -name dalfox | head -1)" /usr/local/bin/dalfox; \
    rm -rf /tmp/dalfox.tgz /tmp/dx; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/katana /usr/local/bin/interactsh-client /usr/local/bin/dalfox; \
    # ensure zap-full-scan.py is reachable by the adapter (it lives in /zap on the base image)
    [ -f /zap/zap-full-scan.py ] && ln -sf /zap/zap-full-scan.py /usr/local/bin/zap-full-scan.py || true

# nuclei templates (bake so the first scan doesn't stall pulling them)
RUN nuclei -update-templates -silent || true

# --- python scanner tools (git checkouts on PATH) ---
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && printf '#!/usr/bin/env bash\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
    && git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix \
    && printf '#!/usr/bin/env bash\nexec python3 /opt/commix/commix.py "$@"\n' > /usr/local/bin/commix \
    && chmod +x /usr/local/bin/sqlmap /usr/local/bin/commix

# ===================================================================================
# FULL ROSTER — the Phase-5 tools every adapter expects. WITHOUT these baked in, the
# adapters hit "binary not found on PATH" and SILENTLY SKIP inside the container (the
# same class of gap that skipped ZAP). The scanner is only as strong as the tools
# present, so the packaged image must carry the whole roster, not the core subset.
# ===================================================================================

# --- Go toolchain, then go-install the Go-based scanners (no release-asset guesswork) ---
RUN curl -sfL https://go.dev/dl/go1.23.4.linux-amd64.tar.gz -o /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:/root/go/bin:${PATH}" GOBIN=/usr/local/bin GOFLAGS=-buildvcs=false
RUN set -eux; \
    go install github.com/ffuf/ffuf/v2@latest; \
    go install github.com/lc/gau/v2/cmd/gau@latest; \
    go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest; \
    go install github.com/BishopFox/jsluice/cmd/jsluice@latest; \
    go install github.com/Charlie-belmer/nosqli@latest; \
    go install github.com/gitleaks/gitleaks/v8@latest; \
    go install github.com/trufflesecurity/trufflehog/v3@latest

# --- Rust-based scanners (release binaries / official installers, no cargo build) ---
RUN set -eux; \
    curl -sfL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \
      | bash -s -- -b /usr/local/bin; \
    # x8 hidden-parameter finder: resolve latest tag via the releases redirect, grab the binary
    xver="$(curl -sfL --retry 5 --retry-all-errors --connect-timeout 30 -o /dev/null -w '%{url_effective}' https://github.com/Sh1Yo/x8/releases/latest | sed -E 's#.*/tag/v?##')"; \
    curl -sfL --retry 5 --retry-delay 3 --retry-all-errors --connect-timeout 30 --speed-limit 2048 --speed-time 30 \
      -o /usr/local/bin/x8 "https://github.com/Sh1Yo/x8/releases/download/v${xver}/x8_linux_amd64" \
      && chmod +x /usr/local/bin/x8

# --- apt scanner (Ruby) ---
RUN apt-get update && apt-get install -y --no-install-recommends whatweb \
    && rm -rf /var/lib/apt/lists/*

# --- pip scanners ---
RUN pip install --no-cache-dir semgrep schemathesis xsrfprobe

# --- git-clone Python/Perl/bash tools + PATH wrappers ---
RUN set -eux; \
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
      && ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl.sh; \
    git clone --depth 1 https://github.com/r0oth3x49/ghauri.git /opt/ghauri \
      && pip install --no-cache-dir /opt/ghauri; \
    git clone --depth 1 https://github.com/vladko312/SSTImap.git /opt/sstimap \
      && pip install --no-cache-dir -r /opt/sstimap/requirements.txt \
      && printf '#!/usr/bin/env bash\nexec python3 /opt/sstimap/sstimap.py "$@"\n' > /usr/local/bin/sstimap; \
    git clone --depth 1 https://github.com/dolevf/graphw00f.git /opt/graphw00f \
      && printf '#!/usr/bin/env bash\nexec python3 /opt/graphw00f/main.py "$@"\n' > /usr/local/bin/graphw00f; \
    git clone --depth 1 https://github.com/devanshbatham/OpenRedireX.git /opt/openredirex \
      && (pip install --no-cache-dir -r /opt/openredirex/requirements.txt || true) \
      && printf '#!/usr/bin/env bash\nexec python3 /opt/openredirex/openredirex.py "$@"\n' > /usr/local/bin/openredirex; \
    git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/jwt_tool \
      && (pip install --no-cache-dir pycryptodomex termcolor requests || true) \
      && printf '#!/usr/bin/env bash\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool; \
    git clone --depth 1 https://github.com/wireghoul/dotdotpwn.git /opt/dotdotpwn \
      && printf '#!/usr/bin/env bash\nexec perl /opt/dotdotpwn/dotdotpwn.pl "$@"\n' > /usr/local/bin/dotdotpwn; \
    chmod +x /usr/local/bin/sstimap /usr/local/bin/graphw00f /usr/local/bin/openredirex \
             /usr/local/bin/jwt_tool /usr/local/bin/dotdotpwn

# --- d4st orchestrator (editable install; bind-mount overrides code at runtime) ---
WORKDIR /app
COPY pyproject.toml README.md ./
COPY d4st/ d4st/
RUN pip install --no-cache-dir -e . \
    && python3 -m playwright install --with-deps chromium

EXPOSE 8810
CMD ["d4st", "serve", "--host", "0.0.0.0", "--port", "8810"]
