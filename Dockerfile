# dast-ng all-in-one scanner image (core subset).
#
# Strategy for painless remote updates: BAKE the heavy, slow-changing scanner tools into
# the image, but install the dast-ng SOURCE editable (pip install -e) so the docker-compose
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
    ghver() { curl -sfL --retry 4 --retry-delay 3 -o /dev/null -w '%{url_effective}' \
                "https://github.com/$1/releases/latest" | sed -E 's#.*/tag/v?##'; }; \
    dl_pd() { \
      repo="$1"; asset="$2"; ver="$(ghver "$repo")"; \
      test -n "$ver"; \
      curl -sfL --retry 4 --retry-delay 3 -o /tmp/t.zip \
        "https://github.com/${repo}/releases/download/v${ver}/${asset}_${ver}_linux_amd64.zip"; \
      unzip -o /tmp/t.zip -d /usr/local/bin "$asset"; rm -f /tmp/t.zip; \
    }; \
    dl_pd projectdiscovery/nuclei nuclei; \
    dl_pd projectdiscovery/katana katana; \
    dl_pd projectdiscovery/interactsh interactsh-client; \
    dver="$(ghver hahwul/dalfox)"; test -n "$dver"; \
    curl -sfL --retry 4 --retry-delay 3 -o /tmp/dalfox.tgz \
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

# --- dast-ng orchestrator (editable install; bind-mount overrides code at runtime) ---
WORKDIR /app
COPY pyproject.toml README.md ./
COPY dastng/ dastng/
RUN pip install --no-cache-dir -e . \
    && python3 -m playwright install --with-deps chromium

EXPOSE 8810
CMD ["dast-ng", "serve", "--host", "0.0.0.0", "--port", "8810"]
