FROM python:3.11-slim

WORKDIR /app

# System deps for psycopg. Scanner tool binaries (katana, nuclei, sqlmap, dalfox,
# ZAP, commix, interactsh) are layered in during Phase 2 via a tools stage; the
# base image here carries the orchestrator + Python deps only.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY dastng/ dastng/

RUN pip install --no-cache-dir .

EXPOSE 8810

CMD ["dast-ng", "serve", "--host", "0.0.0.0", "--port", "8810"]
