#!/bin/sh
# d4st container entrypoint.
#
# Guard against the most common self-host bind-mount mistake: mounting the d4st
# REPO ROOT onto /app/d4st instead of the package directory (<repo>/d4st). That
# buries the Python package one level too deep, so the editable install can't
# import it and the app dies in a restart loop with a cryptic
# "ModuleNotFoundError: No module named 'd4st'". Fail early with a clear fix.
if [ ! -f /app/d4st/__init__.py ]; then
  echo "d4st: FATAL - /app/d4st is not the d4st Python package (no __init__.py there)." >&2
  if [ -f /app/d4st/d4st/__init__.py ]; then
    echo "d4st: You bind-mounted the repo ROOT onto /app/d4st. Mount the PACKAGE subdir instead:" >&2
    echo "d4st:     -v <repo>/d4st:/app/d4st        (note the repeated 'd4st')" >&2
    echo "d4st: Or just run 'docker compose up' from the repo root - ./d4st:/app/d4st resolves correctly there." >&2
  else
    echo "d4st: Expected the d4st package at /app/d4st. Check (or drop) your code bind-mount (-v ...:/app/d4st)." >&2
  fi
  exit 1
fi

exec "$@"
