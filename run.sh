#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if [ -n "${PYTHON_BIN:-}" ]; then
    python="$PYTHON_BIN"
elif [ -x .venv/bin/python ]; then
    python=.venv/bin/python
else
    python=""
    for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 /usr/bin/python3 python3; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(not ((3,9) <= sys.version_info[:2] <= (3,13)))' 2>/dev/null; then
            python="$candidate"
            break
        fi
    done
    if [ -z "$python" ]; then
        printf '%s\n' '{"schema_version":"1.0","status":"error","findings":[],"errors":[{"code":"python_missing","message":"Instale Python 3.9 a 3.13."}]}' > findings.json
        echo 'Erro: instale Python 3.9 a 3.13 ou configure PYTHON_BIN.' >&2
        exit 2
    fi
fi
export PYTHONDONTWRITEBYTECODE=1
exec "$python" scripts/bootstrap.py --run "$@"
