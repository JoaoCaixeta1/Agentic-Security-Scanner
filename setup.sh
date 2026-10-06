#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
python="${PYTHON_BIN:-}"
if [ -z "$python" ]; then
    for candidate in .venv/bin/python python3.13 python3.12 python3.11 python3.10 python3.9 /usr/bin/python3 python3; do
        if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(not ((3,9) <= sys.version_info[:2] <= (3,13)))' 2>/dev/null; then
            python="$candidate"
            break
        fi
    done
fi
if [ -z "$python" ]; then
    echo 'Instale Python 3.9 a 3.13 ou configure PYTHON_BIN.' >&2
    exit 2
fi
export PYTHONDONTWRITEBYTECODE=1
exec "$python" scripts/bootstrap.py "$@"
