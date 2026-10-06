#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
mkdir -p work/validation
if ! ./setup.sh --dev >work/validation/test-setup.log 2>&1; then
    echo 'Falha ao preparar testes. Consulte work/validation/test-setup.log.' >&2
    exit 2
fi
export PYTHONDONTWRITEBYTECODE=1
exec .venv/bin/python scripts/validate.py "$@"
