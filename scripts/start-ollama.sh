#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
export OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1:11434}"
if [ "${SCANNER_OLLAMA_CPU:-0}" = "1" ]; then
    export OLLAMA_LLM_LIBRARY=cpu
    export LLAMA_ARG_DEVICE=none
    export LLAMA_ARG_FIT=off
fi
export OLLAMA_NO_CLOUD=1
export OLLAMA_NUM_PARALLEL=1
export OLLAMA_MAX_LOADED_MODELS=1
if command -v ollama >/dev/null 2>&1; then
    exec ollama serve
elif [ -x work/ollama/runtime/ollama ]; then
    export OLLAMA_MODELS="$PWD/work/ollama/models"
    exec work/ollama/runtime/ollama serve
else
    echo 'Instale Ollama e baixe qwen2.5:3b conforme o README.' >&2
    exit 2
fi
