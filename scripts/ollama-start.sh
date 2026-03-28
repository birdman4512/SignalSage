#!/bin/bash
# Start Ollama server and auto-pull the configured model on first run.

set -e

MODEL="${OLLAMA_MODEL:-gemma2:2b}"

# Start the server in the background
/bin/ollama serve &
SERVER_PID=$!

# Wait until the API is accepting connections
echo "Waiting for Ollama server to start..."
until bash -c 'echo >/dev/tcp/localhost/11434' 2>/dev/null; do
    sleep 2
done
echo "Ollama server ready."

# Pull the model (idempotent — skips if already up to date)
echo "Pulling model: ${MODEL}"
/bin/ollama pull "${MODEL}"
echo "Model ready."

# Hand control back to the server process
wait "${SERVER_PID}"
