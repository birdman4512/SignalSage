FROM python:3.12-slim

WORKDIR /app

# Install gcc and other build deps for native extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY signalsage/ ./signalsage/
COPY config/ ./config/

# Optionally bake in the Codex + Claude Code CLIs so the digest.llm_provider: cli
# backend works inside the container (otherwise these CLIs only exist on a host).
# Off by default to keep the image lean; the docker-compose codex/claude profiles
# build with --build-arg INSTALL_CLI_LLM=true. Node 22 LTS is pulled from
# NodeSource; both CLIs are installed globally onto PATH.
ARG INSTALL_CLI_LLM=false
RUN if [ "$INSTALL_CLI_LLM" = "true" ]; then \
        apt-get update \
        && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
        && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
        && apt-get install -y --no-install-recommends nodejs \
        && npm install -g @openai/codex @anthropic-ai/claude-code \
        && npm cache clean --force \
        && apt-get purge -y curl gnupg && apt-get autoremove -y \
        && rm -rf /var/lib/apt/lists/* ; \
    fi

# Run as a non-root user. The /app/data volume is chowned so the digest
# history files can be written; everything else is owned by root + readable.
# (The codex/claude profiles override this with user: "0:0" so the CLI can
# read/refresh the mounted host credentials regardless of their ownership.)
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin signalsage \
    && mkdir -p /app/data \
    && chown -R signalsage:signalsage /app/data
USER signalsage

CMD ["python", "-m", "signalsage.main"]
