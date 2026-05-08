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

# Run as a non-root user. The /app/data volume is chowned so the digest
# history files can be written; everything else is owned by root + readable.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin signalsage \
    && mkdir -p /app/data \
    && chown -R signalsage:signalsage /app/data
USER signalsage

CMD ["python", "-m", "signalsage.main"]
