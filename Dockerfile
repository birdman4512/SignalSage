FROM python:3.14-slim

WORKDIR /app

# Hash-pinned dependencies; all ship binary wheels, so no compiler is needed.
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY signalsage/ ./signalsage/
COPY config/ ./config/

# Record the commit being built so !version can report it. .dockerignore lets
# only .git/HEAD and the refs through; a context without .git records nothing.
RUN --mount=type=bind,target=/tmp/context python -m signalsage.version /tmp/context

# Run as a non-root user. /app/data is the only writable path (SQLite store).
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin signalsage \
    && mkdir -p /app/data \
    && chown -R signalsage:signalsage /app/data
USER signalsage

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health/ready', timeout=2)" || exit 1

CMD ["python", "-m", "signalsage.main"]
