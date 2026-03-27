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

CMD ["python", "-m", "signalsage.main"]
