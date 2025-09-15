# ronschlabs-btc-checker/Dockerfile
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=Europe/Berlin

WORKDIR /app

# Zeitzone (für korrekte Europe/Berlin-Zeit)
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/*

# Python-Abhängigkeiten (alle sind pure-Python → kein build-essential nötig)
RUN pip install --no-cache-dir \
    flask \
    requests \
    ecdsa \
    base58 \
    mnemonic \
    bech32 \
    python-dotenv

# App-Code kopieren
COPY ronschlabs-btc-checker/app/app.py /app/app.py
COPY ronschlabs-btc-checker/app/static /app/static

EXPOSE 5001
CMD ["python", "app.py"]
