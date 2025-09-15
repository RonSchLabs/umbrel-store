FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=Europe/Berlin

WORKDIR /app

# Zeitzone (für Europe/Berlin)
RUN apt-get update && apt-get install -y --no-install-recommends tzdata \
 && rm -rf /var/lib/apt/lists/*

# Python-Abhängigkeiten (alles pure-Python; kein build-essential nötig)
RUN pip install --no-cache-dir \
    flask \
    requests \
    ecdsa \
    base58 \
    mnemonic \
    bech32 \
    python-dotenv

# WICHTIG: Build-Kontext ist ./ronschlabs-btc-checker
# => also nur 'app/…' kopieren, nicht 'ronschlabs-btc-checker/app/…'
COPY app/app.py /app/app.py
COPY app/static /app/static

EXPOSE 5001
CMD ["python", "app.py"]
