# Basis-Image
FROM python:3.11-slim

WORKDIR /app

# System-Build-Tools (bei Bedarf minimal)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

# Python-Abhängigkeiten
# (sqlite3 ist in der stdlib, kein pip nötig)
RUN pip install --no-cache-dir \
    flask \
    requests \
    ecdsa \
    base58 \
    mnemonic \
    bech32

# App-Code kopieren
# (Struktur: /app/app.py + /app/static/icon.png)
COPY app/app.py /app/app.py
COPY app/static /app/static

# Port
EXPOSE 5001

# Start
CMD ["python", "app.py"]
