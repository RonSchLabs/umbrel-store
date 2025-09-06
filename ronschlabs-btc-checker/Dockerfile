# Basisbild mit Python
FROM python:3.11-slim

# Arbeitsverzeichnis im Container
WORKDIR /app

# Ihre App‑Dateien kopieren
COPY app/ /app/

# Abhängigkeiten installieren (falls nötig)
RUN pip install flask mnemonic ecdsa base58 bech32 requests

# Port, auf dem Flask läuft (muss mit dem Port in umbrel-app.yml übereinstimmen)
EXPOSE 5001

# Startbefehl
CMD ["python", "app.py"]
