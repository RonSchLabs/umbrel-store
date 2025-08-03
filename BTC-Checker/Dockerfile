FROM python:3.11-slim

# Arbeitsverzeichnis
WORKDIR /app

# Quellcode kopieren
COPY ./app /app

# requirements.txt separat kopieren
COPY requirements.txt .

# Anforderungen installieren
RUN pip install --no-cache-dir -r requirements.txt

# Umbrel-Modus aktivieren
ENV BTC_MODE=umbrel

# Als unprivilegierter Benutzer laufen lassen
USER 1000:1000

# Anwendung starten
CMD ["python", "./app.py"]
