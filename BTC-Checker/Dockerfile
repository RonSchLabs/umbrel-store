FROM python:3.11-slim

# Setze Arbeitsverzeichnis
WORKDIR /app

# Kopiere Quellcode
COPY ./app /app

# Kopiere requirements separat
COPY requirements.txt /app

# Installiere Abhängigkeiten
RUN pip install --no-cache-dir -r requirements.txt

# Setze Umgebungsvariablen
ENV BTC_MODE=umbrel

# Starte Anwendung
CMD ["python3", "app.py"]
