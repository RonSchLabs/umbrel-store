# 🧠 BTC Checker – Umbrel App

Ein Tool zur automatisierten Suche nach Bitcoin-Adressen mit Guthaben, basierend auf zufällig generierten Seeds. Zeigt Live-Statistiken direkt im Umbrel-Dashboard.

---

## 🔍 Funktionen

- Generiert kontinuierlich gültige Seeds
- Erstellt P2SH- und SegWit-Adressen
- Prüft Guthaben per Blockstream API
- Speichert Treffer automatisch (inkl. Seed!)
- Zeigt Live-Statistik per Web-UI in Umbrel

---

## 📦 Installation

1. Community App-Store in Umbrel hinzufügen:

```
https://github.com/RonSchLabs/umbrel-store
```


2. App "BTC Checker" auswählen und installieren

3. Webinterface öffnet sich automatisch (Port 5001)

---

## 📁 Ergebnisse

Gefundene Adressen werden automatisch gespeichert unter:

- Umbrel: `/data/gefunden.txt`
- Lokal: `gefunden.txt`

---

## ⚠️ Warnung

Dieses Tool dient ausschließlich **zu Forschungs- und Lernzwecken**.

**Missbrauch oder illegale Nutzung ist untersagt.**

---

## 📷 Vorschau

![Screenshot](https://raw.githubusercontent.com/RonSchLabs/umbrel-store/master/ronschlabs-btc-checker/icon.png)

---

## 🛠️ Entwickler

- Docker-Image: `ronschlabs/btc-checker`
- Umbrel-App Store: [`umbrel-store`](https://github.com/RonSchLabs/umbrel-store)
