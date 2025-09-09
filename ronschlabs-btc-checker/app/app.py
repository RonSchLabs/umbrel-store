# -*- coding: utf-8 -*-
"""
BTC Checker – v2.2 (Drop-in, nur DB)
- Live-Scan von BTC-Adressen (P2SH + SegWit) mit Zufalls-Seeds
- Korrekte Kumulierung in SQLite (Zeit & geprüfte Adressen) via Hintergrund-Flush
- Web-UI zeigt Session & kumulierte Werte (aus DB) + letzte Funde
"""

import os
import time
import hmac
import ecdsa
import base58
import sqlite3
import hashlib
import threading
import requests
from datetime import datetime
from mnemonic import Mnemonic
from bech32 import bech32_encode, convertbits
from flask import Flask, send_from_directory, request

# ----------------------------- Konfiguration ---------------------------------

__version__ = "2.2"

ADDRESSES_PER_SEED = 10
FIND_LIMIT = 100
PERSIST_INTERVAL_SEC = 5  # wie oft wir Zeit & checked in die DB flushen

# Pfade (Umbrel nutzt /data)
IS_UMBREL = (os.getenv("BTC_MODE") == "umbrel") or os.path.exists("/data")
DB_PATH = "/data/btc_checker.db" if IS_UMBREL else "btc_checker.db"

# Flask
app = Flask(__name__, static_folder="static")

# ------------------------------- Laufzeit-Status ------------------------------

status = {
    "checked": 0,           # Geprüfte Adressen in dieser Session
    "rate": 0.0,            # Adressen/s (Session)
    "found": 0,             # Gefundene Wallets (Session)
    "start_time": time.time()
}

# Persistenz-Helfer für Delta-Flush
_persist_lock = threading.Lock()
_persist_last_checked = 0
_persist_last_ts = time.time()

# ------------------------------- Krypto-Utils --------------------------------

def sha256(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def ripemd160(x: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(x)
    return h.digest()

def pubkey_to_p2sh(pub: bytes) -> str:
    # P2SH-P2WPKH: redeem script 0 <20-byte keyhash>
    h160 = ripemd160(sha256(pub))
    redeem = b"\x00\x14" + h160
    hashed = ripemd160(sha256(redeem))
    payload = b"\x05" + hashed       # 0x05 = mainnet P2SH
    checksum = sha256(sha256(payload))[:4]
    return base58.b58encode(payload + checksum).decode()

def pubkey_to_segwit(pub: bytes) -> str:
    # bech32 P2WPKH
    h160 = ripemd160(sha256(pub))
    five = convertbits(h160, 8, 5)
    return bech32_encode("bc", [0] + five)

def derive_privkey(seed: bytes) -> bytes:
    # dummy-derivation (nicht BIP32), hier reicht deterministische Ableitung
    return hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()[:32]

def check_balance(addr: str) -> float:
    try:
        r = requests.get(f"https://blockstream.info/api/address/{addr}", timeout=10)
        j = r.json()
        funded = j.get("chain_stats", {}).get("funded_txo_sum", 0)
        spent  = j.get("chain_stats", {}).get("spent_txo_sum", 0)
        return (funded - spent) / 1e8
    except Exception:
        # Bei API-Problemen einfach 0 zurück (wir scannen weiter)
        time.sleep(1.5)
        return 0.0

# --------------------------------- SQLite -------------------------------------

def db_connect():
    # isolation_level=None -> autocommit
    return sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)

def db_init():
    con = db_connect()
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            total_hours REAL NOT NULL DEFAULT 0.0,
            total_checked INTEGER NOT NULL DEFAULT 0
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS finds (
            ts TEXT NOT NULL,
            addr TEXT NOT NULL,
            typ TEXT NOT NULL,
            balance REAL NOT NULL,
            seed TEXT NOT NULL
        )
    """)
    # Ensure singleton stats row
    cur.execute("INSERT OR IGNORE INTO stats (id, total_hours, total_checked) VALUES (1, 0.0, 0)")
    con.close()

def db_get_stats():
    con = db_connect()
    cur = con.cursor()
    cur.execute("SELECT total_hours, total_checked FROM stats WHERE id = 1")
    row = cur.fetchone()
    con.close()
    return (row[0] if row else 0.0, row[1] if row else 0)

def db_update_stats(hours_inc: float, checked_inc: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute("""
        UPDATE stats
           SET total_hours = total_hours + ?,
               total_checked = total_checked + ?
         WHERE id = 1
    """, (float(hours_inc), int(checked_inc)))
    con.close()

def db_insert_find(ts: str, addr: str, typ: str, balance: float, seed: str):
    con = db_connect()
    cur = con.cursor()
    cur.execute("INSERT INTO finds (ts, addr, typ, balance, seed) VALUES (?, ?, ?, ?, ?)",
                (ts, addr, typ, float(balance), seed))
    con.close()

def db_get_recent_finds(limit: int = FIND_LIMIT):
    con = db_connect()
    cur = con.cursor()
    cur.execute("""
        SELECT ts, typ, addr, balance, seed
          FROM finds
         ORDER BY ts DESC
         LIMIT ?
    """, (int(limit),))
    rows = cur.fetchall()
    con.close()
    return rows

# ------------------------------ Format-Helfer ---------------------------------

def format_duration(seconds: int) -> str:
    minutes, _ = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts = []
    if days:
        parts.append(f"{days} Tag{'e' if days != 1 else ''}")
    if hours:
        parts.append(f"{hours} Stunde{'n' if hours != 1 else ''}")
    if minutes:
        parts.append(f"{minutes} Minute{'n' if minutes != 1 else ''}")
    return ", ".join(parts) if parts else "weniger als 1 Minute"

def format_duration_hours(total_hours: float) -> str:
    return format_duration(int(total_hours * 3600))

# ---------------------------- Hintergrund-Threads -----------------------------

def persist_loop(interval_sec: int = PERSIST_INTERVAL_SEC):
    """Schreibt fortlaufend Zeit & geprüfte Adressen in die DB (UI-unabhängig)."""
    global _persist_last_checked, _persist_last_ts
    while True:
        time.sleep(interval_sec)
        now = time.time()
        with _persist_lock:
            delta_sec = max(0.0, now - _persist_last_ts)
            delta_checked = max(0, status["checked"] - _persist_last_checked)
            if delta_sec > 0 or delta_checked > 0:
                db_update_stats(hours_inc=delta_sec / 3600.0,
                                checked_inc=delta_checked)
                _persist_last_ts = now
                _persist_last_checked = status["checked"]

def suchroutine():
    mnemo = Mnemonic("english")
    checked, found = 0, 0
    start = time.time()

    print("\n Starte endlose Suche auf P2SH & SegWit mit zufälligen Seeds\n")
    while True:
        mnemonic = mnemo.generate(strength=256)
        seed = mnemo.to_seed(mnemonic)
        priv = derive_privkey(seed)
        sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        pubkey = b"\x04" + vk.to_string()

        for _ in range(ADDRESSES_PER_SEED):
            for addr, typ in [(pubkey_to_p2sh(pubkey), "P2SH"),
                              (pubkey_to_segwit(pubkey), "SegWit")]:
                bal = check_balance(addr)
                checked += 1
                if bal > 0:
                    found += 1
                    ts = datetime.utcnow().isoformat(timespec="seconds")
                    db_insert_find(ts, addr, typ, bal, mnemonic)

                # Session-Status aktualisieren
                status["checked"] = checked
                status["found"] = found
                status["rate"] = checked / max(1e-6, (time.time() - start))

        # kleine Atempause? -> optional
        # time.sleep(0.01)

# --------------------------------- Web-UI -------------------------------------

@app.route("/favicon.ico")
def favicon():
    # Icon liegt als PNG in /app/static; Dockerfile kopiert /app/static
    return send_from_directory(app.static_folder, "icon.png", mimetype="image/png")

@app.route("/")
def show_status():
    # Refresh-Intervall aus Query (Standard 10s)
    try:
        refresh = int(request.args.get("refresh", "10"))
    except ValueError:
        refresh = 10

    laufzeit_session = format_duration(int(time.time() - status["start_time"]))
    total_hours, total_checked = db_get_stats()
    recent = db_get_recent_finds(FIND_LIMIT)

    # Minimal-Styles inline (Self-contained)
    return f"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8" />
<meta http-equiv="refresh" content="{refresh}">
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>BTC Checker · v{__version__}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin: 16px; color: #111; }}
  h1 {{ font-size: 28px; margin: 0 0 12px 0; }}
  .muted a {{ color: #2a6fdb; text-decoration: none; margin-right: 10px; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin: 12px 0 18px 0; }}
  .card {{ border: 1px solid #e8e8e8; border-radius: 12px; padding: 16px; background: #fff; }}
  .hint {{ color: #666; font-size: 13px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 8px; }}
  th, td {{ border: 1px solid #eee; padding: 8px; text-align: left; }}
  th {{ background: #fafafa; }}
  footer {{ margin-top: 18px; color: #777; font-size: 12px; }}
</style>
</head>
<body>
  <h1>BTC Checker · v{__version__}</h1>

  <div class="muted">Refresh:
    <a href="?refresh=5">5s</a>
    <a href="?refresh=10">10s</a>
    <a href="?refresh=30">30s</a>
    <a href="?refresh=60">60s</a>
  </div>

  <div class="grid">
    <div class="card">
      <h3>⏱️ Laufzeit (Session)</h3>
      <p style="font-size:18px;margin:4px 0">{laufzeit_session}</p>
      <div class="hint">Seit App-Start</div>
    </div>

    <div class="card">
      <h3>🧰 Geprüfte Adressen (Session)</h3>
      <p style="font-size:18px;margin:4px 0">{status['checked']:,}</p>
      <div class="hint">Aktuelle Session · Rate: {status['rate']:.2f} Adressen/s</div>
    </div>

    <div class="card">
      <h3>🧮 Gesamt-Laufzeit</h3>
      <p style="font-size:18px;margin:4px 0">{format_duration_hours(total_hours)}  ({total_hours:.1f} h)</p>
      <div class="hint">Kumuliert (aus DB)</div>
    </div>

    <div class="card">
      <h3>📦 Gesamt geprüfte Adressen</h3>
      <p style="font-size:18px;margin:4px 0">{total_checked:,}</p>
      <div class="hint">Kumuliert (aus DB)</div>
    </div>
  </div>

  <h2>🔎 Gefundene Wallets (letzte {FIND_LIMIT})</h2>
  <table>
    <thead>
      <tr><th>Zeit (UTC)</th><th>Typ</th><th>Adresse</th><th>Guthaben (BTC)</th><th>Seed</th></tr>
    </thead>
    <tbody>
      {"".join(f"<tr><td>{ts}</td><td>{typ}</td><td>{addr}</td><td>{balance:.8f}</td><td>{seed}</td></tr>" for ts, typ, addr, balance, seed in recent) or "<tr><td colspan='5' class='hint'>Noch keine Funde</td></tr>"}
    </tbody>
  </table>

  <footer>© BTC Checker · v{__version__}</footer>
</body>
</html>
"""

# --------------------------------- Startpunkt ---------------------------------

if __name__ == "__main__":
    db_init()
    # Worker starten
    threading.Thread(target=suchroutine, daemon=True).start()
    threading.Thread(target=persist_loop, daemon=True).start()
    # Webserver
    app.run(host="0.0.0.0", port=5001)
