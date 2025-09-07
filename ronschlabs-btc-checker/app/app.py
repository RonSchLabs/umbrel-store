import os, sys, time, hashlib, hmac, ecdsa, base58, requests, threading, sqlite3
from datetime import datetime
from mnemonic import Mnemonic
from bech32 import bech32_encode, convertbits
from flask import Flask, send_from_directory, request

__version__ = "2.0.1"

# Flask App
app = Flask(__name__, static_folder="static")

# ---- Laufzeit-/Status (nur Session) ----
status = {
    "checked": 0,   # Session: geprüfte Adressen
    "rate": 0.0,    # Session: Rate
    "found": 0,     # Session: gefundene Wallets
    "start_time": time.time()
}
ADRESSES_PER_SEED = 10

# ---- Pfade (Umbrel vs. lokal) ----
IS_UMBREL = (os.getenv("BTC_MODE") == "umbrel") or os.path.exists("/data")
SAVE_DIR = "/data" if IS_UMBREL else "."
DB_PATH = os.path.join(SAVE_DIR, "btc-checker.db")

print(f"[INFO] BTC Checker Version: {__version__}")
print(f"[INFO] DB-Pfad: {DB_PATH}")

# ---- DB Helper ----
def db_connect():
    # Eine kurze Verbindung pro Operation ist hier okay
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def db_init():
    """
    Initialisiert die SQLite-DB ohne /data anzulegen.
    - Nutzt /data nur, wenn es existiert UND beschreibbar ist.
    - Fällt sonst auf '.' zurück.
    - Legt Tabellen + Startwerte an.
    """
    global SAVE_DIR, DB_PATH

    desired_dir = "/data" if IS_UMBREL else "."
    save_dir = desired_dir

    # /data niemals selbst anlegen; nur nutzen, wenn vorhanden + schreibbar
    if os.path.isabs(save_dir):
        if not (os.path.isdir(save_dir) and os.access(save_dir, os.W_OK)):
            print("[WARN] /data nicht verfügbar oder nicht schreibbar – falle auf lokalen Ordner zurück.")
            save_dir = "."
    else:
        os.makedirs(save_dir, exist_ok=True)

    SAVE_DIR = save_dir
    DB_PATH = os.path.join(SAVE_DIR, "btc-checker.db")
    print(f"[INFO] DB-Pfad: {DB_PATH}")

    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = con.cursor()
    cur.execute("PRAGMA journal_mode=WAL;")
    cur.execute("PRAGMA synchronous=NORMAL;")

    cur.execute("""
        CREATE TABLE IF NOT EXISTS stats (
            id INTEGER PRIMARY KEY CHECK (id=1),
            total_hours REAL NOT NULL DEFAULT 0.0,
            total_checked INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS finds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            addr TEXT NOT NULL,
            typ TEXT NOT NULL,
            balance_btc REAL NOT NULL,
            seed TEXT NOT NULL
        )
                """)

    # Startwerte
    cur.execute("SELECT COUNT(*) FROM stats")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO stats (id, total_hours, total_checked, updated_at) VALUES (1, ?, ?, ?)",
            (240.0, 1_500_000, datetime.utcnow().isoformat())
        )

    cur.execute("SELECT COUNT(*) FROM finds")
    if cur.fetchone()[0] == 0:
        cur.execute(
            "INSERT INTO finds (ts, addr, typ, balance_btc, seed) VALUES (?,?,?,?,?)",
            (datetime.utcnow().isoformat(), "", "", 0.0, "")
        )

    con.commit()
    con.close()

def db_get_stats():
    with db_connect() as con:
        cur = con.cursor()
        cur.execute("SELECT total_hours, total_checked FROM stats WHERE id=1")
        row = cur.fetchone()
        if row:
            return float(row[0]), int(row[1])
    return 0.0, 0

def db_update_stats(hours_inc: float, checked_inc: int):
    if hours_inc <= 0 and checked_inc <= 0:
        return
    with db_connect() as con:
        cur = con.cursor()
        cur.execute("""
            UPDATE stats
            SET total_hours = total_hours + ?,
                total_checked = total_checked + ?,
                updated_at = ?
            WHERE id=1
        """, (max(0.0, hours_inc), max(0, checked_inc), datetime.utcnow().isoformat()))
        con.commit()

def db_insert_find(addr: str, typ: str, bal_btc: float, seed_words: str):
    with db_connect() as con:
        cur = con.cursor()
        cur.execute(
            "INSERT INTO finds (ts, addr, typ, balance_btc, seed) VALUES (?,?,?,?,?)",
            (datetime.utcnow().isoformat(), addr, typ, float(bal_btc), seed_words)
        )
        con.commit()

def db_get_recent_finds(limit=100):
    with db_connect() as con:
        cur = con.cursor()
        cur.execute("""
            SELECT ts, typ, addr, balance_btc, seed
            FROM finds
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        return cur.fetchall()

db_init()

# ---- Hashfunktionen
def sha256(x): return hashlib.sha256(x).digest()
def ripemd160(x):
    h = hashlib.new("ripemd160"); h.update(x); return h.digest()

# ---- Adressen
def pubkey_to_p2sh(pub):
    h160 = ripemd160(sha256(pub))
    redeem = b'\x00\x14' + h160
    hashed = ripemd160(sha256(redeem))
    payload = b'\x05' + hashed
    return base58.b58encode(payload + sha256(sha256(payload))[:4]).decode()

def pubkey_to_segwit(pub):
    h160 = ripemd160(sha256(pub))
    five = convertbits(h160, 8, 5)
    return bech32_encode("bc", [0] + five)

def derive_privkey(seed):
    return hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()[:32]

# ---- Externe Abfrage
def check_balance(addr):
    try:
        r = requests.get(f"https://blockstream.info/api/address/{addr}", timeout=10)
        j = r.json()
        funded = j.get("chain_stats", {}).get("funded_txo_sum", 0)
        spent  = j.get("chain_stats", {}).get("spent_txo_sum", 0)
        return (funded - spent) / 1e8
    except Exception:
        time.sleep(2)
        return 0.0

# ---- Treffer speichern -> DB
def save(addr, typ, bal, seed_words):
    db_insert_find(addr, typ, bal, seed_words)

# ---- Session-Formatierung
def format_duration(seconds):
    minutes, _ = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts = []
    if days: parts.append(f"{days} Tag{'e' if days != 1 else ''}")
    if hours: parts.append(f"{hours} Stunde{'n' if hours != 1 else ''}")
    if minutes: parts.append(f"{minutes} Minute{'n' if minutes != 1 else ''}")
    return ", ".join(parts) if parts else "weniger als 1 Minute"

# ---- Suchroutine (Thread)
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
        pubkey = b'\x04' + vk.to_string()

        for _ in range(ADRESSES_PER_SEED):
            for addr, typ in [
                (pubkey_to_p2sh(pubkey), "P2SH"),
                (pubkey_to_segwit(pubkey), "SegWit")
            ]:
                bal = check_balance(addr)
                checked += 1
                if bal > 0:
                    found += 1
                    save(addr, typ, bal, mnemonic)

                rate = checked / (time.time() - start)
                status["checked"] = checked
                status["rate"] = rate
                status["found"] = found

                # dezentes Terminal-Update
                sys.stdout.write(
                    f"\r Geprüfte Adressen: {checked:,} | Rate: {rate:.2f} Adressen/s | Gefunden: {found}"
                )
                sys.stdout.flush()

def format_int_de(n: int) -> str:
  # 1_234_567 -> "1.234.567"
  return f"{int(n):,}".replace(",", ".")


def format_total_hours_human(total_hours: float) -> str:
  total_seconds = int(round(total_hours * 3600))
  minutes, _ = divmod(total_seconds, 60)
  hours, minutes = divmod(minutes, 60)
  days, hours = divmod(hours, 24)
  parts = []
  if days: parts.append(f"{days} Tag{'e' if days != 1 else ''}")
  if hours: parts.append(f"{hours} Stunde{'n' if hours != 1 else ''}")
  if minutes or not parts: parts.append(f"{minutes} Minute{'n' if minutes != 1 else ''}")
  return ", ".join(parts)


def format_ts_de(ts: str) -> str:
  # ISO aus DB -> "DD.MM.YYYY HH:MM"
  try:
    dt = datetime.fromisoformat(ts)
  except Exception:
    return ts  # Fallback: Rohwert anzeigen
  return dt.strftime("%d.%m.%Y %H:%M")


# ---- Favicon
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        app.static_folder, 'icon.png', mimetype='image/png'
    )

# ---- Web-UI
_last_persisted_checked = 0  # Session-Helfer

@app.route("/")
@app.route("/")
def show_status():
    global _last_persisted_checked

    try:
        refresh = int(request.args.get("refresh", "10"))
    except ValueError:
        refresh = 10
    if refresh not in (5, 10, 30, 60):
        refresh = 10

    # DB kumuliert updaten
    delta_checked = max(0, status["checked"] - _last_persisted_checked)
    db_update_stats(hours_inc=refresh / 3600.0, checked_inc=delta_checked)
    _last_persisted_checked = status["checked"]

    total_hours, total_checked = db_get_stats()
    laufzeit_session = format_duration(time.time() - status["start_time"])
    laufzeit_total_human = format_total_hours_human(total_hours)

    # Zähler mit deutschem Tausenderpunkt
    session_checked_de = format_int_de(status["checked"])
    total_checked_de = format_int_de(total_checked)

    finds = db_get_recent_finds(limit=100)
    rows = "".join(
        f"<tr><td>{format_ts_de(ts)}</td><td>{typ}</td><td>{addr}</td>"
        f"<td>{bal:.8f}</td><td>{seed}</td></tr>"
        for ts, typ, addr, bal, seed in finds
    )

    return f"""
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8" />
<title>BTC Checker · v{__version__}</title>
<link rel="icon" href="/favicon.ico" sizes="any">
<meta http-equiv="refresh" content="{refresh}">
<style>
 body{{font-family:system-ui,Segoe UI,Roboto,Arial,sans-serif;max-width:880px;margin:32px auto;padding:0 16px}}
 h1{{margin:0 0 16px}}
 .kpi{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
 .card{{border:1px solid #ddd;border-radius:12px;padding:12px}}
 table{{width:100%;border-collapse:collapse}}
 td,th{{border:1px solid #eee;padding:6px 8px;text-align:left}}
 footer{{margin-top:32px;color:#666;font-size:12px}}
</style>
</head>
<body>
  <h1>BTC Checker · v{__version__}</h1>

  <p>Refresh:
    <a href="?refresh=5">5s</a> ·
    <a href="?refresh=10">10s</a> ·
    <a href="?refresh=30">30s</a> ·
    <a href="?refresh=60">60s</a>
  </p>

  <div class="kpi">
    <div class="card">
      <h3>⏱️ Laufzeit (Session)</h3>
      <div>{laufzeit_session}</div>
      <small>Seit App-Start</small>
    </div>
    <div class="card">
      <h3>🧮 Geprüfte Adressen (Session)</h3>
      <div>{session_checked_de}</div>
      <small>Aktuelle Session</small>
    </div>
    <div class="card">
      <h3>🧭 Gesamt-Laufzeit</h3>
      <div>{laufzeit_total_human}</div>
      <small>Kumuliert (aus DB)</small>
    </div>
    <div class="card">
      <h3>📦 Gesamt geprüfte Adressen</h3>
      <div>{total_checked_de}</div>
      <small>Kumuliert (aus DB)</small>
    </div>
  </div>

  <h2>🔎 Gefundene Wallets (letzte 100)</h2>
  <table>
    <thead><tr><th>Zeit</th><th>Typ</th><th>Adresse</th><th>Guthaben (BTC)</th><th>Seed</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>

  <footer>© BTC Checker · v{__version__}</footer>
</body>
</html>
"""

if __name__ == "__main__":
    threading.Thread(target=suchroutine, daemon=True).start()
    app.run(host="0.0.0.0", port=5001)
