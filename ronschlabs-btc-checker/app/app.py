import os, sys, time, hashlib, hmac, ecdsa, base58, requests, threading, sqlite3
from datetime import datetime
from mnemonic import Mnemonic
from bech32 import bech32_encode, convertbits
from flask import Flask, send_from_directory, request

__version__ = "2.0"

# Flask App
app = Flask(__name__, static_folder="static")

# ---- Laufzeit-/Status (nur Session) ----
status = {
    "checked": 0,            # Session: geprüfte Adressen
    "rate": 0.0,             # Session: Rate
    "found": 0,              # Session: gefundene Wallets
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
  """Initialisiert die SQLite-DB ohne /data anzulegen.
  - Nutzt /data nur, wenn es existiert UND beschreibbar ist.
  - Fällt sonst auf '.' zurück.
  - Legt Tabellen + Startwerte an.
  """
  import sqlite3
  from datetime import datetime
  global SAVE_DIR, DB_PATH

  # Zielverzeichnis bestimmen (Umbrel bevorzugt /data)
  desired_dir = "/data" if IS_UMBREL else "."
  save_dir = desired_dir

  # /data niemals selbst anlegen; nur nutzen, wenn vorhanden + schreibbar
  if os.path.isabs(save_dir):
    if not (os.path.isdir(save_dir) and os.access(save_dir, os.W_OK)):
      print("[WARN] /data nicht verfügbar oder nicht schreibbar – falle auf lokalen Ordner zurück.")
      save_dir = "."
  else:
    # Lokale Pfade dürfen wir anlegen
    os.makedirs(save_dir, exist_ok=True)

  # Globale Pfade aktualisieren
  SAVE_DIR = save_dir
  DB_PATH = os.path.join(SAVE_DIR, "btc-checker.db")
  print(f"[INFO] DB-Pfad: {DB_PATH}")

  # DB öffnen + Basis-Setup
  con = sqlite3.connect(DB_PATH, check_same_thread=False)
  cur = con.cursor()
  # leichte Robustheit/Performance
  cur.execute("PRAGMA journal_mode=WAL;")
  cur.execute("PRAGMA synchronous=NORMAL;")

  # Eine Zeile mit kumulierten Werten
  cur.execute("""
              CREATE TABLE IF NOT EXISTS stats (
                  id INTEGER PRIMARY KEY CHECK (id=1),
                  total_hours REAL NOT NULL DEFAULT 0.0,
                  total_checked INTEGER NOT NULL DEFAULT 0,
                  updated_at TEXT NOT NULL
                  )
              """)

  # Trefferliste
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

  # Startwerte nur beim allerersten Mal
  cur.execute("SELECT COUNT(*) FROM stats")
  if cur.fetchone()[0] == 0:
    cur.execute(
      "INSERT INTO stats (id, total_hours, total_checked, updated_at) VALUES (1, ?, ?, ?)",
      (240.0, 1_500_000, datetime.utcnow().isoformat())
    )

  # Beispiel-/Platzhalter-Eintrag für finds (nur wenn leer)
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
def ripemd160(x): h = hashlib.new("ripemd160"); h.update(x); return h.digest()

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

def derive_privkey(seed): return hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()[:32]

# ---- Externe Abfrage
def check_balance(addr):
    try:
        r = requests.get(f"https://blockstream.info/api/address/{addr}", timeout=10)
        j = r.json()
        funded = j.get("chain_stats", {}).get("funded_txo_sum", 0)
        spent = j.get("chain_stats", {}).get("spent_txo_sum", 0)
        return (funded - spent) / 1e8
    except Exception:
        time.sleep(2)
        return 0.0

# ---- Treffer speichern -> jetzt DB
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

    print("🔍 Starte endlose Suche auf P2SH & SegWit mit zufälligen Seeds\n")

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
                    f"\r🔄 Geprüfte Adressen: {checked:,} | Rate: {rate:.2f} Adressen/s | Gefunden: {found}"
                )
                sys.stdout.flush()

# ---- Favicon
@app.route('/favicon.ico')
def favicon():
    # icon.png liegt in /static
    return send_from_directory(
        app.static_folder,
        'icon.png',
        mimetype='image/png'
    )

# ---- Web-UI
_last_persisted_checked = 0  # Session-Helfer, um in stats nur Deltas zu addieren

@app.route("/")
def show_status():
    global _last_persisted_checked

    # Refresh-Intervall (Sekunden) aus URL (default 10)
    try:
        refresh = int(request.args.get("refresh", "10"))
    except ValueError:
        refresh = 10
    if refresh not in (5, 10, 30, 60):
        refresh = 10

    # --- DB kumuliert bei jedem Refresh erhöhen ---
    # Stunden-Zuwachs aus refresh; Adress-Zuwachs aus Session-Delta
    delta_checked = max(0, status["checked"] - _last_persisted_checked)
    db_update_stats(hours_inc=refresh / 3600.0, checked_inc=delta_checked)
    _last_persisted_checked = status["checked"]

    # Gesamtwerte laden (für Anzeige)
    total_hours, total_checked = db_get_stats()

    laufzeit_session = format_duration(time.time() - status["start_time"])
    finds = db_get_recent_finds(limit=100)

    # Schlichte Formatierung
    # Hinweis: wir verwenden bewusst kein großes Framework; CSS ist inline für Einfachheit
    return f"""
    <html>
    <head>
        <meta http-equiv="refresh" content="{refresh}">
        <title>BTC Checker · v{__version__}</title>
        <link rel="icon" type="image/png" href="/favicon.ico" />
        <style>
            :root {{
                --bg: #f6f7fb;
                --fg: #16181d;
                --muted: #677084;
                --card: #ffffff;
                --accent: #0d6efd;
                --ok: #2fa24a;
                --shadow: 0 8px 24px rgba(0,0,0,0.08);
                --radius: 14px;
            }}
            * {{ box-sizing: border-box; }}
            body {{
                margin: 0; padding: 24px;
                font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial;
                background: var(--bg); color: var(--fg);
            }}
            .container {{ max-width: 980px; margin: 0 auto; }}
            header {{ display:flex; align-items:center; gap:12px; margin-bottom: 16px; }}
            header img {{ width:28px; height:28px; }}
            h1 {{ font-size: 20px; margin: 0; }}
            .row {{ display:grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
            .card {{
                background: var(--card); border-radius: var(--radius); box-shadow: var(--shadow);
                padding: 16px;
            }}
            .kpi {{ display:flex; justify-content: space-between; align-items:end; }}
            .kpi h2 {{ margin:0; font-size: 14px; color: var(--muted); }}
            .kpi .v {{ font-size: 22px; font-weight: 700; }}
            .sub {{ color: var(--muted); font-size: 12px; margin-top: 6px; }}
            .table {{ width:100%; border-collapse: collapse; }}
            .table th, .table td {{ text-align:left; padding: 8px 6px; border-bottom: 1px solid #eef0f4; font-size: 13px; }}
            .table th {{ color: var(--muted); font-weight: 600; }}
            footer {{ margin-top: 18px; color: var(--muted); font-size: 12px; display:flex; justify-content: space-between; }}
            .controls {{ display:flex; gap:8px; align-items:center; }}
            select {{ padding:6px 8px; border-radius: 8px; border:1px solid #d7dbe4; background:#fff; }}
            .ok {{ color: var(--ok); font-weight: 700; }}
        </style>
        <script>
        // Dropdown steuert den Refresh via URL-Param
        function setRefresh(sel) {{
            const v = sel.value;
            const url = new URL(window.location.href);
            url.searchParams.set("refresh", v);
            window.location.href = url.toString();
        }}
        </script>
    </head>
    <body>
    <div class="container">
        <header>
            <img src="/favicon.ico" alt="icon" />
            <h1>BTC Checker</h1>
            <div style="flex:1"></div>
            <div class="controls">
                <span class="sub">Refresh:</span>
                <select onchange="setRefresh(this)">
                    <option value="5"  {"selected" if refresh==5 else ""}>5s</option>
                    <option value="10" {"selected" if refresh==10 else ""}>10s</option>
                    <option value="30" {"selected" if refresh==30 else ""}>30s</option>
                    <option value="60" {"selected" if refresh==60 else ""}>60s</option>
                </select>
            </div>
        </header>

        <div class="row">
            <div class="card">
                <div class="kpi"><h2>⏱️ Laufzeit (Session)</h2><div class="v">{laufzeit_session}</div></div>
                <div class="sub">Seit App-Start</div>
                <div class="kpi" style="margin-top:12px;"><h2>🔄 Geprüfte Adressen (Session)</h2><div class="v">{status['checked']:,}</div></div>
                <div class="sub">Aktuelle Session</div>
            </div>

            <div class="card">
                <div class="kpi"><h2>📆 Gesamt-Laufzeit</h2><div class="v">{total_hours:.1f} h</div></div>
                <div class="sub">Kumuliert (aus DB)</div>
                <div class="kpi" style="margin-top:12px;"><h2>📊 Gesamt geprüfte Adressen</h2><div class="v">{total_checked:,}</div></div>
                <div class="sub">Kumuliert (aus DB)</div>
            </div>
        </div>

        <div class="card" style="margin-top:16px;">
            <h2 style="margin:0 0 8px 0; font-size:16px;">🎯 Gefundene Wallets (letzte 100)</h2>
            <table class="table">
                <thead>
                    <tr>
                        <th>Zeit</th><th>Typ</th><th>Adresse</th><th>Guthaben (BTC)</th><th>Seed</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(f"<tr><td>{ts}</td><td>{typ}</td><td>{addr}</td><td>{bal:.8f}</td><td>{seed}</td></tr>" for ts,typ,addr,bal,seed in finds)}
                </tbody>
            </table>
            <div class="sub">Zeigt max. 100 Einträge (neueste zuerst).</div>
        </div>

        <footer>
            <div>© BTC Checker</div>
            <div>v{__version__}</div>
        </footer>
    </div>
    </body>
    </html>
    """

# ---- Start
if __name__ == "__main__":
    threading.Thread(target=suchroutine, daemon=True).start()
    app.run(host="0.0.0.0", port=5001)
