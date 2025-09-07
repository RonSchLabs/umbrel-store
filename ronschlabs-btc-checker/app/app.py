import os, sys, time, hashlib, hmac, ecdsa, base58, requests, threading
from datetime import datetime
from mnemonic import Mnemonic
from bech32 import bech32_encode, convertbits
from flask import Flask, send_from_directory

__version__ = "1.1"
print(f"[INFO] BTC Checker Version: {__version__}")

# Flask App starten
app = Flask(__name__)
status = {
    "checked": 0,
    "rate": 0.0,
    "found": 0,
    "start_time": time.time()
}

ADRESSES_PER_SEED = 10

# Speicherpfad dynamisch festlegen (lokal oder Umbrel)
if os.getenv("BTC_MODE") == "umbrel" or os.path.exists("/data"):
    SAVE_PATH = "/data/gefunden.txt"
else:
    SAVE_PATH = "gefunden.txt"

print(f"[INFO] Treffer werden gespeichert in: {SAVE_PATH}")

# Hashfunktionen
def sha256(x): return hashlib.sha256(x).digest()
def ripemd160(x): h = hashlib.new("ripemd160"); h.update(x); return h.digest()

# Adresse generieren
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

# Guthaben prüfen
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

# Treffer speichern
def save(addr, typ, bal, seed_words):
    os.makedirs(os.path.dirname(SAVE_PATH), exist_ok=True)
    with open(SAVE_PATH, "a", encoding="utf-8") as f:
        f.write(f"🎯 {typ} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Adresse: {addr}\nGuthaben: {bal:.8f} BTC\nSeed: {seed_words}\n")
        f.write("=" * 60 + "\n")

# Laufzeit schön formatieren
def format_duration(seconds):
    minutes, _ = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    months, days = divmod(days, 30)
    years, months = divmod(months, 12)

    parts = []
    if years: parts.append(f"{years} Jahr{'e' if years != 1 else ''}")
    if months: parts.append(f"{months} Monat{'e' if months != 1 else ''}")
    if days: parts.append(f"{days} Tag{'e' if days != 1 else ''}")
    if hours: parts.append(f"{hours} Stunde{'n' if hours != 1 else ''}")
    if minutes: parts.append(f"{minutes} Minute{'n' if minutes != 1 else ''}")

    return ", ".join(parts) if parts else "weniger als 1 Minute"

# Suche starten
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

                sys.stdout.write(
                    f"\r🔄 Geprüfte Adressen: {checked:,} | Rate: {rate:.2f} Adressen/s | Gefunden: {found}"
                )
                sys.stdout.flush()

# Favicon bereitstellen
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(
        app.static_folder,
        'icon.jpg',
        mimetype='image/jpeg'
    )

# Web-UI
@app.route("/")
def show_status():
    laufzeit = format_duration(time.time() - status["start_time"])
    return f"""
    <html>
    <head>
        <meta http-equiv="refresh" content="10">
        <title>BTC Checker Status</title>
        <link rel="icon" type="image/jpeg" href="/favicon.ico" />
        <style>
            body {{
                font-family: sans-serif;
                padding: 2em;
                background-color: #f8f8f8;
            }}
            .box {{
                background: white;
                border-radius: 10px;
                padding: 2em;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                max-width: 400px;
                margin: auto;
            }}
            h2 {{ color: #333; }}
        </style>
    </head>
    <body>
        <div class="box">
            <h2>🔍 Live Status</h2>
            <p>⏱️ Laufzeit: {laufzeit}</p>
            <p>🔄 Geprüfte Adressen: {status['checked']:,}</p>
            <p>🚀 Rate: {status['rate']:.2f} Adressen/s</p>
            <p>🎯 Gefundene Wallets: {status['found']}</p>
            <small>(Aktualisierung alle 10 Sekunden)</small>
        </div>
    </body>
    </html>
    """

# Start
if __name__ == "__main__":
    threading.Thread(target=suchroutine, daemon=True).start()
    app.run(host="0.0.0.0", port=5001)

