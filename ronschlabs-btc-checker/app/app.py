# -*- coding: utf-8 -*-
"""
BTC Checker – v3.2 (Cycle-Reset + 12M-Historie)
- UI v4.1 Dark + DE-Zeit (Style unverändert)
- Live-UI (ohne Page-Reload) für KPIs, Funde & Prüfprotokoll
- Prüfprotokoll inkl. Typ & Guthaben
- Blockstream Enterprise API mit OAuth2 (Client-Credentials)
- Adaptive Drossel nach Monatsbudget (Minute/Std/Tag konservativ abgerundet)
- Token-Bucket (Catch-up): ungenutzte Minuten-Budgets werden nachgeholt (Burst begrenzt)
- Quota als volle Zeile + Backlog-Anzeige
- Pause-Button (Toggle) in der Status-Karte
- IO/NIO-Split bei "Geprüfte Adressen (Session)"
- Abrechnungsfenster per Anchor-Day (Default 13 → 13. bis 12.), auto berechnet
- **NEU**: Harte Resets beim Cycle-Wechsel (inkl. Token-Bucket leeren)
- **NEU**: Quota-Historie (letzte 12 Zyklen) in SQLite + UI-Tabelle
"""

import os
import math
import time
import json
import hmac
import ecdsa
import base58
import sqlite3
import hashlib
import threading
import requests
from datetime import datetime, timedelta
from typing import Optional, Tuple, List, Dict, Any
from mnemonic import Mnemonic
from bech32 import bech32_encode, convertbits
from flask import Flask, send_from_directory, request, jsonify

# ---- .env automatisch laden ----
try:
  from dotenv import load_dotenv
  load_dotenv()  # .env im Arbeitsverzeichnis
  load_dotenv("/data/.env")  # Fallback: Umbrel-Persistenz
except Exception:
    pass

# ------------------------------ Zeitzone --------------------------------------
try:
    from zoneinfo import ZoneInfo
    TZ = ZoneInfo("Europe/Berlin")
except Exception:
    TZ = None  # Fallback unten in now_de_str()

# ----------------------------- Konfiguration ----------------------------------
__version__ = "3.2"

# --- UI / Scan ---
ADDRESSES_PER_SEED = 10
FIND_LIMIT = 100
PERSIST_INTERVAL_SEC = 5

# Prüfprotokoll: wie viele Einträge halten (ältere sofort löschen)
CHECK_KEEP_DEFAULT = 50
CHECK_KEEP_MIN = 10
CHECK_KEEP_MAX = 500
_check_keep = CHECK_KEEP_DEFAULT  # via UI setzbar

# API Service
API_SERVICE_NAME = "blockstream-enterprise"
ENTERPRISE_API_BASE = "https://enterprise.blockstream.info/api"

# OAuth2
OAUTH_TOKEN_URL = "https://login.blockstream.com/realms/blockstream-public/protocol/openid-connect/token"
BS_CLIENT_ID = os.getenv("BS_CLIENT_ID", "").strip()
BS_CLIENT_SECRET = os.getenv("BS_CLIENT_SECRET", "").strip()

# Quota / Cycle
DEFAULT_MONTH_CAP = 490_000  # per UI anpassbar
CYCLE_ANCHOR_DAY = int(os.getenv("BS_CYCLE_ANCHOR_DAY", "13"))  # 1..28 sinnvoll; Default 13

# Pfade (Umbrel nutzt /data)
IS_UMBREL = (os.getenv("BTC_MODE") == "umbrel") or os.path.exists("/data")
DB_PATH = "/data/btc_checker.db" if IS_UMBREL else "btc_checker.db"

# Flask
app = Flask(__name__, static_folder="static")

# ------------------------------- Laufzeit-Status ------------------------------
status = {
    "checked": 0,           # Geprüfte Adressen in dieser Session (gesamt)
    "io": 0,                # HTTP 200
    "nio": 0,               # != 200 / Fehler
    "rate": 0.0,            # Adressen/s (Session)
    "found": 0,             # Gefundene Wallets (Session)
    "start_time": time.time(),
    "paused": False         # Pause-Toggle
}

# Persistenz-Helfer für Delta-Flush
_persist_lock = threading.Lock()
_persist_last_checked = 0
_persist_last_ts = time.time()

# ------------------------------ Zeit/Format-Helfer ----------------------------
def now_de_str() -> str:
    """Aktuelle Zeit in Europa/Berlin als 'DD.MM.YYYY HH:MM:SS' (mit Fallback)."""
    try:
        if TZ is not None:
            return datetime.now(TZ).strftime("%d.%m.%Y %H:%M:%S")
    except Exception:
        pass
    return datetime.now().strftime("%d.%m.%Y %H:%M:%S")

def now_tz() -> datetime:
    try:
        if TZ is not None:
            return datetime.now(TZ)
    except Exception:
        pass
    return datetime.now()

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

# ------------------------------ Cycle/Quota-Helfer ----------------------------
def compute_cycle_window(anchor_day: int, ref: Optional[datetime] = None) -> Tuple[datetime, datetime]:
    """
    Bestimmt das aktuelle Abrechnungsfenster [start, end) basierend auf anchor_day.
    Beispiel anchor_day=13 → Fenster 13. (inkl) bis 13. des Folgemonats (exkl).
    Wir zeigen es in der UI als 13..12.
    """
    ref = ref or now_tz()
    month_start = ref.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    try:
        start_this = month_start.replace(day=anchor_day)
    except ValueError:
        # Clamp auf letzten Tag des Monats
        next_month = (month_start.replace(day=28) + timedelta(days=4)).replace(day=1)
        last_day = (next_month - timedelta(days=1)).day
        start_this = month_start.replace(day=min(anchor_day, last_day))

    if ref >= start_this:
        start = start_this
    else:
        prev_month = (month_start - timedelta(days=1)).replace(day=1)
        try:
            start = prev_month.replace(day=anchor_day)
        except ValueError:
            next_of_prev = (prev_month.replace(day=28) + timedelta(days=4)).replace(day=1)
            last_day = (next_of_prev - timedelta(days=1)).day
            start = prev_month.replace(day=min(anchor_day, last_day))

    # +1 Monat robust
    def add_one_month(dt: datetime) -> datetime:
        y, m = dt.year, dt.month
        if m == 12:
            y, m = y + 1, 1
        else:
            m += 1
        for d in (dt.day, 28, 27, 26):
            try:
                return dt.replace(year=y, month=m, day=d)
            except ValueError:
                continue
        return dt.replace(year=y, month=m, day=1)

    end = add_one_month(start)
    return start, end

def midnight_next(dt: datetime) -> datetime:
    return (dt + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)

def next_hour(dt: datetime) -> datetime:
    return (dt + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)

def next_minute(dt: datetime) -> datetime:
    return (dt + timedelta(minutes=1)).replace(second=0, microsecond=0)

# --------------------------------- SQLite -------------------------------------
def db_connect():
    # isolation_level=None -> autocommit
    return sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)

def db_kv_get(cur, key: str, default=None):
    cur.execute("SELECT val FROM config WHERE key = ?", (key,))
    row = cur.fetchone()
    if row is None:
        return default
    try:
        return json.loads(row[0])
    except Exception:
        return row[0]

def db_kv_set(cur, key: str, val):
    cur.execute("INSERT OR REPLACE INTO config (key, val) VALUES (?, ?)", (key, json.dumps(val)))

def _ensure_checks_columns(cur):
    cur.execute("PRAGMA table_info(checks)")
    cols = {row[1] for row in cur.fetchall()}
    if "typ" not in cols:
        cur.execute("ALTER TABLE checks ADD COLUMN typ TEXT DEFAULT '—'")
    if "balance" not in cols:
        cur.execute("ALTER TABLE checks ADD COLUMN balance REAL DEFAULT 0.0")

def _ensure_quota_history_columns(cur):
    cur.execute("PRAGMA table_info(quota_usage_history)")
    cols = {row[1] for row in cur.fetchall()}
    if "month_cap" not in cols:
        try:
            cur.execute("ALTER TABLE quota_usage_history ADD COLUMN month_cap INTEGER NOT NULL DEFAULT 0")
        except sqlite3.OperationalError:
            pass  # falls busy/gleichzeitig – nächster Start fix es

def db_init():
    con = db_connect()
    cur = con.cursor()

    # Basis-Tabellen
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            addr TEXT NOT NULL,
            service TEXT NOT NULL,
            ok INTEGER NOT NULL,
            http_status INTEGER,
            duration_ms INTEGER NOT NULL,
            typ TEXT DEFAULT '—',
            balance REAL DEFAULT 0.0
        )
    """)
    _ensure_checks_columns(cur)

    # config Key/Value
    cur.execute("""
        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            val TEXT NOT NULL
        )
    """)

    # Quota-Historie (letzte 12 Zyklen)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS quota_usage_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            period_start TEXT NOT NULL,
            period_end TEXT NOT NULL,
            used_requests INTEGER NOT NULL,
            month_cap INTEGER NOT NULL DEFAULT 0
        )
    """)
    _ensure_quota_history_columns(cur)

    # Singleton stats
    cur.execute("INSERT OR IGNORE INTO stats (id, total_hours, total_checked) VALUES (1, 0.0, 0)")

    # Quota-Defaults
    if db_kv_get(cur, "month_cap") is None:
        db_kv_set(cur, "month_cap", DEFAULT_MONTH_CAP)
    if db_kv_get(cur, "anchor_day") is None:
        db_kv_set(cur, "anchor_day", CYCLE_ANCHOR_DAY)

    if db_kv_get(cur, "cycle_start") is None or db_kv_get(cur, "cycle_end") is None:
        anchor = int(db_kv_get(cur, "anchor_day", CYCLE_ANCHOR_DAY))
        start, end = compute_cycle_window(anchor)
        db_kv_set(cur, "cycle_start", start.isoformat())
        db_kv_set(cur, "cycle_end", end.isoformat())

    # Laufende Zähler + Token-Bucket Defaults
    for key, default in [
        ("used_cycle", 0),
        ("used_day", 0),
        ("used_hour", 0),
        ("used_minute", 0),
        ("minute_epoch", None),
        ("hour_epoch", None),
        ("day_epoch", None),
        ("last_quota_sync", None),
        # --- Token-Bucket ---
        ("tokens", 0),
        ("last_refill", None),   # ISO der letzten vollen Minute
        ("burst_factor", 2.0),   # max 2x Minutenbudget als Puffer
    ]:
        if db_kv_get(cur, key) is None:
            db_kv_set(cur, key, default)

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

def db_insert_check(ts: str, addr: str, typ: str, service: str, ok: int,
                    http_status: int | None, duration_ms: int, balance: float):
    con = db_connect()
    cur = con.cursor()
    try:
        cur.execute("""
            INSERT INTO checks (ts, addr, typ, service, ok, http_status, duration_ms, balance)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (ts, addr, typ, service, int(ok), http_status, int(duration_ms), float(balance)))
    except sqlite3.OperationalError as e:
        if "no such column" in str(e).lower():
            _ensure_checks_columns(cur)
            cur.execute("""
                INSERT INTO checks (ts, addr, typ, service, ok, http_status, duration_ms, balance)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts, addr, typ, service, int(ok), http_status, int(duration_ms), float(balance)))
        else:
            raise
    finally:
        con.close()

def db_get_recent_checks(limit: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute("""
        SELECT ts, addr, typ, service, ok, http_status, duration_ms, balance
          FROM checks
         ORDER BY id DESC
         LIMIT ?
    """, (int(limit),))
    rows = cur.fetchall()
    con.close()
    return rows

def db_prune_checks(keep: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute("""
        DELETE FROM checks
         WHERE id NOT IN (SELECT id FROM checks ORDER BY id DESC LIMIT ?)
    """, (int(keep),))
    con.close()

def db_record_quota_history(period_start_iso: str, period_end_iso: str, used: int, cap: int):
    con = db_connect()
    cur = con.cursor()
    cur.execute("""
        INSERT INTO quota_usage_history (period_start, period_end, used_requests, month_cap)
        VALUES (?, ?, ?, ?)
    """, (period_start_iso, period_end_iso, int(used), int(cap)))
    cur.execute("""
        DELETE FROM quota_usage_history
         WHERE id NOT IN (SELECT id FROM quota_usage_history ORDER BY id DESC LIMIT 12)
    """)
    con.close()

def db_get_quota_history(limit: int = 12) -> List[tuple]:
    con = db_connect()
    cur = con.cursor()
    cur.execute("""
        SELECT period_start, period_end, used_requests, month_cap
          FROM quota_usage_history
         ORDER BY id DESC
         LIMIT ?
    """, (int(limit),))
    rows = cur.fetchall()
    con.close()
    return rows

# ------------------------------ OAuth2 Client ---------------------------------
class OAuthClient:
    def __init__(self, token_url: str, client_id: str, client_secret: str):
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self._access_token = None
        self._expires_at = 0.0

    def _needs_refresh(self) -> bool:
        return (self._access_token is None) or (time.time() > self._expires_at - 120)

    def _fetch_token(self):
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
            "scope": "openid"
        }
        r = requests.post(self.token_url, data=data, headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=15)
        r.raise_for_status()
        j = r.json()
        self._access_token = j.get("access_token")
        expires_in = int(j.get("expires_in", 3600))
        self._expires_at = time.time() + expires_in

    def get_token(self) -> str:
        if self._needs_refresh():
            self._fetch_token()
        return self._access_token or ""

# --------------------------- Explorer Enterprise API --------------------------
class ExplorerApi:
    def __init__(self, base_url: str, oauth: OAuthClient):
        self.base_url = base_url.rstrip("/")
        self.oauth = oauth
        self.session = requests.Session()

    def _auth_headers(self) -> dict:
        token = self.oauth.get_token()
        return {"Authorization": f"Bearer {token}"}

    def get_address_info(self, addr: str) -> dict:
        url = f"{self.base_url}/address/{addr}"
        r = self.session.get(url, headers=self._auth_headers(), timeout=15)
        return {"status": r.status_code, "json": (r.json() if r.status_code == 200 else None)}

# ------------------------------- Quota Manager --------------------------------
class QuotaManager:
    """
    Lokale Request-Zähler (Minute/Std/Tag/Cycle) + Budgets,
    plus Token-Bucket (Catch-up) mit Burst-Begrenzung.
    Handhabt **harten Reset** beim Abrechnungswechsel.
    """
    def __init__(self):
        self._lock = threading.Lock()

    def _load(self):
      con = db_connect()
      cur = con.cursor()
      month_cap = int(db_kv_get(cur, "month_cap", DEFAULT_MONTH_CAP))
      anchor_day = int(db_kv_get(cur, "anchor_day", CYCLE_ANCHOR_DAY))
      cycle_start_iso = db_kv_get(cur, "cycle_start")
      cycle_end_iso = db_kv_get(cur, "cycle_end")
      used_cycle = int(db_kv_get(cur, "used_cycle", 0))
      used_day = int(db_kv_get(cur, "used_day", 0))
      used_hour = int(db_kv_get(cur, "used_hour", 0))
      used_minute = int(db_kv_get(cur, "used_minute", 0))
      minute_epoch_iso = db_kv_get(cur, "minute_epoch", None)
      hour_epoch_iso = db_kv_get(cur, "hour_epoch", None)
      day_epoch_iso = db_kv_get(cur, "day_epoch", None)

      # Token-Bucket
      tokens = int(db_kv_get(cur, "tokens", 0))
      last_refill_iso = db_kv_get(cur, "last_refill", None)
      burst_factor = float(db_kv_get(cur, "burst_factor", 2.0))
      con.close()

      def to_dt(x):
        if not x:
          return None
        if isinstance(x, datetime):
          return x
        try:
          return datetime.fromisoformat(x)
        except Exception:
          return None

      cycle_start = to_dt(cycle_start_iso)
      cycle_end = to_dt(cycle_end_iso)
      now = now_tz()

      # Falls Fenster ungültig/abgelaufen: archivieren + hart resetten
      if (cycle_start is None) or (cycle_end is None) or not (cycle_start <= now < cycle_end):
        if cycle_start is not None and cycle_end is not None:
          try:
            db_record_quota_history(cycle_start.isoformat(), cycle_end.isoformat(), used_cycle, month_cap)
          except Exception:
            pass

        # Reset aller Zähler & Token
        used_cycle = used_day = used_hour = used_minute = 0
        tokens = 0
        now_minute = now.replace(second=0, microsecond=0)
        m_epoch = now_minute
        h_epoch = now.replace(minute=0, second=0, microsecond=0)
        d_epoch = now.replace(hour=0, minute=0, second=0, microsecond=0)
        last_refill = now_minute

        # Neues Fenster setzen
        start, end = compute_cycle_window(anchor_day, now)
        cycle_start, cycle_end = start, end

        # Persistieren
        con = db_connect()
        cur = con.cursor()
        db_kv_set(cur, "cycle_start", cycle_start.isoformat())
        db_kv_set(cur, "cycle_end", cycle_end.isoformat())
        db_kv_set(cur, "used_cycle", used_cycle)
        db_kv_set(cur, "used_day", used_day)
        db_kv_set(cur, "used_hour", used_hour)
        db_kv_set(cur, "used_minute", used_minute)
        db_kv_set(cur, "tokens", tokens)
        db_kv_set(cur, "minute_epoch", m_epoch.isoformat())
        db_kv_set(cur, "hour_epoch", h_epoch.isoformat())
        db_kv_set(cur, "day_epoch", d_epoch.isoformat())
        db_kv_set(cur, "last_refill", last_refill.isoformat())
        con.close()
      else:
        # Normallauf: vorhandene Epochen/last_refill einlesen und parsen
        m_epoch = to_dt(minute_epoch_iso)
        h_epoch = to_dt(hour_epoch_iso)
        d_epoch = to_dt(day_epoch_iso)
        last_refill = to_dt(last_refill_iso) or now.replace(second=0, microsecond=0)

      # --- Epochen prüfen/resets (innerhalb laufender Periode) ---
      now_minute = now.replace(second=0, microsecond=0)
      if (m_epoch is None) or (now >= m_epoch + timedelta(minutes=1)):
        used_minute = 0
        m_epoch = now_minute

      now_hour = now.replace(minute=0, second=0, microsecond=0)
      if (h_epoch is None) or (now >= h_epoch + timedelta(hours=1)):
        used_hour = 0
        h_epoch = now_hour

      today_0 = now.replace(hour=0, minute=0, second=0, microsecond=0)
      if (d_epoch is None) or (d_epoch < today_0):
        used_day = 0
        d_epoch = today_0

      return {
        "month_cap": month_cap,
        "cycle_start": cycle_start,
        "cycle_end": cycle_end,
        "used_cycle": used_cycle,
        "used_day": used_day,
        "used_hour": used_hour,
        "used_minute": used_minute,
        "minute_epoch": m_epoch,
        "hour_epoch": h_epoch,
        "day_epoch": d_epoch,
        "tokens": tokens,
        "last_refill": last_refill,
        "burst_factor": burst_factor
      }

    def _save(self, state):
        con = db_connect()
        cur = con.cursor()
        db_kv_set(cur, "month_cap", int(state["month_cap"]))
        db_kv_set(cur, "cycle_start", state["cycle_start"].isoformat())
        db_kv_set(cur, "cycle_end", state["cycle_end"].isoformat())
        db_kv_set(cur, "used_cycle", int(state["used_cycle"]))
        db_kv_set(cur, "used_day", int(state["used_day"]))
        db_kv_set(cur, "used_hour", int(state["used_hour"]))
        db_kv_set(cur, "used_minute", int(state["used_minute"]))
        db_kv_set(cur, "minute_epoch", state["minute_epoch"].isoformat())
        db_kv_set(cur, "hour_epoch", state["hour_epoch"].isoformat())
        db_kv_set(cur, "day_epoch", state["day_epoch"].isoformat())
        # Token-Bucket
        db_kv_set(cur, "tokens", int(state["tokens"]))
        db_kv_set(cur, "last_refill", state["last_refill"].isoformat())
        db_kv_set(cur, "burst_factor", float(state["burst_factor"]))
        con.close()

    def quotas(self):
        """Budgets + empfohlene Rate und Token-Backlog berechnen (mit Refill)."""
        with self._lock:
            st = self._load()
            now = now_tz()

            # Restzeiten
            rem_cycle_sec = max(1, int((st["cycle_end"] - now).total_seconds()))
            rem_cycle_min = max(1, rem_cycle_sec // 60)
            rem_cycle_hour = max(1, rem_cycle_sec // 3600)
            rem_days = max(1, math.ceil((st["cycle_end"] - now).total_seconds() / 86400))

            # Restrequests im Fenster
            remaining = max(0, int(st["month_cap"]) - int(st["used_cycle"]))

            # Konservative Basisbudgets
            day_cap = remaining // rem_days
            hour_cap = remaining // rem_cycle_hour
            minute_cap = remaining // rem_cycle_min

            # Verbrauch in der aktuellen Periode
            minute_left = max(0, minute_cap - int(st["used_minute"]))
            hour_left   = max(0, hour_cap - int(st["used_hour"]))
            day_left    = max(0, day_cap - int(st["used_day"]))
            cycle_left  = remaining

            # ---------- Token-Bucket Refill ----------
            last_refill = st["last_refill"]
            elapsed_min = max(0, int((now.replace(second=0, microsecond=0) - last_refill).total_seconds() // 60))
            tokens = int(st["tokens"])
            burst_factor = float(st["burst_factor"])
            max_tokens = int(burst_factor * minute_cap) if minute_cap > 0 else 0

            if elapsed_min > 0 and minute_cap > 0:
                tokens = min(max_tokens, tokens + minute_cap * elapsed_min)
                last_refill = now.replace(second=0, microsecond=0)

            # Gleichverteilung über verbleibende Minuten (informativ)
            eq_per_min = remaining // rem_cycle_min

            # Catch-up ohne harten Minuten-Guard
            suggested_per_minute = min(
              max(0, tokens),
              max(0, hour_left),
              max(0, day_left)
            )

            # Zustand speichern
            st["tokens"] = tokens
            st["last_refill"] = last_refill
            self._save(st)

            return {
                "month_cap": int(st["month_cap"]),
                "cycle_start": st["cycle_start"],
                "cycle_end": st["cycle_end"],
                "used": {
                    "minute": int(st["used_minute"]),
                    "hour": int(st["used_hour"]),
                    "day": int(st["used_day"]),
                    "cycle": int(st["used_cycle"]),
                },
                "remaining": {
                    "minute": int(minute_left),
                    "hour": int(hour_left),
                    "day": int(day_left),
                    "cycle": int(cycle_left),
                },
                "budgets": {
                    "per_minute": int(minute_cap),
                    "per_hour": int(hour_cap),
                    "per_day": int(day_cap),
                },
                "suggested_per_minute": int(suggested_per_minute),
                "backlog_tokens": int(tokens),
                "max_tokens": int(max_tokens),
                "burst_factor": float(burst_factor),
                "eq_per_min": int(eq_per_min)
            }

    def wait_if_needed_before_request(self):
        """
        Wartet, bis Tokens verfügbar sind und Std/Tag-Guards eingehalten werden.
        Verteilt Requests grob gleichmäßig gemäß suggested_per_minute.
        """
        while True:
            q = self.quotas()
            now = now_tz()

            if status.get("paused"):
                time.sleep(0.2)
                continue

            # Harte Guards
            if q["remaining"]["hour"] <= 0:
                nh = next_hour(now)
                time.sleep(max(0.1, (nh - now).total_seconds()))
                continue
            if q["remaining"]["day"] <= 0:
                nd = midnight_next(now)
                time.sleep(max(0.5, (nd - now).total_seconds()))
                continue

            spm = int(q["suggested_per_minute"])
            tokens = int(q["backlog_tokens"])

            if tokens <= 0 or spm <= 0:
                nm = next_minute(now)
                time.sleep(max(0.05, (nm - now).total_seconds()))
                continue

            interval = 60.0 / max(1, spm)
            time.sleep(max(0.05, interval))
            break

    def note_request(self, ok: bool):
        """Nach JEDEM Request aufrufen (IO/NIO egal → zählt Verbrauch und Tokens)."""
        with self._lock:
            st = self._load()
            st["used_cycle"] += 1
            st["used_day"] += 1
            st["used_hour"] += 1
            st["used_minute"] += 1
            # 1 Token verbrauchen (nicht negativ)
            st["tokens"] = max(0, int(st.get("tokens", 0)) - 1)
            self._save(st)

quota_mgr = QuotaManager()

# ------------------------------ Krypto-Utils ---------------------------------
def sha256(x: bytes) -> bytes:
    return hashlib.sha256(x).digest()

def ripemd160(x: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(x)
    return h.digest()

def pubkey_to_p2sh(pub: bytes) -> str:
    h160 = ripemd160(sha256(pub))
    redeem = b"\x00\x14" + h160
    hashed = ripemd160(sha256(redeem))
    payload = b"\x05" + hashed
    checksum = sha256(sha256(payload))[:4]
    return base58.b58encode(payload + checksum).decode()

def pubkey_to_segwit(pub: bytes) -> str:
    h160 = ripemd160(sha256(pub))
    five = convertbits(h160, 8, 5)
    return bech32_encode("bc", [0] + five)

def derive_privkey(seed: bytes) -> bytes:
    return hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()[:32]

# ------------------------------ HTTP-Check Wrapper ----------------------------
_oauth = OAuthClient(OAUTH_TOKEN_URL, BS_CLIENT_ID, BS_CLIENT_SECRET) if (BS_CLIENT_ID and BS_CLIENT_SECRET) else None
_api = ExplorerApi(ENTERPRISE_API_BASE, _oauth) if _oauth else None

def check_balance(addr: str, typ: str):
    """
    Fragt Guthaben ab, protokolliert in 'checks' (auch bei Fehlern).
    Rückgabe: (balance_btc, http_status or None)
    """
    started = time.perf_counter()
    ok = 0
    http_status = None
    balance = 0.0

    try:
        if _api is None:
            # Fallback (sollte nicht auftreten, wenn ENV korrekt)
            url = f"{ENTERPRISE_API_BASE}/address/{addr}"
            r = requests.get(url, timeout=15)
            http_status = r.status_code
            j = r.json() if r.status_code == 200 else None
        else:
            quota_mgr.wait_if_needed_before_request()
            resp = _api.get_address_info(addr)
            http_status = resp["status"]
            j = resp["json"]

        if http_status == 200 and j:
            funded = j.get("chain_stats", {}).get("funded_txo_sum", 0)
            spent  = j.get("chain_stats", {}).get("spent_txo_sum", 0)
            balance = (funded - spent) / 1e8
            ok = 1
        else:
            balance = 0.0
    except Exception:
        balance = 0.0
        http_status = None
    finally:
        duration_ms = int((time.perf_counter() - started) * 1000)
        quota_mgr.note_request(ok=True)
        db_insert_check(
            ts=now_de_str(),
            addr=addr,
            typ=typ,
            service=API_SERVICE_NAME,
            ok=ok,
            http_status=http_status,
            duration_ms=duration_ms,
            balance=balance,
        )
        db_prune_checks(_check_keep)
        if http_status == 429:
            time.sleep(1.5)
        elif http_status == 401:
            status["paused"] = True
            time.sleep(2.0)
        elif http_status is None or (isinstance(http_status, int) and http_status >= 500):
            time.sleep(0.5)
    return balance, (http_status if isinstance(http_status, int) else -1)

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
    """Endlose Suche – adaptiv gedrosselt mit Token-Bucket, Pause-Toggle."""
    mnemo = Mnemonic("english")
    checked, found = 0, 0
    io_cnt, nio_cnt = 0, 0
    start = time.time()

    # Schutz: wenn ENV fehlt → pausieren
    if not BS_CLIENT_ID or not BS_CLIENT_SECRET:
        print("WARN: BS_CLIENT_ID/BS_CLIENT_SECRET fehlen → Scanner pausiert. .env setzen!")
        status["paused"] = True

    print("\n Starte endlose Suche (P2SH & SegWit) mit adaptiver Quota-Drossel (Token-Bucket)\n")
    while True:
        if status.get("paused"):
            time.sleep(0.2)
            continue

        mnemonic = mnemo.generate(strength=256)
        seed = mnemo.to_seed(mnemonic)
        priv = derive_privkey(seed)
        sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        pubkey = b"\x04" + vk.to_string()

        for _ in range(ADDRESSES_PER_SEED):
            for addr, typ in [(pubkey_to_p2sh(pubkey), "P2SH"),
                              (pubkey_to_segwit(pubkey), "SegWit")]:

                if status.get("paused"):
                    break

                bal, http_status = check_balance(addr, typ)

                checked += 1
                if http_status == 200:
                    io_cnt += 1
                else:
                    nio_cnt += 1

                if bal > 0:
                    found += 1
                    ts = now_de_str()
                    db_insert_find(ts, addr, typ, bal, mnemonic)

                status["checked"] = checked
                status["io"] = io_cnt
                status["nio"] = nio_cnt
                elapsed = max(1e-6, (time.time() - start))
                status["rate"] = checked / elapsed
                status["found"] = found

            if status.get("paused"):
                break

# --------------------------------- Web-API (JSON) -----------------------------
@app.route("/favicon.ico")
def favicon():
    return send_from_directory(app.static_folder, "favicon.ico", mimetype="image/vnd.microsoft.icon")

@app.route("/status.json")
def status_json():
    total_hours, total_checked = db_get_stats()
    return jsonify({
        "now": now_de_str(),
        "session": {
            "runtime_human": format_duration(int(time.time() - status["start_time"])),
            "checked": status["checked"],
            "io": status["io"],
            "nio": status["nio"],
            "rate": round(status["rate"], 2),
            "found": status["found"],
            "paused": bool(status.get("paused", False))
        },
        "total": {
            "hours": round(total_hours, 1),
            "hours_human": format_duration_hours(total_hours),
            "checked": int(total_checked)
        }
    })

@app.route("/recent_checks.json")
def recent_checks_json():
    try:
        limit = int(request.args.get("limit", str(_check_keep)))
    except ValueError:
        limit = _check_keep
    rows = db_get_recent_checks(limit)
    data = [{
        "ts": ts,
        "addr": addr,
        "typ": typ,
        "service": service,
        "ok": bool(ok),
        "http_status": http_status,
        "duration_ms": duration_ms,
        "balance": float(balance) if balance is not None else 0.0
    } for (ts, addr, typ, service, ok, http_status, duration_ms, balance) in rows]
    return jsonify(data)

@app.route("/recent_finds.json")
def recent_finds_json():
    rows = db_get_recent_finds(FIND_LIMIT)
    data = [{
        "ts": ts, "typ": typ, "addr": addr, "balance": float(balance), "seed": seed
    } for (ts, typ, addr, balance, seed) in rows]
    return jsonify(data)

@app.route("/quota.json")
def quota_json():
    q = quota_mgr.quotas()
    cycle_start = q["cycle_start"].strftime("%d.%m.%Y")
    cycle_end_excl = q["cycle_end"].strftime("%d.%m.%Y")
    end_inclusive = (q["cycle_end"] - timedelta(days=1)).strftime("%d.%m.%Y")
    return jsonify({
        "now": now_de_str(),
        "cycle": {
            "start": cycle_start,
            "end_exclusive": cycle_end_excl,
            "end_inclusive": end_inclusive
        },
        "month_cap": q["month_cap"],
        "used": q["used"],
        "remaining": q["remaining"],
        "budgets": q["budgets"],
        "suggested_per_minute": q["suggested_per_minute"],
        "backlog_tokens": q["backlog_tokens"],
        "max_tokens": q["max_tokens"]
    })

@app.route("/quota_history.json")
def quota_history_json():
    rows = db_get_quota_history(12)
    data = []
    for (ps, pe, used, cap) in rows:
        try:
            ps_dt = datetime.fromisoformat(ps)
            pe_dt = datetime.fromisoformat(pe) - timedelta(days=1)
            period = f"{ps_dt.strftime('%d.%m.%Y')} – {pe_dt.strftime('%d.%m.%Y')}"
        except Exception:
            period = f"{ps} – {pe}"
        data.append({"period": period, "used": int(used), "cap": int(cap)})
    return jsonify(data)

@app.route("/set_month_cap", methods=["POST"])
def set_month_cap():
    try:
        val = int(request.form.get("month_cap", DEFAULT_MONTH_CAP))
        if val < 1000:
            return jsonify({"ok": False, "error": "month_cap zu klein"}), 400
        con = db_connect()
        cur = con.cursor()
        db_kv_set(cur, "month_cap", val)
        con.close()
        return jsonify({"ok": True, "month_cap": val})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400

@app.route("/toggle_pause", methods=["POST"])
def toggle_pause():
    status["paused"] = not status.get("paused", False)
    return jsonify({"ok": True, "paused": status["paused"]})

# --------------------------------- Web-UI -------------------------------------
@app.route("/")
def show_status():
    total_hours, total_checked = db_get_stats()
    recent = db_get_recent_finds(FIND_LIMIT)
    q = quota_mgr.quotas()
    hist = db_get_quota_history(12)

    cycle_start = q["cycle_start"].strftime("%d.%m.%Y")
    cycle_end_incl = (q["cycle_end"] - timedelta(days=1)).strftime("%d.%m.%Y")
    suggested = q["suggested_per_minute"]

    # History-HTML
    if hist:
        hist_rows = "".join(
            f"<tr><td>{datetime.fromisoformat(ps).strftime('%d.%m.%Y')} – {(datetime.fromisoformat(pe)-timedelta(days=1)).strftime('%d.%m.%Y')}</td>"
            f"<td>{int(used)}</td><td>{int(cap)}</td></tr>"
            for (ps, pe, used, cap) in hist
        )
    else:
        hist_rows = "<tr><td colspan='3' class='muted small'>Noch keine Historie</td></tr>"

    return f"""<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8" />
  <link rel="icon" type="image/x-icon" href="/static/favicon.ico">
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>BTC Checker · v{__version__}</title>
  <style>
    :root {{
      --fg:#eaeaea; --bg:#0f1115; --muted:#9a9a9a; --card:#151822;
      --accent:#3aa675; --danger:#e25858; --ok:#3fbf7f;
      --border:#222632; --input:#131720;
      --checks-max-h: 12.4em;
    }}
    html, body {{
      margin:0; padding:0; background:var(--bg); color:var(--fg);
      font-family:system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,Arial,sans-serif;
    }}
    .wrap {{ max-width:1080px; margin:24px auto; padding:0 16px; }}
    h1 {{ font-size:20px; margin:0 0 12px 0; color:var(--fg); }}
    .muted {{ color:var(--muted); }}
    .grid {{ display:grid; grid-template-columns: repeat(auto-fit,minmax(240px,1fr)); gap:12px; }}
    .card {{ background:var(--card); border-radius:16px; padding:14px 16px; box-shadow:0 2px 10px rgba(0,0,0,.25); }}
    .kpi {{ font-size:28px; font-weight:700; margin-top:4px; }}
    .small {{ font-size:12px; }}
    .row {{ display:flex; align-items:center; gap:8px; flex-wrap:wrap; }}
    .tag {{ display:inline-block; padding:2px 8px; border-radius:999px; background:#1c2230; font-size:12px; }}
    a {{ color:var(--accent); text-decoration:none; }} a:hover {{ text-decoration:underline; }}
    input[type="number"]{{ background:var(--input); border:1px solid var(--border); color:var(--fg); border-radius:10px; padding:6px 8px; width:120px; }}
    button, .btn {{
      background:var(--input); border:1px solid var(--border); color:var(--fg); border-radius:10px; padding:6px 10px;
      cursor:pointer; text-decoration:none;
    }}
    button:hover, .btn:hover {{ filter:brightness(1.1); }}
    table {{ width:100%; border-collapse:collapse; }}
    th,td {{ border-bottom:1px solid var(--border); padding:8px 8px; text-align:left; font-size:13px; }}
    th {{ color:#c9d1d9; font-weight:600; background:transparent; position:sticky; top:0; z-index:1; }}
    .scrollbox {{ overflow-y:auto; border:1px solid var(--border); border-radius:12px; }}
    .scrollbox.six-rows {{ max-height: var(--checks-max-h); }}
    .ok {{ color:var(--ok); font-weight:600; }}
    .nio {{ color:var(--danger); font-weight:600; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size:12px; }}
    .footer {{ margin:18px 0 40px 0; color:var(--muted); font-size:12px; text-align:center; }}

    /* Volle Zeile für die Quota-Kachel */
    .quota-grid {{ display:grid; grid-template-columns: 1fr 1fr; gap:12px; }}
    .quota-left  {{ display:flex; flex-direction:column; gap:8px; }}
    .quota-right {{ display:flex; flex-direction:column; gap:8px; align-items:flex-start; }}
    @media (max-width: 820px) {{ .quota-grid {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="wrap">
  <h1>BTC Checker · v{__version__}</h1>

  <!-- 1. Reihe: 4 KPIs wie gehabt -->
  <div class="grid" style="margin-top:12px;">
    <div class="card">
      <div class="muted small">⏱️ Laufzeit (Session)</div>
      <div id="kpi-runtime" class="kpi">{format_duration(int(time.time() - status["start_time"]))}</div>
      <div class="muted small">Seit App-Start</div>
    </div>
    <div class="card">
      <div class="muted small">🧮 Geprüfte Adressen (Session)</div>
      <div class="kpi"><span id="kpi-checked">{status['checked']}</span></div>
      <div class="muted small">IO/NIO: <span id="kpi-io">{status['io']}</span> / <span id="kpi-nio">{status['nio']}</span> &nbsp;·&nbsp; Rate (Soll): <span id="kpi-rate">{status['rate']:.2f}</span> / s</div>
    </div>
    <div class="card">
      <div class="muted small">🕒 Gesamt-Laufzeit</div>
      <div class="kpi"><span id="kpi-total-hours-human">{format_duration_hours(total_hours)}</span> <span class="small muted">(<span id="kpi-total-hours">{total_hours:.1f}</span> h)</span></div>
      <div class="muted small">Kumuliert (DB)</div>
    </div>
    <div class="card">
      <div class="muted small">📈 Gesamt geprüfte Adressen</div>
      <div id="kpi-total-checked" class="kpi">{total_checked}</div>
      <div class="muted small">Kumuliert (DB)</div>
    </div>
  </div>

  <!-- 2. Reihe: Quota als volle Zeile -->
  <div class="card" style="margin-top:16px;">
    <div class="quota-grid">
      <!-- linke Spalte: große Zahl + Budgets/Remaining -->
      <div class="quota-left">
        <div class="muted small">🧯 Quota (Blockstream)</div>
        <div class="kpi"><span id="quota-suggest">{suggested}</span> <span class="small muted">/ min</span></div>
        <div class="muted small">Fenster: {cycle_start} – {cycle_end_incl}</div>

        <div class="row small" style="margin-top:8px; gap:8px;">
          <div class="tag">Min übrig: <span id="q-rem-min">—</span></div>
          <div class="tag">Std übrig: <span id="q-rem-hr">—</span></div>
          <div class="tag">Tag übrig: <span id="q-rem-day">—</span></div>
          <div class="tag">Monat übrig: <span id="q-rem-cyc">—</span></div>
        </div>

        <div class="row small" style="margin-top:8px; gap:8px;">
          <div class="tag">Min Budget: <span id="q-bud-min">—</span></div>
          <div class="tag">Std Budget: <span id="q-bud-hr">—</span></div>
          <div class="tag">Tag Budget: <span id="q-bud-day">—</span></div>
        </div>

        <!-- Backlog-Zeile -->
        <div class="row small" style="margin-top:8px; gap:8px;">
          <div class="tag">Backlog: <span id="q-backlog">—</span></div>
        </div>
      </div>

      <!-- rechte Spalte: Eingabe/Buttons -->
      <div class="quota-right">
        <form id="cap-form" class="row small" style="gap:8px;" onsubmit="return false;">
          <label for="month_cap" class="muted">Monatslimit:</label>
          <input id="month_cap" name="month_cap" type="number" min="1000" step="1000" value="{q['month_cap']}" />
          <button id="cap-btn" type="button">Speichern</button>
        </form>

        <div class="row small" style="gap:8px; margin-top:6px;">
          <div class="muted">Derzeit ca.</div>
          <div class="tag"><span id="quota-suggest-dup">{suggested}</span> / min</div>
        </div>
      </div>
    </div>
  </div>

  <div class="card" style="margin-top:16px;">
    <div class="row" style="justify-content:space-between; align-items:center;">
      <div class="row" style="gap:16px;">
        <div><strong>System-Status:</strong></div>
        <div class="tag">Session-Rate: <span id="tag-rate">{status['rate']:.2f}</span> / s</div>
        <div class="tag">Gefunden (Session): <span id="tag-found">{status['found']}</span></div>
      </div>
      <div class="row" style="gap:8px;">
        <button id="pause-btn" class="btn">{'Fortsetzen' if status['paused'] else 'Pause'}</button>
        <div class="muted small">Jetzt: <span id="now">{now_de_str()}</span></div>
      </div>
    </div>
  </div>

  <!-- Prüfprotokoll -->
  <div class="card" style="margin-top:16px;">
    <div class="row" style="justify-content:space-between; align-items:center;">
      <div><strong>🧪 Protokoll letzte geprüfte Adressen</strong> <span class="muted small">(behält <span id="keep-badge">{_check_keep}</span>)</span></div>
      <form id="keep-form" class="row small" style="gap:8px;" onsubmit="return false;">
        <label for="keep" class="muted">Anzahl behalten/anzeigen:</label>
        <input id="keep" name="keep" type="number" min="{CHECK_KEEP_MIN}" max="{CHECK_KEEP_MAX}" step="10" value="{_check_keep}" />
        <button id="keep-btn" type="button">Übernehmen</button>
      </form>
    </div>
    <div id="checks-scroll" class="scrollbox six-rows" style="margin-top:10px;">
      <table>
        <thead>
          <tr>
            <th>Datum/Uhrzeit</th>
            <th>Walletadresse</th>
            <th>Typ</th>
            <th>Guthaben (BTC)</th>
            <th>API-Dienst</th>
            <th>Prüfung</th>
            <th>HTTP</th>
            <th>Dauer (ms)</th>
          </tr>
        </thead>
        <tbody id="checks-body">
          <tr><td colspan="8" class="muted small">Lade…</td></tr>
        </tbody>
      </table>
    </div>
    <div class="muted small" style="margin-top:8px;">
      Neueste oben · Kein Autoscroll beim Nachladen, außer du bist am oberen Rand.
    </div>
  </div>

  <!-- Gefundene Wallets -->
  <div class="card" style="margin-top:16px;">
    <div><strong>🪙 Gefundene Wallets</strong> <span class="muted small">(letzte {FIND_LIMIT})</span></div>
    <div id="finds-scroll" class="scrollbox" style="margin-top:10px; max-height:260px;">
      <table>
        <thead>
          <tr>
            <th>Zeit (DE)</th>
            <th>Typ</th>
            <th>Adresse</th>
            <th>Guthaben (BTC)</th>
            <th>Seed (mnemonic)</th>
          </tr>
        </thead>
        <tbody id="finds-body">
          {''.join(
            f"<tr><td>{ts}</td><td>{typ}</td><td><code>{addr}</code></td><td>{balance:.8f}</td><td><code>{seed}</code></td></tr>"
            for (ts, typ, addr, balance, seed) in recent
          ) or "<tr><td colspan='5' class='muted small'>Noch keine Funde</td></tr>"}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Quota-Historie (letzte 12 Zyklen) -->
  <div class="card" style="margin-top:16px;">
    <div><strong>📊 Quota-Verbrauch letzte 12 Abrechnungsmonate</strong></div>
    <div class="scrollbox" style="margin-top:10px; max-height:260px;">
      <table>
        <thead>
          <tr>
            <th>Zeitraum</th>
            <th>Verbrauchte Requests</th>
            <th>Limit</th>
          </tr>
        </thead>
        <tbody>
          {hist_rows}
        </tbody>
      </table>
    </div>
  </div>

  <div class="footer">© BTC Checker · v{__version__}</div>
</div>

<script>
  function escHtml(s) {{
    if (s === null || s === undefined) return "";
    return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
  }}

  async function updateStatus() {{
    try {{
      const r = await fetch('/status.json', {{cache:'no-store'}});
      const d = await r.json();
      document.getElementById('kpi-runtime').textContent = d.session.runtime_human;
      document.getElementById('kpi-checked').textContent = d.session.checked;
      document.getElementById('kpi-io').textContent = d.session.io;
      document.getElementById('kpi-nio').textContent = d.session.nio;
      document.getElementById('kpi-rate').textContent = d.session.rate.toFixed(2);
      document.getElementById('tag-rate').textContent = d.session.rate.toFixed(2);
      document.getElementById('tag-found').textContent = d.session.found;
      document.getElementById('kpi-total-hours-human').textContent = d.total.hours_human;
      document.getElementById('kpi-total-hours').textContent = d.total.hours.toFixed(1);
      document.getElementById('kpi-total-checked').textContent = d.total.checked;
      document.getElementById('now').textContent = d.now;

      const pbtn = document.getElementById('pause-btn');
      pbtn.textContent = d.session.paused ? 'Fortsetzen' : 'Pause';
    }} catch(e) {{}}
  }}

  async function updateQuota() {{
    try {{
      const r = await fetch('/quota.json', {{cache:'no-store'}});
      const q = await r.json();
      document.getElementById('quota-suggest').textContent = q.suggested_per_minute;

      document.getElementById('q-rem-min').textContent = q.remaining.minute;
      document.getElementById('q-rem-hr').textContent  = q.remaining.hour;
      document.getElementById('q-rem-day').textContent = q.remaining.day;
      document.getElementById('q-rem-cyc').textContent = q.remaining.cycle;

      document.getElementById('q-bud-min').textContent = q.budgets.per_minute;
      document.getElementById('q-bud-hr').textContent  = q.budgets.per_hour;
      document.getElementById('q-bud-day').textContent = q.budgets.per_day;

      document.getElementById('quota-suggest-dup').textContent = q.suggested_per_minute;      
      document.getElementById('q-backlog').textContent = q.backlog_tokens;

      const cap = document.getElementById('month_cap');
      if (!cap.value) cap.value = q.month_cap;
    }} catch(e) {{}}
  }}

  const checksScroll = document.getElementById('checks-scroll');
  const checksBody = document.getElementById('checks-body');
  async function updateChecks() {{
    const atTop = (checksScroll.scrollTop === 0);
    const prev = checksScroll.scrollTop;
    try {{
      const keepVal = encodeURIComponent(document.getElementById('keep').value);
      const r = await fetch('/recent_checks.json?limit=' + keepVal, {{cache:'no-store'}});
      const items = await r.json();
      var html = "";
      for (var i=0;i<items.length;i++) {{
        var it = items[i];
        var okTxt = it.ok ? "IO" : "NIO";
        var okCls = it.ok ? "ok" : "nio";
        var httpTxt = (it.http_status === null) ? "—" : String(it.http_status);
        html += "<tr>"
              + "<td>" + escHtml(it.ts) + "</td>"
              + "<td><code>" + escHtml(it.addr) + "</code></td>"
              + "<td>" + escHtml(it.typ) + "</td>"
              + "<td>" + Number(it.balance).toFixed(8) + "</td>"
              + "<td>" + escHtml(it.service) + "</td>"
              + "<td class='" + okCls + "'>" + okTxt + "</td>"
              + "<td>" + httpTxt + "</td>"
              + "<td>" + escHtml(it.duration_ms) + "</td>"
              + "</tr>";
      }}
      if (html === "") {{
        html = '<tr><td colspan="8" class="muted small">Noch keine Prüfungen</td></tr>';
      }}
      checksBody.innerHTML = html;
      if (atTop) {{
        checksScroll.scrollTop = 0;
      }} else {{
        checksScroll.scrollTop = prev;
      }}
    }} catch(e) {{}}
  }}

  const findsScroll = document.getElementById('finds-scroll');
  const findsBody = document.getElementById('finds-body');
  async function updateFinds() {{
    const atTop = (findsScroll.scrollTop === 0);
    const thePrev = findsScroll.scrollTop;
    try {{
      const r = await fetch('/recent_finds.json', {{cache:'no-store'}});
      const items = await r.json();
      var html = "";
      for (var i=0;i<items.length;i++) {{
        var it = items[i];
        html += "<tr>"
              + "<td>" + escHtml(it.ts) + "</td>"
              + "<td>" + escHtml(it.typ) + "</td>"
              + "<td><code>" + escHtml(it.addr) + "</code></td>"
              + "<td>" + Number(it.balance).toFixed(8) + "</td>"
              + "<td><code>" + escHtml(it.seed) + "</code></td>"
              + "</tr>";
      }}
      if (html === "") {{
        html = "<tr><td colspan='5' class='muted small'>Noch keine Funde</td></tr>";
      }}
      findsBody.innerHTML = html;
      if (atTop) {{
        findsScroll.scrollTop = 0;
      }} else {{
        findsScroll.scrollTop = thePrev;
      }}
    }} catch(e) {{}}
  }}

  document.getElementById('keep-btn').addEventListener('click', async function() {{
    var val = document.getElementById('keep').value;
    try {{
      const fd = new FormData(); fd.append('keep', val);
      const r = await fetch('/set_keep', {{method:'POST', body: fd}});
      const d = await r.json();
      if (d.ok) {{
        document.getElementById('keep-badge').textContent = d.keep;
        updateChecks();
      }}
    }} catch(e) {{}}
  }});

  document.getElementById('cap-btn').addEventListener('click', async function() {{
    const cap = document.getElementById('month_cap').value;
    try {{
      const fd = new FormData(); fd.append('month_cap', cap);
      const r = await fetch('/set_month_cap', {{method:'POST', body: fd}});
      const d = await r.json();
      if (d.ok) {{
        updateQuota();
      }}
    }} catch(e) {{}}
  }});

  document.getElementById('pause-btn').addEventListener('click', async function() {{
    try {{
      const r = await fetch('/toggle_pause', {{method:'POST'}});
      const d = await r.json();
      if (d.ok) {{
        this.textContent = d.paused ? 'Fortsetzen' : 'Pause';
      }}
    }} catch(e) {{}}
  }});

  function tick() {{
    updateStatus();
    updateQuota();
    updateChecks();
  }}
  tick();
  setInterval(updateStatus, 1000);
  setInterval(updateQuota, 1000);
  setInterval(updateChecks, 1000);
  setInterval(updateFinds, 5000);
</script>
</body>
</html>
"""

# --------------------------------- Startpunkt ---------------------------------
if __name__ == "__main__":
    db_init()
    threading.Thread(target=suchroutine, daemon=True).start()
    threading.Thread(target=persist_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5001)
