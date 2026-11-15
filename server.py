#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
White API — сервер личного кабинета и система ключей.
Только стандартная библиотека Python 3.8+, ничего устанавливать не нужно.

  python server.py                запуск сервера + консоль выдачи ключей
  python server.py gen 500k       выдать ключ на 500 000 токенов (и выйти)
  python server.py gen 1m 5       выдать 5 ключей по 1 000 000 токенов
  python server.py list           список всех ключей

Команды те же самые можно вводить прямо в консоли запущенного сервера:
  gen <токены> [кол-во]   выдать код доступа (TC-XXXX-XXXX-XXXX)
  list                    список кодов и остатков
  gen 30d [кол-во]        безлимитный код на 30 дней
  admin                   адрес админки;  adminpass <пароль> / adminlogin <логин>
  topup <код> <токены>    добавить токены
  revoke <код>            заблокировать код
  restore <код>           разблокировать
  help / exit

Токены можно писать так: 500000, 500k, 1.5m, 2_000_000.

При заданном DATABASE_URL данные keys/sessions/models/admin сохраняются в PostgreSQL. Без DATABASE_URL используется локальный JSON.
Настройки через переменные окружения:
  PORT=8080                порт
  WHITE_HOST=127.0.0.1     адрес (0.0.0.0 — слушать снаружи)
  WHITE_BASE_URL=https://твой-домен.ру/v1   что показывать в кабинете как Base URL
  WHITE_TRUST_PROXY=1      если стоишь за nginx/Cloudflare (читать X-Forwarded-*)
"""
import hashlib
import http.server
import json
import os
import re
import secrets
import sys
import threading
import time
from collections import defaultdict, deque
from http import cookies
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import io
import uuid
import time as _time
import ai_engine

ROOT = Path(__file__).resolve().parent
# Render's container filesystem is ephemeral. Set DATABASE_URL to a PostgreSQL
# database to persist keys, sessions, model list and admin credentials across deploys.
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DB_TABLE = "whiteapi_json_store"
_db_init_lock = threading.Lock()
_db_initialized = False

KEYS_FILE = ROOT / "keys.json"
SESSIONS_FILE = ROOT / "sessions.json"
MODELS_FILE = ROOT / "models.json"
ADMIN_FILE = ROOT / "admin.json"
SETTINGS_FILE = ROOT / "settings.json"   # общая заморозка и её сообщение
STATS_FILE = ROOT / "stats.json"         # история запросов по дням/часам для аналитики


def _db_connect():
    if not DATABASE_URL:
        return None
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("DATABASE_URL задан, но psycopg не установлен. Проверь requirements.txt") from exc
    dsn = DATABASE_URL
    if dsn.startswith("postgres://"):
        dsn = "postgresql://" + dsn[len("postgres://"):]
    return psycopg.connect(dsn, connect_timeout=10)


def _ensure_db():
    global _db_initialized
    if not DATABASE_URL or _db_initialized:
        return
    with _db_init_lock:
        if _db_initialized:
            return
        with _db_connect() as conn:
            conn.execute(f"CREATE TABLE IF NOT EXISTS {DB_TABLE} (name TEXT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
        _db_initialized = True


def _db_read(name, default):
    _ensure_db()
    with _db_connect() as conn:
        row = conn.execute(f"SELECT data FROM {DB_TABLE} WHERE name = %s", (name,)).fetchone()
    return row[0] if row else default


def _db_write(name, data):
    _ensure_db()
    with _db_connect() as conn:
        conn.execute(
            f"INSERT INTO {DB_TABLE} (name, data, updated_at) VALUES (%s, %s::jsonb, NOW()) "
            f"ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()",
            (name, json.dumps(data, ensure_ascii=False)),
        )


def _import_existing_json_once():
    """Import old local JSON files only when their database row does not exist."""
    if not DATABASE_URL:
        return
    _ensure_db()
    for path in (KEYS_FILE, SESSIONS_FILE, MODELS_FILE, ADMIN_FILE):
        if not path.is_file():
            continue
        with _db_connect() as conn:
            found = conn.execute(f"SELECT 1 FROM {DB_TABLE} WHERE name = %s", (path.name,)).fetchone()
            if found:
                continue
        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            _db_write(path.name, data)
            print(f"[database] Импортированы старые данные: {path.name}")
        except Exception as exc:
            print(f"[database] Не удалось импортировать {path.name}: {type(exc).__name__}: {exc}")

HOST = os.environ.get("WHITE_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8080"))
PUBLIC_BASE_URL = os.environ.get("WHITE_BASE_URL", "").rstrip("/")
TRUST_PROXY = os.environ.get("WHITE_TRUST_PROXY") == "1"

CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"        # без похожих 0/O и 1/I
CODE_RE = re.compile(r"^TC-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$")
API_PREFIX = "white_api_"
SESSION_TTL = 30 * 24 * 3600
COOKIE = "wsid"
ADMIN_COOKIE = "wadm"
ADMIN_TTL = 12 * 3600

DEFAULT_MODELS = [
    {"id": "claude-fable-5", "title": "Claude Fable 5"},
    {"id": "gpt-astra-6", "title": "GPT Astra 6"},
    {"id": "claude-opus-5-5", "title": "Claude Opus 5.5"},
    {"id": "gpt-sol-5-6", "title": "GPT Sol 5.6"},
    {"id": "kimi-k3", "title": "Kimi K3"},
    {"id": "glm-5-3", "title": "Glm 5.3"},
]

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/cabinet": ("cabinet.html", "text/html; charset=utf-8"),
    "/cabinet.html": ("cabinet.html", "text/html; charset=utf-8"),
    "/guide": ("guide.html", "text/html; charset=utf-8"),
    "/guide.html": ("guide.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/theme.css": ("theme.css", "text/css; charset=utf-8"),
    "/theme.js": ("theme.js", "application/javascript; charset=utf-8"),
    "/freeze-notice.js": ("freeze-notice.js", "application/javascript; charset=utf-8"),
    "/app": ("app.html", "text/html; charset=utf-8"),
    "/app/": ("app.html", "text/html; charset=utf-8"),
    "/app.html": ("app.html", "text/html; charset=utf-8"),
    "/app/manifest.webmanifest": ("app-manifest.webmanifest", "application/manifest+json; charset=utf-8"),
    "/app/sw.js": ("app-sw.js", "application/javascript; charset=utf-8"),
    "/app/icon-192.png": ("app-icon-192.png", "image/png"),
    "/app/icon-512.png": ("app-icon-512.png", "image/png"),
    "/app/apple-touch-icon.png": ("app-apple-touch-icon.png", "image/png"),
    "/white-api-installer.ps1": ("white-api-installer.ps1", "text/plain; charset=utf-8"),
    "/install.ps1": ("white-api-installer.ps1", "text/plain; charset=utf-8"),
    "/install.sh": ("install.sh", "text/plain; charset=utf-8"),
    "/WhiteCode.exe": ("WhiteCode.exe", "application/octet-stream"),
    "/white-api-tutorial.mp4": ("white-api-tutorial.mp4", "video/mp4"),
}


def now():
    return int(time.time())


def fmt(n):
    return f"{int(n):,}".replace(",", " ")


def fmt_date(ts):
    return time.strftime("%d.%m.%Y %H:%M", time.localtime(ts)) if ts else "—"


# ------------------------------------------------------------------ хранилище
class Store:
    """Простое JSON-хранилище. Файлы читаются заново при каждом обращении,
    поэтому ключи, выданные из другого терминала, сразу работают на сайте."""

    def __init__(self):
        self.lock = threading.RLock()

    @staticmethod
    def _read(path, default):
        if DATABASE_URL:
            return _db_read(path.name, default)
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return default
        except json.JSONDecodeError:
            sys.exit(f"Файл {path.name} повреждён. Исправь его или удали (сделай копию!).")

    @staticmethod
    def _write(path, data):
        if DATABASE_URL:
            _db_write(path.name, data)
            return
        tmp = path.with_name(path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

    # --- ключи
    @staticmethod
    def _norm(k):
        for key, val in (("type", "tokens"), ("frozen", False), ("duration_days", 0), ("expires_at", None), ("models", None),
                         ("limits", {}), ("note", ""), ("last_used_at", None), ("requests", 0), ("log", [])):
            k.setdefault(key, val)
        return k

    @staticmethod
    def log(rec, action, detail=""):
        rec["log"] = (rec["log"] + [{"ts": now(), "action": action, "detail": detail}])[-100:]

    def _keys(self):
        return [self._norm(k) for k in self._read(KEYS_FILE, {"keys": []})["keys"]]

    def _save(self, keys):
        self._write(KEYS_FILE, {"keys": keys})

    def list(self):
        with self.lock:
            return self._keys()

    def issue(self, tokens=0, count=1, days=0, models=None, limits=None, note=""):
        """days > 0 — безлимитный ключ на N дней (отсчёт с первого входа в кабинет)."""
        with self.lock:
            keys = self._keys()
            codes = {k["code"] for k in keys}
            made = []
            for _ in range(count):
                while True:
                    code = "TC-" + "-".join(
                        "".join(secrets.choice(CODE_ALPHABET) for _ in range(4)) for _ in range(3)
                    )
                    if code not in codes:
                        break
                codes.add(code)
                rec = self._norm({
                    "code": code,
                    "api_key": API_PREFIX + secrets.token_hex(24),   # white_api_ + 48 hex
                    "type": "unlimited" if days else "tokens",
                    "tokens_total": 0 if days else tokens,
                    "tokens_used": 0,
                    "revoked": False,
                    "created_at": now(),
                    "activated_at": None,
                    "duration_days": days,
                    "models": models, "limits": limits or {}, "note": note,
                })
                self.log(rec, "created", f"безлимит {days} дн." if days else f"{fmt(tokens)} токенов")
                keys.append(rec)
                made.append(rec)
            self._save(keys)
            return made

    def find_code(self, code):
        with self.lock:
            return next((k for k in self._keys() if k["code"] == code), None)

    def find_api_key(self, api_key):
        with self.lock:
            return next((k for k in self._keys() if secrets.compare_digest(k["api_key"], api_key)), None)

    def _update(self, code, fn):
        with self.lock:
            keys = self._keys()
            rec = next((k for k in keys if k["code"] == code), None)
            if rec is None:
                return None
            fn(rec)
            self._save(keys)
            return rec

    def mark_activated(self, code):
        def f(r):
            if not r["activated_at"]:
                r["activated_at"] = now()
                if r["type"] == "unlimited":
                    r["expires_at"] = now() + r["duration_days"] * 86400
                self.log(r, "activated")
        return self._update(code, f)

    def topup(self, code, tokens):
        def f(r):
            r["tokens_total"] += tokens
            self.log(r, "topup", f"+{fmt(tokens)} токенов")
        return self._update(code, f)

    def delete_code(self, code):
        with self.lock:
            keys = self._keys()
            kept = [k for k in keys if k.get("code") != code]
            if len(kept) == len(keys):
                return False
            self._save(kept)
            return True

    def set_revoked(self, code, value):
        def f(r):
            r["revoked"] = value
            self.log(r, "revoke" if value else "restore")
        return self._update(code, f)

    def act(self, code, action, d):
        """Действия из админки. Возвращает (ключ, ошибка)."""
        err = []

        def f(r):
            if action == "freeze":
                r["frozen"] = True; self.log(r, "freeze")
            elif action == "unfreeze":
                r["frozen"] = r["revoked"] = False; self.log(r, "unfreeze")
            elif action == "topup" and r["type"] == "tokens":
                n = parse_tokens(str(d.get("value", "")))
                if not n:
                    return err.append("bad_value")
                r["tokens_total"] += n; self.log(r, "topup", f"+{fmt(n)} токенов")
            elif action == "add_days" and r["type"] == "unlimited":
                try:
                    n = int(d.get("value"))
                except (TypeError, ValueError):
                    n = 0
                if not 1 <= n <= 3650:
                    return err.append("bad_value")
                if r["expires_at"]:
                    r["expires_at"] = max(r["expires_at"], now()) + n * 86400
                else:
                    r["duration_days"] += n
                self.log(r, "add_days", f"+{n} дн.")
            elif action == "limits":
                r["limits"] = clean_limits(d.get("limits")); self.log(r, "limits", json.dumps(r["limits"]))
            elif action == "models":
                r["models"] = clean_models(d.get("models")); self.log(r, "models", ", ".join(r["models"] or ["все"]))
            elif action == "note":
                r["note"] = str(d.get("value", ""))[:200]
            else:
                err.append("bad_action")

        rec = self._update(code, f)
        return rec, ("not_found" if rec is None else (err[0] if err else None))

    # --- мосты для ai_engine (статистика и сообщение общей заморозки)
    def record_event(self, kind, **kw):
        stats.record(kind, **kw)

    def freeze_message(self):
        return freeze_public()

    def authorize(self, api_key, model=None):
        """Для шлюза: вызывать ПЕРЕД запросом к модели. Возвращает (ключ, ошибка|None).
        Ошибки: invalid_key, frozen, expired, depleted, model_not_allowed, rate_limit_rpm/rpd/tpd.
        После ответа вызови spend(api_key, токены)."""
        rec = self.find_api_key(api_key)
        if rec is None:
            return None, "invalid_key"
        st = status_of(rec)
        if st in ("frozen", "expired", "depleted"):
            return rec, st
        if model and rec["models"] is not None and model not in rec["models"]:
            return rec, "model_not_allowed"
        return rec, meter.check(rec)

    def spend(self, api_key, tokens):
        """Списать токены после запроса. Возвращает остаток (для безлимита -1) или None, если списать нельзя."""
        with self.lock:
            keys = self._keys()
            rec = next((k for k in keys if secrets.compare_digest(k["api_key"], api_key)), None)
            if rec is None or status_of(rec) not in ("active", "pending"):
                return None
            n = int(tokens)
            unl = rec["type"] == "unlimited"
            rec["tokens_used"] = rec["tokens_used"] + n if unl else min(rec["tokens_total"], rec["tokens_used"] + n)
            rec["requests"] += 1
            rec["last_used_at"] = now()
            self._save(keys)
        meter.add_tokens(rec["code"], n)
        return -1 if unl else rec["tokens_total"] - rec["tokens_used"]

    # --- сессии (в файле лежат только хэши токенов)
    @staticmethod
    def _h(token):
        return hashlib.sha256(token.encode()).hexdigest()

    def create_session(self, code):
        token = secrets.token_urlsafe(32)
        with self.lock:
            data = {h: s for h, s in self._read(SESSIONS_FILE, {}).items() if s["exp"] > now()}
            data[self._h(token)] = {"code": code, "exp": now() + SESSION_TTL}
            self._write(SESSIONS_FILE, data)
        return token

    def session_code(self, token):
        with self.lock:
            s = self._read(SESSIONS_FILE, {}).get(self._h(token))
        return s["code"] if s and s["exp"] > now() else None

    def drop_session(self, token):
        with self.lock:
            data = self._read(SESSIONS_FILE, {})
            if data.pop(self._h(token), None) is not None:
                self._write(SESSIONS_FILE, data)


if DATABASE_URL:
    _import_existing_json_once()
    print("[database] PostgreSQL persistence enabled (DATABASE_URL).")
else:
    print("[database] DATABASE_URL не задан: используется локальный JSON, на Render данные могут исчезнуть при redeploy.")

store = Store()
ai_engine.set_white_store(store)

DEFAULT_FREEZE_MSG = "Все ключи временно заморожены. Работа API приостановлена, скоро всё вернётся в норму."


class Settings:
    """Общие настройки (сейчас — общая заморозка всех ключей). Кэш на 3 секунды, чтобы не ходить в БД на каждый запрос."""
    TTL = 3

    def __init__(self):
        self.lock = threading.Lock()
        self._d = None
        self._t = 0.0

    def get(self):
        with self.lock:
            if self._d is None or time.time() - self._t > self.TTL:
                try:
                    d = Store._read(SETTINGS_FILE, {})
                except (Exception, SystemExit):
                    d = self._d or {}
                self._d = d if isinstance(d, dict) else {}
                self._t = time.time()
            return dict(self._d)

    def update(self, upd):
        with self.lock:
            try:
                d = Store._read(SETTINGS_FILE, {})
            except (Exception, SystemExit):
                d = {}
            d = dict(d) if isinstance(d, dict) else {}
            d.update(upd)
            Store._write(SETTINGS_FILE, d)
            self._d, self._t = d, time.time()


settings = Settings()


def freeze_on():
    return bool(settings.get().get("freeze_all"))


def freeze_state():
    """Для админки: включено ли, сохранённый текст, с какого времени."""
    s = settings.get()
    return {"on": bool(s.get("freeze_all")), "message": str(s.get("freeze_message") or ""), "since": s.get("freeze_since")}


def freeze_public():
    """Для покупателей: только то, что можно показать (текст по умолчанию, если свой не задан)."""
    st = freeze_state()
    if not st["on"]:
        return {"on": False}
    return {"on": True, "message": st["message"] or DEFAULT_FREEZE_MSG, "default": not st["message"], "since": st["since"]}


class Stats:
    """История использования API по дням и часам (для вкладки «Аналитика»).
    Копится в памяти и сбрасывается в хранилище раз в ~15 секунд. Время — серверное (на Render это UTC)."""
    KEEP_DAYS, KEEP_HOURS, FLUSH = 120, 72, 15

    def __init__(self):
        self.lock = threading.Lock()
        self.wlock = threading.Lock()
        self._d = None
        self._last = time.time()
        self._dirty = False

    def _data(self):
        if self._d is None:
            try:
                d = Store._read(STATS_FILE, {})
            except (Exception, SystemExit):
                d = {}
            if not isinstance(d, dict):
                d = {}
            if not isinstance(d.get("days"), dict):
                d["days"] = {}
            if not isinstance(d.get("hours"), dict):
                d["hours"] = {}
            d.setdefault("since", now())
            self._d = d
        return self._d

    @staticmethod
    def _inc(b, key, n=1):
        b[key] = b.get(key, 0) + n

    def record(self, kind, model="", provider="", tokens=0, reason=""):
        day, hour = time.strftime("%Y-%m-%d"), time.strftime("%Y-%m-%d %H")
        try:
            tokens = int(tokens or 0)
        except (TypeError, ValueError):
            tokens = 0
        with self.lock:
            d = self._data()
            D, H = d["days"].setdefault(day, {}), d["hours"].setdefault(hour, {})
            if kind == "ok":
                for b in (D, H):
                    self._inc(b, "req"); self._inc(b, "tok", tokens)
                for grp, name in (("models", model), ("providers", provider)):
                    if name:
                        b = D.setdefault(grp, {}).setdefault(name, {})
                        self._inc(b, "req"); self._inc(b, "tok", tokens)
            elif kind == "perr":
                self._inc(D, "perr")
                if provider:
                    self._inc(D.setdefault("providers", {}).setdefault(provider, {}), "err")
            elif kind == "fail":
                for b in (D, H):
                    self._inc(b, "fail")
                if model:
                    self._inc(D.setdefault("models", {}).setdefault(model, {}), "fail")
            elif kind == "blocked":
                self._inc(D, "blocked")
                if reason:
                    self._inc(D.setdefault("blocked_by", {}), str(reason)[:30])
            elif kind in ("login", "login_fail"):
                self._inc(D, kind)
            else:
                return
            self._dirty = True
            due = time.time() - self._last >= self.FLUSH
            if due:
                self._last = time.time()
        if due:
            self.flush()

    def flush(self):
        with self.wlock:
            with self.lock:
                if self._d is None or not self._dirty:
                    return
                d = self._d
                for k in sorted(d["days"])[:-self.KEEP_DAYS]:
                    d["days"].pop(k, None)
                for k in sorted(d["hours"])[:-self.KEEP_HOURS]:
                    d["hours"].pop(k, None)
                snap = json.loads(json.dumps(d))
                self._dirty = False
            try:
                Store._write(STATS_FILE, snap)
            except Exception as exc:
                self._dirty = True
                print(f"[stats] не удалось сохранить: {type(exc).__name__}")

    def snapshot(self, days=30):
        self.flush()
        with self.lock:
            d = json.loads(json.dumps(self._data()))
        t = time.time()
        dates = [time.strftime("%Y-%m-%d", time.localtime(t - i * 86400)) for i in range(days - 1, -1, -1)]
        rows, models, provs, blocked = [], {}, {}, {}
        sums = {k: 0 for k in ("req", "tok", "fail", "perr", "blocked", "login", "login_fail")}
        for dt_ in dates:
            b = d["days"].get(dt_, {})
            row = {"date": dt_}
            for k in sums:
                row[k] = int(b.get(k, 0)); sums[k] += row[k]
            rows.append(row)
            for grp, acc in (("models", models), ("providers", provs)):
                for name, v in (b.get(grp) or {}).items():
                    a = acc.setdefault(name, {"req": 0, "tok": 0, "fail": 0, "err": 0})
                    for k in a:
                        a[k] += int(v.get(k, 0))
            for name, n in (b.get("blocked_by") or {}).items():
                blocked[name] = blocked.get(name, 0) + int(n)
        hours = []
        for i in range(23, -1, -1):
            hk = time.strftime("%Y-%m-%d %H", time.localtime(t - i * 3600))
            b = d["hours"].get(hk, {})
            hours.append({"hour": hk[-2:], "req": int(b.get("req", 0)), "tok": int(b.get("tok", 0)), "fail": int(b.get("fail", 0))})
        return {"since": d.get("since"), "rows": rows, "hours": hours, "sums": sums, "models": models, "providers": provs, "blocked_by": blocked}


stats = Stats()
ai_engine.set_disabled_keys(settings.get().get("disabled_keys") or [])


def status_of(r, ignore_global=False):
    """active / pending (ещё не входил) / frozen / expired / depleted.
    Общая заморозка (freeze_all) не меняет сами ключи: просто все живые ключи считаются замороженными."""
    if r["type"] == "unlimited":
        if r["expires_at"] and r["expires_at"] <= now():
            return "expired"
    elif r["tokens_used"] >= r["tokens_total"]:
        return "depleted"
    if r["frozen"] or r["revoked"] or (not ignore_global and freeze_on()):
        return "frozen"
    return "active" if r["activated_at"] else "pending"


def clean_limits(d):
    out = {}
    for k in ("rpm", "rpd", "tpd"):
        try:
            v = int((d or {}).get(k) or 0)
        except (TypeError, ValueError):
            v = 0
        if 0 < v <= 10**10:
            out[k] = v
    return out


def clean_models(m):
    ids = [x["id"] for x in load_models()]
    chosen = [x for x in (m or []) if x in ids]
    return None if not chosen or len(chosen) == len(ids) else chosen   # None = все модели


class Meter:
    """Лимиты в памяти: запросов в минуту / в сутки и токенов в сутки (сбрасываются при перезапуске)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.hits = defaultdict(deque)
        self.day = {}

    def _day(self, code):
        today = time.strftime("%Y%m%d")
        d = self.day.get(code)
        if not d or d[0] != today:
            d = self.day[code] = [today, 0, 0]
        return d

    def check(self, rec):
        lim, code, t = rec["limits"], rec["code"], time.time()
        with self.lock:
            q, d = self.hits[code], self._day(code)
            while q and q[0] < t - 60:
                q.popleft()
            if lim.get("rpm") and len(q) >= lim["rpm"]:
                return "rate_limit_rpm"
            if lim.get("rpd") and d[1] >= lim["rpd"]:
                return "rate_limit_rpd"
            if lim.get("tpd") and d[2] >= lim["tpd"]:
                return "rate_limit_tpd"
            q.append(t)
            d[1] += 1
        return None

    def add_tokens(self, code, n):
        with self.lock:
            self._day(code)[2] += n


meter = Meter()


class Admin:
    """Вход в админку: секретный адрес + логин/пароль (PBKDF2). Данные — admin.json."""
    ITER = 200_000
    fresh_password = None

    def __init__(self):
        self.lock = threading.Lock()
        self.sessions = {}
        self._data = None

    @classmethod
    def _hash(cls, pw, salt):
        return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, cls.ITER).hex()

    def data(self):
        """Читает admin.json; при первом запуске создаёт (пароль виден один раз — fresh_password)."""
        if self._data is None:
            d = Store._read(ADMIN_FILE, None)
            if not d:
                pw = os.environ.get("WHITE_ADMIN_PASS") or secrets.token_urlsafe(12)
                salt = secrets.token_bytes(16)
                d = {"slug": secrets.token_urlsafe(9), "login": os.environ.get("WHITE_ADMIN_USER", "admin"),
                     "salt": salt.hex(), "hash": self._hash(pw, salt)}
                Store._write(ADMIN_FILE, d)
                self.fresh_password = pw
            self._data = d
        return self._data

    def slug(self):
        env = re.sub(r"[^A-Za-z0-9_-]", "", os.environ.get("WHITE_ADMIN_PATH", ""))
        return env if len(env) >= 6 else self.data()["slug"]

    def verify(self, login, pw):
        d = self.data()
        ok_pw = secrets.compare_digest(self._hash(str(pw), bytes.fromhex(d["salt"])), d["hash"])
        ok_login = secrets.compare_digest(str(login).encode(), d["login"].encode())
        return ok_pw and ok_login

    def set_credentials(self, login=None, password=None):
        d = dict(self.data())
        if login:
            d["login"] = login
        if password:
            salt = secrets.token_bytes(16)
            d["salt"], d["hash"] = salt.hex(), self._hash(password, salt)
        Store._write(ADMIN_FILE, d)
        self._data = d
        with self.lock:
            self.sessions.clear()

    def new_session(self):
        token = secrets.token_urlsafe(32)
        with self.lock:
            self.sessions = {h: e for h, e in self.sessions.items() if e > now()}
            self.sessions[Store._h(token)] = now() + ADMIN_TTL
        return token

    def valid(self, token):
        with self.lock:
            return bool(token) and self.sessions.get(Store._h(token), 0) > now()

    def drop(self, token):
        with self.lock:
            self.sessions.pop(Store._h(token), None)


admin = Admin()


class Limiter:
    """Не больше 10 неверных кодов за 10 минут с одного адреса."""
    WINDOW, MAX = 600, 10

    def __init__(self):
        self.fails = defaultdict(deque)
        self.lock = threading.Lock()

    def _prune(self, ip):
        q = self.fails[ip]
        while q and q[0] < now() - self.WINDOW:
            q.popleft()
        return q

    def blocked(self, ip):
        with self.lock:
            return len(self._prune(ip)) >= self.MAX

    def fail(self, ip):
        with self.lock:
            self._prune(ip).append(now())


limiter = Limiter()


class AdminLimiter(Limiter):
    MAX = 5          # неверных паролей за 10 минут


admin_limiter = AdminLimiter()


def load_models():
    try:
        models = Store._read(MODELS_FILE, None)
        if not isinstance(models, list) or not models:
            Store._write(MODELS_FILE, DEFAULT_MODELS)
            return DEFAULT_MODELS

        # Add newly shipped models to an existing models.json without
        # removing any models or changing existing entries/settings.
        known_ids = {
            str(item.get("id", "")) for item in models
            if isinstance(item, dict)
        }
        changed = False
        for item in DEFAULT_MODELS:
            if item["id"] not in known_ids:
                models.append(dict(item))
                known_ids.add(item["id"])
                changed = True
        if changed:
            Store._write(MODELS_FILE, models)
        return models
    except Exception as exc:
        print(f"[database] Не удалось прочитать models.json: {type(exc).__name__}: {exc}")
        return DEFAULT_MODELS


def key_view(r, full=False):
    v = {k: r[k] for k in ("code", "type", "tokens_total", "tokens_used", "duration_days", "expires_at", "models", "limits", "note",
                           "created_at", "activated_at", "last_used_at", "requests")}
    v["status"] = status_of(r)
    v["frozen"] = bool(r["frozen"] or r["revoked"])
    if full:
        v["api_key"] = r["api_key"]
        v["log"] = r["log"][::-1]
    return v


def build_analytics(days=30):
    try:
        days = int(days)
    except (TypeError, ValueError):
        days = 30
    days = max(7, min(days, 120))
    t = now()
    keys = store.list()
    models = load_models()
    titles = {m["id"]: m.get("title") or m["id"] for m in models if isinstance(m, dict) and m.get("id")}
    day_of = lambda ts: time.strftime("%Y-%m-%d", time.localtime(ts))
    kt = dict(total=len(keys), token_keys=0, unlimited_keys=0, tokens_issued=0, tokens_used=0, tokens_left=0, requests=0,
              activated=0, active_24h=0, active_7d=0, never_used=0, funpay_orders=0, funpay_keys=0, manual_keys=0, bonuses=0)
    status = defaultdict(int)
    tl = {}
    seen_orders = set()
    allowed = defaultdict(int)
    for k in keys:
        status[status_of(k, True)] += 1
        unl = k["type"] == "unlimited"
        kt["unlimited_keys" if unl else "token_keys"] += 1
        kt["tokens_used"] += k["tokens_used"]
        kt["requests"] += k["requests"]
        if not unl:
            kt["tokens_issued"] += k["tokens_total"]
            kt["tokens_left"] += max(0, k["tokens_total"] - k["tokens_used"])
        if k["activated_at"]:
            kt["activated"] += 1
        if k["last_used_at"]:
            kt["active_24h"] += k["last_used_at"] >= t - 86400
            kt["active_7d"] += k["last_used_at"] >= t - 7 * 86400
        if not k["requests"]:
            kt["never_used"] += 1
        note = str(k.get("note") or "")
        if note.startswith("funpay:"):
            kt["funpay_keys"] += 1
            kt["bonuses"] += note.endswith("+bonus")
            tag = note.split()[0]
            if tag not in seen_orders:
                seen_orders.add(tag)
                kt["funpay_orders"] += 1
                if k["created_at"]:
                    tl.setdefault(day_of(k["created_at"]), {}).setdefault("orders", 0)
                    tl[day_of(k["created_at"])]["orders"] += 1
        else:
            kt["manual_keys"] += 1
        if k["created_at"]:
            b = tl.setdefault(day_of(k["created_at"]), {})
            b["keys"] = b.get("keys", 0) + 1
            b["tok_issued"] = b.get("tok_issued", 0) + (0 if unl else k["tokens_total"])
        if k["activated_at"]:
            b = tl.setdefault(day_of(k["activated_at"]), {})
            b["activated"] = b.get("activated", 0) + 1
        for m in titles:
            if k["models"] is None or m in k["models"]:
                allowed[m] += 1
    kt["activation_rate"] = round(kt["activated"] / kt["total"] * 100, 1) if kt["total"] else 0
    snap = stats.snapshot(days)
    timeline = []
    for row in snap["rows"]:
        b = tl.get(row["date"], {})
        timeline.append({**row, "keys": b.get("keys", 0), "orders": b.get("orders", 0), "tok_issued": b.get("tok_issued", 0), "activated": b.get("activated", 0)})
    in_period = {"keys": sum(r["keys"] for r in timeline), "orders": sum(r["orders"] for r in timeline),
                 "tok_issued": sum(r["tok_issued"] for r in timeline), "activated": sum(r["activated"] for r in timeline)}
    mrows = []
    for mid in list(titles) + [x for x in snap["models"] if x not in titles]:
        u = snap["models"].get(mid, {})
        mrows.append({"id": mid, "title": titles.get(mid, mid), "allowed_keys": allowed.get(mid, 0),
                      "req": u.get("req", 0), "tok": u.get("tok", 0), "fail": u.get("fail", 0)})
    prows, seen_p = [], set()
    try:
        overview = ai_engine.provider_overview()
    except Exception:
        overview = []
    for p in overview:
        u = snap["providers"].get(p["provider"], {})
        seen_p.add(p["provider"])
        prows.append({"provider": p["provider"], "title": p.get("title") or p["provider"], "keys": len(p["keys"]),
                      "cooling": sum(1 for x in p["keys"] if x.get("cooldown", 0) > 0), "req_today": p.get("requests_today", 0),
                      "tok_today": p.get("tokens_today", 0), "req": u.get("req", 0), "tok": u.get("tok", 0), "err": u.get("err", 0)})
    for name, u in snap["providers"].items():
        if name not in seen_p:
            prows.append({"provider": name, "title": name, "keys": 0, "cooling": 0, "req_today": 0, "tok_today": 0,
                          "req": u.get("req", 0), "tok": u.get("tok", 0), "err": u.get("err", 0)})
    top = sorted(keys, key=lambda k: k["tokens_used"], reverse=True)[:10]
    top_keys = [{"code": k["code"], "note": k.get("note", ""), "tokens_used": k["tokens_used"], "requests": k["requests"],
                 "status": status_of(k, True), "last_used_at": k["last_used_at"]} for k in top if k["tokens_used"] or k["requests"]]
    expiring = sorted(({"code": k["code"], "note": k.get("note", ""), "expires_at": k["expires_at"]} for k in keys
                       if k["type"] == "unlimited" and k["expires_at"] and t < k["expires_at"] <= t + 3 * 86400), key=lambda x: x["expires_at"])[:10]
    low = sorted(({"code": k["code"], "note": k.get("note", ""), "left": k["tokens_total"] - k["tokens_used"], "total": k["tokens_total"]}
                  for k in keys if k["type"] == "tokens" and k["tokens_total"] > 0 and 0 < k["tokens_total"] - k["tokens_used"] <= k["tokens_total"] * 0.1),
                 key=lambda x: x["left"])[:10]
    return {"ok": True, "now": t, "days": days, "keys": kt, "status": dict(status), "timeline": timeline, "period": in_period,
            "usage": {"sums": snap["sums"], "hours": snap["hours"], "blocked_by": snap["blocked_by"], "since": snap["since"]},
            "models": mrows, "providers": prows, "top_keys": top_keys, "expiring": expiring, "low_balance": low,
            "freeze": freeze_state()}


def mask(api_key):
    return api_key[:len(API_PREFIX)] + "*" * 16 + api_key[-4:]


# ------------------------------------------------------------------ HTTP


# ===================== Шифрованный канал (поверх HTTPS): ECDH P-256 + HKDF + AES-256-GCM =====================
import base64 as _b64
try:
    from cryptography.hazmat.primitives.asymmetric import ec as _ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
    from cryptography.hazmat.primitives.serialization import Encoding as _Enc, PublicFormat as _PF
    SECURE_OK = True
except Exception:  # библиотека не установлена — канал недоступен, приложение работает по обычному HTTPS
    SECURE_OK = False
_SEC = {}
_SEC_LOCK = threading.Lock()
SEC_TTL = 3600


def _b64e(b):
    return _b64.b64encode(b).decode()


def _b64d(s):
    return _b64.b64decode(str(s) + "=" * (-len(str(s)) % 4))


def secure_hello(client_pub_b64):
    now = time.time()
    cpub = _ec.EllipticCurvePublicKey.from_encoded_point(_ec.SECP256R1(), _b64d(client_pub_b64))
    priv = _ec.generate_private_key(_ec.SECP256R1())
    shared = priv.exchange(_ec.ECDH(), cpub)
    salt = os.urandom(16)
    km = _HKDF(algorithm=_hashes.SHA256(), length=64, salt=salt, info=b"white-secure-v1").derive(shared)
    sid = secrets.token_urlsafe(18)
    with _SEC_LOCK:
        for k in [k for k, v in _SEC.items() if v["exp"] < now]:
            _SEC.pop(k, None)
        if len(_SEC) > 5000:
            for k in sorted(_SEC, key=lambda x: _SEC[x]["exp"])[:1000]:
                _SEC.pop(k, None)
        _SEC[sid] = {"c2s": km[:32], "s2c": km[32:], "exp": now + SEC_TTL, "seen": {}}
    spub = priv.public_key().public_bytes(_Enc.X962, _PF.UncompressedPoint)
    return {"sid": sid, "pub": _b64e(spub), "salt": _b64e(salt), "ttl": SEC_TTL}


def secure_open(sid, iv_b64, ct_b64):
    """Расшифровать запрос. Возвращает (сессия, словарь) или (None, причина)."""
    now = time.time()
    with _SEC_LOCK:
        sess = _SEC.get(sid)
    if not sess or sess["exp"] < now:
        return None, "session"
    try:
        plain = _AESGCM(sess["c2s"]).decrypt(_b64d(iv_b64), _b64d(ct_b64), sid.encode())
        msg = json.loads(plain)
    except Exception:
        return None, "decrypt"
    ts, nonce = msg.get("ts"), str(msg.get("n", ""))
    if not isinstance(ts, (int, float)) or abs(now * 1000 - ts) > 120000 or not nonce or len(nonce) > 64:
        return None, "stale"
    with _SEC_LOCK:
        seen = sess["seen"]
        for k in [k for k, t in seen.items() if t < now - 300]:
            seen.pop(k, None)
        if nonce in seen:
            return None, "replay"
        seen[nonce] = now
    return sess, msg


def secure_seal(sess, sid, obj):
    iv = os.urandom(12)
    ct = _AESGCM(sess["s2c"]).encrypt(iv, json.dumps(obj, ensure_ascii=False).encode(), sid.encode() + b"|resp")
    return {"iv": _b64e(iv), "ct": _b64e(ct)}


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "WhiteAPI"
    sys_version = ""

    def log_message(self, *a):
        pass

    # --- утилиты
    def bearer_key(self):
        sec = getattr(self, "_sec_key", None)
        if sec:
            return sec
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth[7:].strip()
        return self.headers.get("x-api-key", "").strip()

    def anthropic_error(self, message, code=400):
        return self.send_json(code, {"type": "error", "error": {"type": "api_error", "message": str(message)}})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, x-api-key, anthropic-version, anthropic-beta")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def client_ip(self):
        if TRUST_PROXY and self.headers.get("X-Forwarded-For"):
            return self.headers["X-Forwarded-For"].split(",")[0].strip()
        return self.client_address[0]

    def is_https(self):
        return TRUST_PROXY and self.headers.get("X-Forwarded-Proto", "") == "https"

    def base_url(self):
        if PUBLIC_BASE_URL:
            return PUBLIC_BASE_URL if PUBLIC_BASE_URL.endswith("/v1") else PUBLIC_BASE_URL + "/v1"
        proto = "https" if self.is_https() else "http"
        return f"{proto}://{self.headers.get('Host', f'localhost:{PORT}')}/v1"

    def send_json(self, status, obj, extra=None):
        if isinstance(status, (dict, list)):  # ai_engine вызывает send_json(obj, code) — приводим к (code, obj)
            status, obj = obj, status
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def token(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return c[COOKIE].value if COOKIE in c else None

    def current(self):
        t = self.token()
        code = store.session_code(t) if t else None
        rec = store.find_code(code) if code else None
        return rec if rec and not rec["revoked"] else None

    def read_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        path = urlparse(getattr(self, "path", "/")).path
        if n > (2_000_000 if path.startswith("/v1/") else 10_000):
            return None
        try:
            data = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    # --- админка (всё под секретным адресом, для остальных — обычный 404)
    def admin_rel(self, path):
        base = "/" + admin.slug()
        if path.rstrip("/") == base:
            return ""
        return path[len(base):] if path.startswith(base + "/api/") else None

    def admin_cookie(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return c[ADMIN_COOKIE].value if ADMIN_COOKIE in c else None

    def admin_get(self, rel, query):
        if rel == "":
            try:
                data = (ROOT / "admin.html").read_bytes()
            except FileNotFoundError:
                return self.send_json(404, {"ok": False, "error": "not_found"})
            self.send_response(200)
            for k, v in (("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(data))), ("Cache-Control", "no-store"),
                         ("X-Robots-Tag", "noindex, nofollow"), ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"),
                         ("X-Content-Type-Options", "nosniff")):
                self.send_header(k, v)
            self.end_headers()
            return self.wfile.write(data)
        if not admin.valid(self.admin_cookie()):
            return self.send_json(401, {"ok": False, "error": "unauthorized"})
        if rel == "/api/keys":
            return self.send_json(200, {"ok": True, "now": now(), "models": load_models(), "freeze": freeze_state(),
                                        "keys": [key_view(k) for k in reversed(store.list())]})
        if rel == "/api/analytics":
            return self.send_json(200, build_analytics((query.get("days") or ["30"])[0]))
        if rel == "/api/settings":
            return self.send_json(200, {"ok": True, "freeze": freeze_state()})
        if rel == "/api/providers":
            return self.send_json(200, {"ok": True, "providers": ai_engine.provider_overview(), "errors": ai_engine.recent_errors()})
        if rel == "/api/key":
            rec = store.find_code((query.get("code") or [""])[0])
            return self.send_json(200, {"ok": True, "key": key_view(rec, True)}) if rec else self.send_json(404, {"ok": False, "error": "not_found"})
        self.send_json(404, {"ok": False, "error": "not_found"})

    def admin_post(self, rel, body):
        if rel == "/api/login":
            ip = self.client_ip()
            if admin_limiter.blocked(ip):
                return self.send_json(429, {"ok": False, "error": "rate_limited"})
            if not admin.verify(body.get("login", ""), body.get("password", "")):
                admin_limiter.fail(ip)
                time.sleep(0.6)
                return self.send_json(401, {"ok": False, "error": "bad_credentials"})
            cookie = f"{ADMIN_COOKIE}={admin.new_session()}; Path=/{admin.slug()}; HttpOnly; SameSite=Strict; Max-Age={ADMIN_TTL}"
            return self.send_json(200, {"ok": True}, {"Set-Cookie": cookie + ("; Secure" if self.is_https() else "")})
        if rel == "/api/providers/check":
            if not admin.valid(self.admin_cookie()):
                return self.send_json(401, {"ok": False, "error": "unauthorized"})
            only = str(body.get("provider") or "")[:20] or None
            tail = str(body.get("tail") or "")[:8] or None
            return self.send_json(200, {"ok": True, "results": ai_engine.provider_check(only, tail)})
        if rel == "/api/providers/key_toggle":
            if not admin.valid(self.admin_cookie()):
                return self.send_json(401, {"ok": False, "error": "unauthorized"})
            pname, kid = str(body.get("provider") or "")[:20], str(body.get("id") or "")[:16]
            if not ai_engine.key_exists(pname, kid):
                return self.send_json(404, {"ok": False, "error": "not_found"})
            ids = set(settings.get().get("disabled_keys") or [])
            ids.add(kid) if body.get("off") else ids.discard(kid)
            settings.update({"disabled_keys": sorted(ids)})
            ai_engine.set_disabled_keys(ids)
            print("[admin] ключ %s %s: %s" % (pname, "ВЫКЛЮЧЕН" if body.get("off") else "включён", kid))
            return self.send_json(200, {"ok": True})
        if rel == "/api/logout":
            t = self.admin_cookie()
            if t:
                admin.drop(t)
            return self.send_json(200, {"ok": True}, {"Set-Cookie": f"{ADMIN_COOKIE}=; Path=/{admin.slug()}; HttpOnly; SameSite=Strict; Max-Age=0"})
        if not admin.valid(self.admin_cookie()):
            return self.send_json(401, {"ok": False, "error": "unauthorized"})
        if rel == "/api/create":
            days = tokens = 0
            if body.get("type") == "unlimited":
                try:
                    days = int(body.get("days"))
                except (TypeError, ValueError):
                    days = 0
                if not 1 <= days <= 3650:
                    return self.send_json(400, {"ok": False, "error": "bad_days"})
            else:
                tokens = parse_tokens(str(body.get("tokens", "")))
                if not tokens:
                    return self.send_json(400, {"ok": False, "error": "bad_tokens"})
            try:
                count = int(body.get("count") or 1)
            except (TypeError, ValueError):
                count = 0
            if not 1 <= count <= 100:
                return self.send_json(400, {"ok": False, "error": "bad_count"})
            made = store.issue(tokens, count, days, clean_models(body.get("models")), clean_limits(body.get("limits")), str(body.get("note", ""))[:200])
            return self.send_json(200, {"ok": True, "codes": [k["code"] for k in made]})
        if rel == "/api/freeze_all":
            cur, upd = freeze_state(), {}
            if body.get("message") is not None:
                upd["freeze_message"] = str(body.get("message")).strip()[:500]
            if body.get("on") is not None:
                on = bool(body.get("on"))
                upd["freeze_all"] = on
                if on != cur["on"]:
                    upd["freeze_since"] = now() if on else None
            if upd:
                settings.update(upd)
                print("[admin] общая заморозка:", "ВКЛ" if freeze_on() else "выкл")
            return self.send_json(200, {"ok": True, "freeze": freeze_state()})
        if rel == "/api/action":
            rec, err = store.act(str(body.get("code", "")), str(body.get("action", "")), body)
            if err:
                return self.send_json(404 if err == "not_found" else 400, {"ok": False, "error": err})
            return self.send_json(200, {"ok": True, "key": key_view(rec, True)})
        self.send_json(404, {"ok": False, "error": "not_found"})

    # --- GET
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        rel = self.admin_rel(path)
        if rel is not None:
            return self.admin_get(rel, parse_qs(parsed.query))
        if path == "/v1/models":
            api_key = self.bearer_key()
            rec = store.find_api_key(api_key) if api_key else None
            if not rec:
                return ai_engine.api_error(self, 401)
            allowed = [m for m in load_models() if rec["models"] is None or m["id"] in rec["models"]]
            return self.send_json(200, {"object": "list", "data": [{"id": m["id"], "object": "model", "created": 0, "owned_by": "white-api"} for m in allowed]})
        if path in STATIC:
            name, ctype = STATIC[path]
            try:
                data = (ROOT / name).read_bytes()
            except FileNotFoundError:
                return self.send_json(404, {"ok": False, "error": "not_found"})

            # Установочные скрипты: подставляем адрес этого сайта и убираем BOM (нужно для irm | iex)
            if name in ("install.sh", "white-api-installer.ps1"):
                data = data.lstrip(b"\xef\xbb\xbf").replace(b"__WHITE_BASE__", self.base_url().encode())
                data = data.replace(b"\r\n", b"\n") if name == "install.sh" else data

            # Поддержка HTTP Range нужна HTML5-плееру для загрузки и перемотки видео.
            range_header = self.headers.get("Range", "") if name == "white-api-tutorial.mp4" else ""
            status = 200
            start, end = 0, len(data) - 1
            if range_header:
                match = re.fullmatch(r"bytes=(\d*)-(\d*)", range_header.strip())
                if not match or (not match.group(1) and not match.group(2)):
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{len(data)}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if match.group(1):
                    start = int(match.group(1))
                    end = int(match.group(2)) if match.group(2) else len(data) - 1
                else:
                    suffix = int(match.group(2))
                    start = max(0, len(data) - suffix)
                    end = len(data) - 1
                if start >= len(data) or start > end:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{len(data)}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                end = min(end, len(data) - 1)
                status = 206

            payload = data[start:end + 1]
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            if name == "white-api-tutorial.mp4":
                self.send_header("Accept-Ranges", "bytes")
                if status == 206:
                    self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
            self.end_headers()
            self.wfile.write(payload)
        elif path == "/api/config":
            self.send_json(200, {"ok": True, "base_url": self.base_url(), "models": load_models()})
        elif path == "/api/me":
            rec = self.current()
            if not rec:
                return self.send_json(401, {"ok": False, "error": "unauthorized"})
            unl = rec["type"] == "unlimited"
            balance = 0 if unl else max(0, rec["tokens_total"] - rec["tokens_used"])
            models = [m for m in load_models() if rec["models"] is None or m["id"] in rec["models"]]
            self.send_json(200, {
                "ok": True,
                "type": rec["type"],
                "balance": balance,
                "tokens_total": rec["tokens_total"],
                "tokens_used": rec["tokens_used"],
                "status": status_of(rec),
                "expires_at": rec["expires_at"],
                "models": models,
                "api_key_masked": mask(rec["api_key"]),
                "base_url": self.base_url(),
                "created_at": rec["created_at"],
                "activated_at": rec["activated_at"],
                "freeze": freeze_public(),
            })
        elif path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
        else:
            self.send_json(404, {"ok": False, "error": "not_found"})

    def _responses_request(self, body, raw):
        """Minimal OpenAI Responses API adapter over the chat-completions engine."""
        original_model = str(body.get("model") or "gpt-sol-5-6")
        instructions = body.get("instructions")
        messages = []
        if instructions:
            messages.append({"role": "system", "content": str(instructions)})
        inp = body.get("input", "")
        if isinstance(inp, str):
            messages.append({"role": "user", "content": inp})
        elif isinstance(inp, list):
            for item in inp:
                if not isinstance(item, dict):
                    continue
                role = item.get("role", "user")
                content = item.get("content", "")
                if isinstance(content, list):
                    bits = []
                    for part in content:
                        if isinstance(part, dict):
                            if part.get("type") in ("input_text", "text", "output_text"):
                                bits.append(str(part.get("text", "")))
                    content = "\n".join(bits)
                if isinstance(content, str):
                    messages.append({"role": role if role in ("system", "developer", "user", "assistant") else "user", "content": content})
        chat = {"model": original_model, "messages": messages, "stream": False}
        if body.get("max_output_tokens"):
            chat["max_tokens"] = body["max_output_tokens"]
        if body.get("temperature") is not None:
            chat["temperature"] = body["temperature"]
        # Capture the existing engine response so it can be wrapped in Responses shape.
        old_wfile = self.wfile
        old_send_response, old_send_header, old_end_headers = self.send_response, self.send_header, self.end_headers
        capture = io.BytesIO()
        headers = []
        status = [200]
        self.wfile = capture
        self.send_response = lambda code=200, message=None: status.__setitem__(0, int(code))
        self.send_header = lambda name, value: headers.append((name, str(value)))
        self.end_headers = lambda: None
        try:
            ai_engine.proxy_chat(self, chat, json.dumps(chat).encode("utf-8"), fmt="openai")
            payload = capture.getvalue()
        finally:
            self.wfile = old_wfile
            self.send_response, self.send_header, self.end_headers = old_send_response, old_send_header, old_end_headers
        try:
            data = json.loads(payload)
        except Exception:
            return ai_engine.api_error(self, 502)
        if status[0] != 200:
            return self.send_json(status[0], data)
        choice = (data.get("choices") or [{}])[0]
        msg = choice.get("message") or {}
        text_out = msg.get("content") or ""
        usage = data.get("usage") or {}
        rid = "resp_" + uuid.uuid4().hex
        response = {"id": rid, "object": "response", "created_at": int(_time.time()), "status": "completed", "error": None, "incomplete_details": None, "model": original_model, "output": [{"id": "msg_" + uuid.uuid4().hex, "type": "message", "status": "completed", "role": "assistant", "content": [{"type": "output_text", "text": text_out, "annotations": []}]}], "output_text": text_out, "usage": {"input_tokens": usage.get("prompt_tokens", 0), "output_tokens": usage.get("completion_tokens", 0), "total_tokens": usage.get("total_tokens", 0)}}
        if body.get("stream"):
            events = [
                ("response.created", {"type":"response.created", "response": {**response, "status":"in_progress", "output":[]}}),
                ("response.output_item.added", {"type":"response.output_item.added", "output_index":0, "item":{"id":response["output"][0]["id"],"type":"message","status":"in_progress","role":"assistant","content":[]}}),
                ("response.content_part.added", {"type":"response.content_part.added","item_id":response["output"][0]["id"],"output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}}),
                ("response.output_text.delta", {"type":"response.output_text.delta","item_id":response["output"][0]["id"],"output_index":0,"content_index":0,"delta":text_out}),
                ("response.output_text.done", {"type":"response.output_text.done","item_id":response["output"][0]["id"],"output_index":0,"content_index":0,"text":text_out}),
                ("response.content_part.done", {"type":"response.content_part.done","item_id":response["output"][0]["id"],"output_index":0,"content_index":0,"part":response["output"][0]["content"][0]}),
                ("response.output_item.done", {"type":"response.output_item.done","output_index":0,"item":response["output"][0]}),
                ("response.completed", {"type":"response.completed","response":response}),
            ]
            chunks = b"".join(("event: %s\ndata: %s\n\n" % (ev, json.dumps(obj, ensure_ascii=False))).encode("utf-8") for ev,obj in events) + b"data: [DONE]\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(chunks)))
            self.end_headers()
            self.wfile.write(chunks)
            return
        return self.send_json(200, response)

    # --- POST
    def _secure_chat(self, body):
        if not SECURE_OK:
            return self.send_json(501, {"error": {"message": "secure channel unavailable"}})
        sid = str(body.get("sid", ""))[:64]
        sess, msg = secure_open(sid, body.get("iv"), body.get("ct"))
        if sess is None:
            return self.send_json(410 if msg == "session" else 400, {"error": {"message": "secure:" + str(msg)}})
        if msg.get("op") == "models":
            api_key = str(msg.get("key", "")).strip()
            rec = store.find_api_key(api_key) if api_key else None
            if not rec:
                return self.send_json(200, secure_seal(sess, sid, {"status": 401, "data": {"error": {"message": "Invalid API key"}}}))
            allowed = [m["id"] for m in load_models() if rec["models"] is None or m["id"] in rec["models"]]
            return self.send_json(200, secure_seal(sess, sid, {"status": 200, "data": {"models": allowed}}))
        req = msg.get("body")
        if not isinstance(req, dict):
            return self.send_json(400, {"error": {"message": "secure:body"}})
        req["stream"] = False
        req.pop("stream_options", None)
        self._sec_key = str(msg.get("key", "")).strip()
        old_wfile = self.wfile
        old_sr, old_sh, old_eh = self.send_response, self.send_header, self.end_headers
        capture, status = io.BytesIO(), [200]
        self.wfile = capture
        self.send_response = lambda code=200, message=None: status.__setitem__(0, int(code))
        self.send_header = lambda name, value: None
        self.end_headers = lambda: None
        try:
            ai_engine.proxy_chat(self, req, json.dumps(req).encode("utf-8"), fmt="openai")
            payload = capture.getvalue()
        finally:
            self.wfile = old_wfile
            self.send_response, self.send_header, self.end_headers = old_sr, old_sh, old_eh
            self._sec_key = None
        try:
            data = json.loads(payload)
        except Exception:
            status[0], data = 502, ai_engine.error_body(502)
        return self.send_json(200, secure_seal(sess, sid, {"status": status[0], "data": data}))

    def do_POST(self):
        path = urlparse(self.path).path
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0)) if path.startswith("/v1/") else None
        if path.startswith("/v1/"):
            try:
                body = json.loads(raw or b"{}")
                if not isinstance(body, dict): raise ValueError("body must be an object")
            except Exception:
                return ai_engine.api_error(self, 400, "invalid JSON")
            if path == "/v1/secure/hello":
                if not SECURE_OK:
                    return self.send_json(501, {"error": {"message": "secure channel unavailable"}})
                try:
                    return self.send_json(200, secure_hello(body.get("pub", "")))
                except Exception:
                    return self.send_json(400, {"error": {"message": "bad handshake"}})
            if path == "/v1/secure/chat":
                return self._secure_chat(body)
            try:
                if path == "/v1/messages":
                    return ai_engine.proxy_messages(self, body, raw)
                if path == "/v1/chat/completions":
                    return ai_engine.proxy_chat(self, body, raw, fmt="openai")
                if path == "/v1/responses":
                    return self._responses_request(body, raw)
            except (BrokenPipeError, ConnectionResetError):
                return
            except Exception as exc:
                print("[v1] необработанная ошибка: %s" % type(exc).__name__)
                try:
                    return ai_engine.api_error(self, 500, fmt="anthropic" if path == "/v1/messages" else "openai")
                except Exception:
                    return
            return ai_engine.api_error(self, 404)
        body = self.read_json()
        if body is None:
            return self.send_json(400, {"ok": False, "error": "bad_request"})
        rel = self.admin_rel(path)
        if rel is not None:
            return self.admin_post(rel, body)

        if path == "/api/funpay/manage":
            secret = os.environ.get("WHITE_FUNPAY_SECRET") or "77880034848f0bc22caefcf66e3d8ade"
            given = self.headers.get("X-Funpay-Secret", "")
            if not secret or not secrets.compare_digest(given.encode(), secret.encode()):
                time.sleep(0.6)
                return self.send_json(403, {"ok": False, "error": "forbidden"})
            code = str(body.get("code", "")).strip()
            action = str(body.get("action", "")).strip().lower()
            rec = store.find_code(code) if code else None
            if not rec:
                return self.send_json(404, {"ok": False, "error": "key_not_found"})
            if action == "topup":
                amount = parse_tokens(str(body.get("amount", "")))
                if not amount:
                    return self.send_json(400, {"ok": False, "error": "bad_amount"})
                if rec.get("type") != "tokens":
                    return self.send_json(400, {"ok": False, "error": "not_token_key"})
                store.topup(code, amount)
                return self.send_json(200, {"ok": True, "code": code, "added": amount})
            if action == "freeze":
                store.act(code, "freeze", {})
                return self.send_json(200, {"ok": True, "code": code})
            if action == "delete":
                return self.send_json(200, {"ok": store.delete_code(code), "code": code})
            return self.send_json(400, {"ok": False, "error": "bad_action"})
        if path == "/api/funpay/bonus":
            secret = os.environ.get("WHITE_FUNPAY_SECRET") or "77880034848f0bc22caefcf66e3d8ade"
            given = self.headers.get("X-Funpay-Secret", "")
            if not secret or not secrets.compare_digest(given.encode(), secret.encode()):
                time.sleep(0.6)
                return self.send_json(403, {"ok": False, "error": "forbidden"})
            order_id = re.sub(r"[^A-Za-z0-9_-]", "", str(body.get("order_id", "")))[:40]
            try:
                tokens = int(body.get("tokens"))
            except (TypeError, ValueError):
                tokens = 0
            if not order_id or not 0 < tokens <= 100_000_000:
                return self.send_json(400, {"ok": False, "error": "bad_request"})
            tag = "funpay:" + order_id
            with store.lock:
                rec = next((k for k in store._keys() if k.get("note") in (tag, tag + " +bonus")), None)
            if not rec or rec["type"] != "tokens":
                return self.send_json(404, {"ok": False, "error": "key_not_found"})
            if rec.get("note", "").endswith("+bonus"):
                return self.send_json(200, {"ok": True, "code": rec["code"], "repeat": True})
            def add_bonus(r):
                r["tokens_total"] += tokens
                r["note"] = tag + " +bonus"
                store.log(r, "topup", "+%s токенов (бонус за отзыв)" % fmt(tokens))
            store._update(rec["code"], add_bonus)
            return self.send_json(200, {"ok": True, "code": rec["code"], "repeat": False})
        if path == "/api/funpay/issue":
            # Выдача ключей для плагина FunPay Cardinal. Защита: заголовок X-Funpay-Secret == env WHITE_FUNPAY_SECRET.
            secret = os.environ.get("WHITE_FUNPAY_SECRET") or "77880034848f0bc22caefcf66e3d8ade"
            given = self.headers.get("X-Funpay-Secret", "")
            if not secret or not secrets.compare_digest(given.encode(), secret.encode()):
                time.sleep(0.6)
                return self.send_json(403, {"ok": False, "error": "forbidden"})
            order_id = re.sub(r"[^A-Za-z0-9_-]", "", str(body.get("order_id", "")))[:40]
            if not order_id:
                return self.send_json(400, {"ok": False, "error": "no_order_id"})
            tag = "funpay:" + order_id
            with store.lock:
                old = [k for k in store._keys() if k.get("note") == tag]
            if old:  # повторный запрос по тому же заказу — отдаём уже выданные ключи
                return self.send_json(200, {"ok": True, "codes": [k["code"] for k in old], "repeat": True})
            days = tokens = 0
            if body.get("type") == "unlimited":
                try:
                    days = int(body.get("days"))
                except (TypeError, ValueError):
                    days = 0
                if not 1 <= days <= 3650:
                    return self.send_json(400, {"ok": False, "error": "bad_days"})
            else:
                try:
                    tokens = int(body.get("tokens"))
                except (TypeError, ValueError):
                    tokens = 0
                if not 0 < tokens <= 10**12:
                    return self.send_json(400, {"ok": False, "error": "bad_tokens"})
            try:
                count = int(body.get("count") or 1)
            except (TypeError, ValueError):
                count = 0
            if not 1 <= count <= 100:
                return self.send_json(400, {"ok": False, "error": "bad_count"})
            made = store.issue(tokens, count, days, clean_models(body.get("models")), clean_limits(body.get("limits")),
                               tag)
            return self.send_json(200, {"ok": True, "codes": [k["code"] for k in made], "repeat": False})
        if path == "/api/activate":
            ip = self.client_ip()
            if limiter.blocked(ip):
                return self.send_json(429, {"ok": False, "error": "rate_limited"})
            code = str(body.get("code", "")).strip().upper()
            rec = store.find_code(code) if CODE_RE.match(code) else None
            if not rec:
                limiter.fail(ip)
                stats.record("login_fail")
                return self.send_json(404, {"ok": False, "error": "not_found"})
            if rec["revoked"]:
                return self.send_json(403, {"ok": False, "error": "revoked"})
            store.mark_activated(code)
            token = store.create_session(code)
            cookie = f"{COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"
            if self.is_https():
                cookie += "; Secure"
            stats.record("login")
            return self.send_json(200, {"ok": True, "redirect": "cabinet.html", "freeze": freeze_public()}, {"Set-Cookie": cookie})

        if path == "/api/reveal":
            rec = self.current()
            if not rec:
                return self.send_json(401, {"ok": False, "error": "unauthorized"})
            return self.send_json(200, {"ok": True, "api_key": rec["api_key"]})

        if path == "/api/logout":
            t = self.token()
            if t:
                store.drop_session(t)
            expired = f"{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
            return self.send_json(200, {"ok": True}, {"Set-Cookie": expired})

        self.send_json(404, {"ok": False, "error": "not_found"})


# ------------------------------------------------------------------ консоль
HELP = """Команды:
  gen <токены> [кол-во]   выдать код доступа, напр.:  gen 500k   или   gen 1m 5
  list                    список кодов и остатков
  topup <код> <токены>    добавить токены к коду
  revoke <код>            заблокировать код
  restore <код>           разблокировать код
  help                    эта справка
  exit                    остановить сервер"""


def parse_tokens(s):
    s = str(s).lower().strip().replace("_", "").replace(",", ".").replace(" ", "")
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(кк|kk|млн|миллион(?:а|ов)?|млрд|миллиард(?:а|ов)?|к|k|м|m|b)?", s)
    if not m:
        return None
    suffix = m.group(2) or ""
    multiplier = 1_000_000_000 if suffix in ("млрд", "миллиард", "миллиарда", "миллиардов", "b") else 1_000_000 if suffix in ("кк", "kk", "млн", "миллион", "миллиона", "миллионов", "м", "m") else 1_000 if suffix in ("к", "k") else 1
    n = int(float(m.group(1)) * multiplier)
    return n if 0 < n <= 10**12 else None


def run_command(line):
    """Возвращает False, если нужно выйти."""
    parts = line.strip().split()
    if not parts:
        return True
    cmd, args = parts[0].lower(), parts[1:]

    if cmd in ("exit", "quit", "q"):
        return False

    if cmd in ("help", "?"):
        print(HELP)

    elif cmd == "gen":
        a0 = args[0].lower() if args else ""
        days = int(a0[:-1]) if re.fullmatch(r"\d{1,4}d", a0) else 0
        tokens = 0 if days else (parse_tokens(a0) if args else None)
        count = int(args[1]) if len(args) > 1 and args[1].isdigit() else 1
        if not (tokens or days) or not 1 <= count <= 100:
            print("Использование: gen <токены> [кол-во]   например: gen 500k   или   gen 30d 5  (безлимит на 30 дней)")
            return True
        for rec in store.issue(tokens, count, days=days):
            print(f"\n  Код доступа : {rec['code']}")
            print(f"  Тариф       : безлимит {days} дн." if days else f"  Токенов     : {fmt(rec['tokens_total'])}")
        print("\nОтправь код покупателю — он вводит его на сайте и попадает в кабинет.")

    elif cmd == "list":
        keys = store.list()
        if not keys:
            print("Ключей пока нет. Выдай первый: gen 500k")
        for k in keys:
            left = max(0, k["tokens_total"] - k["tokens_used"])
            state = {"active": "активен", "pending": "не активирован", "frozen": "ЗАМОРОЖЕН", "expired": "срок вышел", "depleted": "токены кончились"}[status_of(k)]
            if k["type"] == "unlimited":
                print(f"{k['code']}  безлимит {k['duration_days']} дн.  {state:<16} выдан {fmt_date(k['created_at'])}")
                continue
            print(f"{k['code']}  осталось {fmt(left):>12} / {fmt(k['tokens_total']):<12}  {state:<14} выдан {fmt_date(k['created_at'])}")

    elif cmd == "admin":
        print(f"Админка: http://localhost:{PORT}/{admin.slug()}   (логин: {admin.data()['login']})")

    elif cmd == "adminpass" and args:
        admin.set_credentials(password=args[0]); print("Пароль админки изменён, все сессии сброшены.")

    elif cmd == "adminlogin" and args:
        admin.set_credentials(login=args[0]); print("Логин админки изменён.")

    elif cmd == "topup":
        n = parse_tokens(args[1]) if len(args) > 1 else None
        rec = store.topup(args[0].upper(), n) if args and n else None
        print(f"Готово. Теперь всего {fmt(rec['tokens_total'])} токенов." if rec else "Использование: topup <код> <токены>  (код должен существовать)")

    elif cmd in ("revoke", "restore"):
        rec = store.set_revoked(args[0].upper(), cmd == "revoke") if args else None
        print(("Заблокирован: " if cmd == "revoke" else "Разблокирован: ") + rec["code"] if rec else f"Использование: {cmd} <код>")

    else:
        print("Неизвестная команда. Введи help")
    return True


def serve():
    load_models()
    try:
        httpd = http.server.ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as e:
        sys.exit(f"Не удалось занять порт {PORT}: {e}\nЗадай другой: set PORT=8081 (Windows) / PORT=8081 python server.py")
    httpd.daemon_threads = True

    shown = "localhost" if HOST in ("127.0.0.1", "0.0.0.0") else HOST
    print(f"\n  White API запущен: http://{shown}:{PORT}")
    if HOST == "127.0.0.1":
        print("  (слушает только этот компьютер; для доступа снаружи: WHITE_HOST=0.0.0.0)")
    print("  Хранилище: PostgreSQL (DATABASE_URL)" if DATABASE_URL else "  Хранилище: локальные JSON-файлы (на Render временные)")
    print(f"  Админка: http://{shown}:{PORT}/{admin.slug()}   (логин: {admin.data()['login']})")
    if admin.fresh_password:
        print(f"  Пароль админки (показан один раз): {admin.fresh_password}\n  Сменить: adminpass <новый пароль>")
    print()

    if sys.stdin and sys.stdin.isatty():
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        print(HELP + "\n")
        while True:
            try:
                if not run_command(input("white> ")):
                    break
            except (EOFError, KeyboardInterrupt):
                break
        httpd.shutdown()
        print("Сервер остановлен.")
    else:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


def main():
    if len(sys.argv) == 1 or sys.argv[1] in ("serve", "start"):
        serve()
    else:
        run_command(" ".join(sys.argv[1:]))


if __name__ == "__main__":
    main()
