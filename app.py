#!/usr/bin/env python3
# HEIN License Control Deck + file delivery server.
# Stdlib-only WSGI app: runs under wsgiref (local/VPS) or PythonAnywhere (point WSGI file at `application`).
import hashlib
import json
import os
import secrets
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.environ.get("HEIN_DATA_FILE", os.path.join(BASE, "data.json"))
FILES_DIR = os.path.join(BASE, "files")
PANEL_FILE = os.path.join(BASE, "panel.html")
GAME_KEY = os.environ.get("HEIN_GAME_KEY", "")
ONLINE_WINDOW = 120  # seconds

_lock = threading.Lock()

FILE_CATALOG = [
    # hein's order 2026-11-17: NO Lion ZG files. Only files we create ourselves
    # get catalog entries here (id / feature / stored filename / display name / target path).
    {
        "id": "hein_quality_config",
        "feature": "QUALITY CONFIG (own file)",
        "stored": "hein_quality_usercustom.ini",
        "name": "UserCustom.ini",
        "target": "files/UE4Game/ShadowTrackerExtra/ShadowTrackerExtra/Saved/Config/Android/UserCustom.ini",
    },
]

MARKERS = [
    # emptied together with the ZG set removal — own-file sets will declare their own markers
]
MARKER_TEXT = "0.17.0.11800\n"

FEATURES = [
    {"name": "HEIN AIM ASSIST", "available": True},
    {"name": "QUALITY CONFIG (own file)", "available": True},
    {"name": "MAP (own file)", "available": False},
]


def _default_data():
    return {
        "admin_password": os.environ.get("HEIN_ADMIN_PASSWORD", "hein-admin-2026"),
        "keys": [],          # {key, created, expires, max_devices, devices:[{id,name,last_seen}]}
        "sessions": {},      # token -> {key, device_id, last_seen}
        "admin_sessions": {},  # token -> expires
    }


def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                d = json.load(f)
            for k, v in _default_data().items():
                d.setdefault(k, v)
            return d
        except Exception:
            pass
    return _default_data()


def save_data(d):
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f)
    os.replace(tmp, DATA_FILE)


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest():
    out = []
    for e in FILE_CATALOG:
        p = os.path.join(FILES_DIR, e["stored"])
        if os.path.exists(p):
            out.append({
                "id": e["id"], "feature": e["feature"], "name": e["name"],
                "target": e["target"], "size": os.path.getsize(p),
                "sha256": sha256_of(p),
            })
    return out


def json_response(start_response, code, obj):
    body = json.dumps(obj).encode("utf-8")
    start_response(f"{code} {'OK' if code<400 else 'Error'}", [
        ("Content-Type", "application/json"),
        ("Content-Length", str(len(body))),
    ])
    return [body]


def read_json(environ):
    try:
        n = int(environ.get("CONTENT_LENGTH") or 0)
    except Exception:
        n = 0
    raw = environ["wsgi.input"].read(n) if n > 0 else b""
    try:
        return json.loads(raw.decode("utf-8")) if raw else {}
    except Exception:
        return {}


def bearer(environ):
    h = environ.get("HTTP_AUTHORIZATION", "")
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    return ""


def check_admin(environ, d):
    tok = bearer(environ)
    exp = d["admin_sessions"].get(tok)
    return bool(exp and exp > time.time())


def get_session(environ, d, body=None):
    tok = environ.get("HTTP_X_SESSION", "")
    if not tok and body:
        tok = body.get("session", "")
    if not tok:
        # allow ?session= for downloads
        from urllib.parse import parse_qs
        qs = parse_qs(environ.get("QUERY_STRING", ""))
        tok = (qs.get("session") or [""])[0]
    s = d["sessions"].get(tok)
    return tok, s


def session_valid(d, s):
    if not s:
        return False, "NO_SESSION"
    for k in d["keys"]:
        if k["key"] == s["key"]:
            if k["expires"] <= time.time():
                return False, "KEY_EXPIRED"
            return True, k
    return False, "KEY_NOT_FOUND"


def application(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET")
    path = environ.get("PATH_INFO", "/")
    now = time.time()

    if path in ("/", "/admin") and method == "GET":
        with open(PANEL_FILE, "rb") as f:
            body = f.read()
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8"),
                                  ("Content-Length", str(len(body)))])
        return [body]

    if path == "/api/health" and method == "GET":
        return json_response(start_response, 200, {"ok": True, "time": int(now)})

    with _lock:
        d = load_data()

        # ---------- admin ----------
        if path == "/api/admin/login" and method == "POST":
            body = read_json(environ)
            if body.get("password") == d["admin_password"]:
                tok = secrets.token_hex(24)
                d["admin_sessions"][tok] = now + 12 * 3600
                save_data(d)
                return json_response(start_response, 200, {"ok": True, "token": tok})
            return json_response(start_response, 401, {"ok": False, "error": "WRONG_PASSWORD"})

        if path.startswith("/api/admin/"):
            if not check_admin(environ, d):
                return json_response(start_response, 401, {"ok": False, "error": "ADMIN_AUTH_REQUIRED"})

            if path == "/api/admin/stats" and method == "GET":
                online = sum(1 for s in d["sessions"].values() if now - s["last_seen"] < ONLINE_WINDOW)
                devices = set()
                for k in d["keys"]:
                    for dev in k["devices"]:
                        devices.add(dev["id"])
                return json_response(start_response, 200, {
                    "ok": True, "total_keys": len(d["keys"]),
                    "online": online, "devices": len(devices)})

            if path == "/api/admin/keys" and method == "GET":
                out = []
                for k in d["keys"]:
                    out.append({
                        "key": k["key"], "created": k["created"], "expires": k["expires"],
                        "expired": k["expires"] <= now, "max_devices": k["max_devices"],
                        "devices": k["devices"],
                        "online": sum(1 for s in d["sessions"].values()
                                      if s["key"] == k["key"] and now - s["last_seen"] < ONLINE_WINDOW),
                    })
                return json_response(start_response, 200, {"ok": True, "keys": out})

            if path == "/api/admin/keys" and method == "POST":
                body = read_json(environ)
                key_text = (body.get("key") or "").strip()
                if not key_text:
                    key_text = "HEIN-" + secrets.token_hex(3).upper()
                amount = float(body.get("amount") or 30)
                unit = (body.get("unit") or "days").lower()
                mult = {"minutes": 60, "hours": 3600, "days": 86400}.get(unit, 86400)
                max_dev = int(body.get("max_devices") or 1)
                if any(k["key"] == key_text for k in d["keys"]):
                    return json_response(start_response, 409, {"ok": False, "error": "KEY_EXISTS"})
                rec = {"key": key_text, "created": int(now),
                       "expires": int(now + amount * mult),
                       "max_devices": max_dev, "devices": []}
                d["keys"].append(rec)
                save_data(d)
                return json_response(start_response, 200, {"ok": True, "record": rec})

            if path == "/api/admin/keys/delete" and method == "POST":
                body = read_json(environ)
                kt = body.get("key")
                d["keys"] = [k for k in d["keys"] if k["key"] != kt]
                d["sessions"] = {t: s for t, s in d["sessions"].items() if s["key"] != kt}
                save_data(d)
                return json_response(start_response, 200, {"ok": True})

            return json_response(start_response, 404, {"ok": False, "error": "NOT_FOUND"})

        # ---------- client ----------
        if path == "/api/login" and method == "POST":
            body = read_json(environ)
            key_text = (body.get("key") or "").strip()
            device_id = (body.get("device_id") or "").strip()
            device_name = (body.get("device_name") or "").strip()
            if not key_text or not device_id:
                return json_response(start_response, 400, {"ok": False, "error": "KEY_AND_DEVICE_REQUIRED"})
            rec = next((k for k in d["keys"] if k["key"] == key_text), None)
            if rec is None:
                return json_response(start_response, 401, {"ok": False, "error": "KEY_NOT_FOUND"})
            if rec["expires"] <= now:
                return json_response(start_response, 403, {"ok": False, "error": "KEY_EXPIRED"})
            dev = next((x for x in rec["devices"] if x["id"] == device_id), None)
            if dev is None:
                if len(rec["devices"]) >= rec["max_devices"]:
                    return json_response(start_response, 403, {"ok": False, "error": "DEVICE_LIMIT"})
                dev = {"id": device_id, "name": device_name, "last_seen": int(now)}
                rec["devices"].append(dev)
            else:
                dev["last_seen"] = int(now)
                if device_name:
                    dev["name"] = device_name
            tok = secrets.token_hex(24)
            d["sessions"][tok] = {"key": key_text, "device_id": device_id, "last_seen": int(now)}
            save_data(d)
            return json_response(start_response, 200, {
                "ok": True, "session": tok, "expires": rec["expires"],
                "game_key": GAME_KEY, "features": FEATURES})

        if path == "/api/heartbeat" and method == "POST":
            body = read_json(environ)
            tok, s = get_session(environ, d, body)
            ok, info = session_valid(d, s)
            if not ok:
                return json_response(start_response, 403, {"ok": False, "error": info})
            s["last_seen"] = int(now)
            for dev in info["devices"]:
                if dev["id"] == s["device_id"]:
                    dev["last_seen"] = int(now)
            save_data(d)
            return json_response(start_response, 200, {"ok": True, "expires": info["expires"]})

        if path == "/api/files" and method == "GET":
            tok, s = get_session(environ, d)
            ok, info = session_valid(d, s)
            if not ok:
                return json_response(start_response, 403, {"ok": False, "error": info})
            return json_response(start_response, 200, {
                "ok": True, "features": FEATURES, "files": manifest(),
                "markers": [{"target": t, "text": MARKER_TEXT} for t in MARKERS],
                "game_key": GAME_KEY, "expires": info["expires"]})

        if path.startswith("/api/download/") and method == "GET":
            tok, s = get_session(environ, d)
            ok, info = session_valid(d, s)
            if not ok:
                return json_response(start_response, 403, {"ok": False, "error": info})
            fid = path.rsplit("/", 1)[-1]
            entry = next((e for e in FILE_CATALOG if e["id"] == fid), None)
            if entry is None:
                return json_response(start_response, 404, {"ok": False, "error": "FILE_NOT_FOUND"})
            p = os.path.join(FILES_DIR, entry["stored"])
            with open(p, "rb") as f:
                body = f.read()
            start_response("200 OK", [("Content-Type", "application/octet-stream"),
                                      ("Content-Length", str(len(body)))])
            return [body]

    return json_response(start_response, 404, {"ok": False, "error": "NOT_FOUND"})


if __name__ == "__main__":
    from wsgiref.simple_server import make_server
    port = int(os.environ.get("PORT", "8791"))
    print(f"HEIN License Deck on http://0.0.0.0:{port}  (admin panel at /admin)")
    make_server("0.0.0.0", port, application).serve_forever()
