# server.py — Curator Finder local API (Spotify) with serial activation
#
# Endpoints:
#   GET  /, /dashboard.html -> serve dashboard.html (same origin)
#   GET  /health            -> server + spotify + license status (+ save_dir)
#   GET  /device-id         -> stable per-machine fingerprint (hashed)
#   GET  /config            -> minimal UX hints (no secrets)
#   POST /setup             -> save spotify keys (+ legacy text license) to ~/.curator-finder/config.json
#   POST /activate          -> accept signed JSON token -> saves ~/.curator-finder/license.json
#   POST /activate-serial   -> accept short serial string -> saves ~/.curator-finder/license.json
#   POST /search            -> run discovery/scrape (gated when LICENSE_MODE=enforced), streams NDJSON progress
#   GET  /license/status    -> compact, user-friendly license summary
#   GET  /license/debug     -> detailed status (only when CF_DEBUG=1)
#
# Licensing:
# - User-facing: "serial" string (looks like CF1-XXXXX-...).
# - Internally: Ed25519-signed payload (offline, machine-bound).
# - Flip on enforcement with:  export LICENSE_MODE=enforced
# - Provide Ed25519 public key via env CURATORFINDER_PUBKEY_B64 (recommended),
#   or paste into PUBLIC_KEY_B64 below.

import os
import re
import sys
import json
import csv
import time
import pathlib
import concurrent.futures
from typing import List, Dict, Any, Optional, Iterable, Tuple, Callable

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv

import traceback
import requests
from bs4 import BeautifulSoup
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
from starlette.responses import StreamingResponse
import threading
import queue

# --- TLS certs for bundled apps (requests/spotipy)
try:
    import certifi, os as _os
    _os.environ.setdefault("SSL_CERT_FILE", certifi.where())
    _os.environ.setdefault("REQUESTS_CA_BUNDLE", certifi.where())
except Exception:
    pass

# -------------------- Load .env (optional) --------------------
load_dotenv()

# -------------------- App / CORS --------------------
app = FastAPI(title="Curator Finder API", version=os.getenv("CURATORFINDER_VERSION", "dev"))

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # dev-friendly; lock down later if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------- Paths (PyInstaller-aware) --------------------
if getattr(sys, "frozen", False):
    HERE = pathlib.Path(sys._MEIPASS)  # PyInstaller temp dir
else:
    HERE = pathlib.Path(__file__).resolve().parent

# Serve static files (place assets next to dashboard.html)
app.mount("/static", StaticFiles(directory=str(HERE), html=False), name="static")

@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard.html", response_class=HTMLResponse)
def dashboard():
    path = HERE / "dashboard.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="dashboard.html missing")
    return HTMLResponse(path.read_text("utf-8"))

# -------------------- Config (self-contained) --------------------
CFG_DIR = pathlib.Path(os.path.expanduser("~/.curator-finder"))
CFG_DIR.mkdir(parents=True, exist_ok=True)
CONF_PATH = CFG_DIR / "config.json"
# Load .env from user config dir so double-click launches can see it
from dotenv import load_dotenv as _load_dotenv
_load_dotenv(dotenv_path=CFG_DIR / ".env")   # doesn't override existing env

# Writable export dir (override with env CURATORFINDER_SAVE_DIR)
SAVE_DIR = pathlib.Path(os.getenv("CURATORFINDER_SAVE_DIR", str(CFG_DIR / "exports")))
SAVE_DIR.mkdir(parents=True, exist_ok=True)

DEFAULTS = {
    "spotify_client_id": "",
    "spotify_client_secret": "",
    "license_key": "keys",   # legacy/dev only (text), ignored when serial enforcement is on
    "target_default": 50
}

def load_config() -> Dict[str, Any]:
    if CONF_PATH.exists():
        try:
            data = json.loads(CONF_PATH.read_text(encoding="utf-8"))
            return {**DEFAULTS, **data}
        except Exception:
            return DEFAULTS.copy()
    return DEFAULTS.copy()

def save_config(cfg: Dict[str, Any]) -> None:
    CONF_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:
        os.chmod(CONF_PATH, 0o600)  # owner read/write only
    except Exception:
        pass

CFG = load_config()

# -------------------- Licensing (Ed25519 offline, serial or JSON) --------------------
import base64, hashlib, platform, uuid, json as _json

# OPTIONAL TWEAK: soft dependency for PyNaCl — only hard-require when enforced
LICENSE_MODE = os.getenv("LICENSE_MODE", "disabled").strip().lower()  # disabled|enforced
try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
except Exception as e:
    if LICENSE_MODE == "enforced":
        # When enforcement is on, PyNaCl must be present
        raise RuntimeError("PyNaCl is required when LICENSE_MODE=enforced") from e
    # In disabled mode, define shims so imports don’t crash
    class BadSignatureError(Exception): ...
    class VerifyKey:  # type: ignore
        def __init__(self, *_args, **_kwargs): ...
        def verify(self, *_args, **_kwargs): ...

LICENSE_PATH = CFG_DIR / "license.json"

# Provide public key at build/launch time:
PUBLIC_KEY_B64 = os.getenv("CURATORFINDER_PUBKEY_B64", "").strip()
# Or hardcode here if you prefer:
# PUBLIC_KEY_B64 = "BASE64_VERIFY_KEY_HERE"

GRACE_SECS = 7*24*3600  # brief grace after a valid check
_last_ok_ts = 0
_last_payload: Optional[dict] = None

# --- Serial packing helpers (urlsafe base64 without padding, grouped)
SERIAL_PREFIX = "CF1-"
GROUP_CHAR = "."  # grouping character that is safe for base64url

def _b64u_no_pad(b: bytes) -> str:
    s = base64.urlsafe_b64encode(b).decode().rstrip("=")
    return s

def _b64u_with_pad(s: str) -> bytes:
    # pad to length % 4 == 0
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _b64flex_to_bytes(s: str) -> bytes:
    """Decode base64 or base64url, with or without padding."""
    s = (s or "").strip().replace("\n", "").replace("\r", "")
    # normalize urlsafe -> standard
    s = s.replace("-", "+").replace("_", "/")
    # add padding
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.b64decode(s)

def pack_token_to_serial(token: dict) -> str:
    """
    Serial format:
      CF1-<base>-<sig>
    where <base> is b64url(json payload) and <sig> is b64url(signature).
    We group with hyphens every 5 chars for readability.
    """
    payload = token.get("payload") or {}
    sig_b64 = token.get("sig") or ""
    if not payload or not sig_b64:
        raise ValueError("token missing parts")
    base = _b64u_no_pad(_json.dumps(payload, separators=(",",":"), ensure_ascii=False).encode())
    sig  = sig_b64.replace("=", "").replace("+", "-").replace("/", "_")  # ensure urlsafe/trimmed
    raw = SERIAL_PREFIX + base + "-" + sig
    letters = raw.replace(SERIAL_PREFIX, "")
    grouped = GROUP_CHAR.join([letters[i:i+5] for i in range(0, len(letters), 5)])
    return SERIAL_PREFIX + grouped

def unpack_serial_to_token(serial: str) -> dict:
    if not serial.upper().startswith(SERIAL_PREFIX):
        raise ValueError("bad-serial-prefix")
    # prefer the new safe grouping char
    if GROUP_CHAR in serial:
        body = serial[len(SERIAL_PREFIX):].replace(GROUP_CHAR, "")
    else:
        # BACKWARD-COMPAT: old buggy hyphen grouping (may corrupt data if '-' appears in base64url)
        body = serial[len(SERIAL_PREFIX):].replace("-", "")
    # Heuristic split of base and sig; try a range of signature lengths (urlsafe b64)
    for cut in range(60, 120):
        base = body[:-cut]
        sig  = body[-cut:]
        try:
            payload_json = _b64u_with_pad(base).decode("utf-8")
            payload = _json.loads(payload_json)
            token = {"payload": payload, "sig": _b64u_no_pad(_b64u_with_pad(sig))}
            return token
        except Exception:
            continue
    raise ValueError("bad-serial-format")

def _device_id() -> str:
    parts = [platform.system(), platform.release(), platform.machine(), hex(uuid.getnode())]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]

def _verify_license_token(token: dict) -> Tuple[bool, str, dict]:
    try:
        payload = token.get("payload") or {}
        sig_b64 = token.get("sig") or ""
        if not PUBLIC_KEY_B64:
            return False, "no-public-key", {}
        if not payload or not sig_b64:
            return False, "malformed", {}

        msg = _json.dumps(payload, separators=(",",":"), ensure_ascii=False).encode("utf-8")
        sig = _b64flex_to_bytes(sig_b64)
        vk = VerifyKey(_b64flex_to_bytes(PUBLIC_KEY_B64))
        vk.verify(msg, sig)  # raises if invalid

        now = int(time.time())
        exp = int(payload.get("exp") or 0)
        if exp and now > exp:
            return False, "expired", payload

        mach = payload.get("machine")
        me = _device_id()
        if mach:
            if isinstance(mach, list):
                if me not in mach:
                    return False, "wrong-machine", payload
            elif mach != me:
                return False, "wrong-machine", payload

        return True, "ok", payload
    except BadSignatureError:
        return False, "bad-signature", {}
    except Exception as e:
        return False, f"error:{e}", {}

def is_license_valid(_: Dict[str, Any]) -> Tuple[bool, str]:
    global _last_ok_ts, _last_payload
    if LICENSE_MODE != "enforced":
        return True, "license disabled"

    if not LICENSE_PATH.exists():
        if _last_ok_ts and (int(time.time()) - _last_ok_ts) <= GRACE_SECS:
            return True, "grace"
        return False, "no-license-file"

    try:
        token = json.loads(LICENSE_PATH.read_text("utf-8"))
    except Exception:
        return False, "corrupt-license-file"

    ok, msg, payload = _verify_license_token(token)
    if ok:
        _last_ok_ts = int(time.time())
        _last_payload = payload
        return True, "ok"
    else:
        if _last_ok_ts and (int(time.time()) - _last_ok_ts) <= GRACE_SECS:
            return True, f"grace:{msg}"
        return False, msg

# ---- Activation request bodies
class ActivateBody(BaseModel):
    token: dict  # {"payload":{...},"sig":"..."}

class ActivateSerialBody(BaseModel):
    serial: str

# -------------------- Friendly error map for UX --------------------
ERROR_MAP = {
    "no-public-key": "License verifier missing (pubkey not set).",
    "malformed": "Malformed license data.",
    "expired": "This license has expired.",
    "wrong-machine": "This license is tied to another device.",
    "bad-signature": "Invalid license signature.",
    "no-license-file": "No license found. Activate with your serial.",
    "corrupt-license-file": "License file is corrupted. Re-activate.",
}

def _humanize(code: str) -> str:
    base = (code or "").split(":", 1)[0]
    return ERROR_MAP.get(base, code)

# -------------------- Scraper/Search config --------------------
USER_AGENT = "KeazeCuratorFinder/API/1.4"
SPOTIFY_PAGE_SIZE = 50
MAX_OFFSETS_PER_QUERY = 20       # up to 1000 playlists per query
MAX_WORKERS_EXTERNAL = 4
REQUEST_TIMEOUT = 10
PAUSE_BETWEEN_EXTERNAL = 0.0

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
# safer URL capture for descriptions:
HTTP_LINK_RE = re.compile(r"https?://[^\s\"'>)]+")
MAILTO_RE = re.compile(r"mailto:([^\s\"'>)]+)", re.IGNORECASE)
CONTEXT_WORDS = ("submit", "submission", "contact", "book", "press", "demo")

CONTACT_LINK_HINTS = (
    "submit", "submission", "contact", "demo", "press", "book",
    "linktr.ee", "beacons.ai", "carrd.co", "notion.so",
    "google.com/forms", "docs.google.com/forms", "typeform.com",
    "form.jotform.com", "wufoo.com", "tally.so", "airtable.com"
)

SKIP_OWNER_CONTAINS = ("spotify", "filtr", "topsify", "digster", "umg", "sony", "warnermusic", "warner")

@app.get("/config")
def get_config():
    """Local-only UX hints for the settings modal (no secrets)."""
    cid = (CFG.get("spotify_client_id") or "").strip()
    csec = (CFG.get("spotify_client_secret") or "").strip()
    lic  = (CFG.get("license_key") or "").strip()

    def mask(s: str, front=4, back=4):
        if not s:
            return ""
        if len(s) <= front + back:
            return s[:2] + "…" + s[-2:]
        return f"{s[:front]}…{s[-back:]}"

    return {
        "spotify_configured": bool(cid and csec),
        "license_present": bool(lic),
        "client_id_masked": mask(cid),
        # keep secrets out of the response:
        "client_secret_set": bool(csec),
        "save_dir": str(SAVE_DIR),
    }

# -------------------- Helpers --------------------
def extract_emails_with_context(text: Optional[str]) -> List[Dict[str, str]]:
    text = text or ""
    lower = text.lower()
    out, seen = [], set()
    for m in EMAIL_RE.finditer(text):
        email = m.group(0)
        if email.lower().endswith("@spotify.com"):
            continue
        start = max(0, m.start() - 60)
        end = min(len(text), m.end() + 60)
        window = lower[start:end]
        hits = [w for w in CONTEXT_WORDS if w in window]
        ctx = "found near: " + ", ".join(sorted(set(hits))) if hits else "no context keywords"
        if email not in seen:
            seen.add(email)
            out.append({"value": email, "context": ctx})
    return out

def is_editorial_owner(owner: Dict[str, Any]) -> bool:
    name = (owner.get("display_name") or owner.get("id") or "").lower()
    return any(bad in name for bad in SKIP_OWNER_CONTAINS)

def fetch_html(url: str) -> Optional[str]:
    try:
        if PAUSE_BETWEEN_EXTERNAL:
            time.sleep(PAUSE_BETWEEN_EXTERNAL)
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        if r.status_code == 200 and "text/html" in r.headers.get("Content-Type", ""):
            return r.text
    except requests.RequestException:
        return None
    return None

def scrape_public_page(url: str) -> Dict[str, Any]:
    out = {"emails": [], "websites": [], "socials": {"instagram": [], "x": [], "youtube": [], "tiktok": []}}
    html = fetch_html(url)
    if not html:
        return out
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)
    out["emails"] = extract_emails_with_context(text)

    links = sorted({a.get("href") for a in soup.select("a[href]") if a.get("href", "").startswith("http")})
    out["websites"] = links

    for l in links:
        ll = l.lower()
        if "instagram.com" in ll:
            out["socials"]["instagram"].append(l)
        elif "x.com" in ll or "twitter.com" in ll:
            out["socials"]["x"].append(l)
        elif "youtube.com" in ll or "youtu.be" in ll:
            out["socials"]["youtube"].append(l)
        elif "tiktok.com" in ll:
            out["socials"]["tiktok"].append(l)

    for k in out["socials"]:
        out["socials"][k] = sorted(set(out["socials"][k]))
    return out

def discover_playlists(sp: spotipy.Spotify, query: str, max_offsets: int) -> Iterable[Dict[str, Any]]:
    for i in range(max_offsets):
        offset = i * SPOTIFY_PAGE_SIZE
        try:
            res = sp.search(q=query, type="playlist", limit=SPOTIFY_PAGE_SIZE, offset=offset)
        except Exception:
            break
        pl_block = res.get("playlists") or {}
        items = pl_block.get("items") or []
        if not items:
            break
        for pl in items:
            if isinstance(pl, dict):
                yield pl

def looks_contactish(u: str) -> bool:
    lu = u.lower()
    return any(h in lu for h in CONTACT_LINK_HINTS)

def curator_key_from(owner_handle: str, owner_url: str, owner_name: str) -> str:
    return (owner_handle or owner_url or owner_name or "").strip().lower()

def write_csv(json_data: List[Dict[str, Any]], csv_path: str) -> None:
    rows = []
    for r in json_data:
        pl = r["playlist"]
        emails = r["contacts"].get("emails", [])
        subs   = r["contacts"].get("submission_links", [])
        if not emails:
            rows.append({
                "curator": pl["owner_name"],
                "handle": pl["owner_handle"],
                "playlist": pl["name"],
                "playlist_url": pl["url"],
                "email": "",
                "email_context": "",
                "submission_links": " ".join(subs),
                "source_query": r["source_query"]
            })
        else:
            for e in emails:
                rows.append({
                    "curator": pl["owner_name"],
                    "handle": pl["owner_handle"],
                    "playlist": pl["name"],
                    "playlist_url": pl["url"],
                    "email": e["value"],
                    "email_context": e.get("context", ""),
                    "submission_links": " ".join(subs),
                    "source_query": r["source_query"]
                })
    if not rows:
        return
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)

# -------------------- Models --------------------
class SetupBody(BaseModel):
    client_id: str
    client_secret: str
    license_key: str  # legacy text key (ignored when enforcement is on)

class SearchBody(BaseModel):
    artists: List[str] = []
    keywords: List[str] = []
    genres: List[str] = []
    target: int = 100
    save: bool = False  # also write curators.json/csv on disk

# -------------------- Endpoints --------------------
@app.get("/health")
def health():
    lic_ok, lic_msg = is_license_valid(CFG)
    spotify_ready = bool(CFG.get("spotify_client_id")) and bool(CFG.get("spotify_client_secret"))
    exp = None
    try:
        if LICENSE_PATH.exists():
            token = json.loads(LICENSE_PATH.read_text("utf-8"))
            exp = (token.get("payload") or {}).get("exp")
    except Exception:
        pass
    return {
        "server": True,
        "version": app.version,
        "license": {"mode": LICENSE_MODE, "ok": lic_ok, "message": lic_msg, "exp": exp},
        "spotify": {"configured": spotify_ready, "message": "OK" if spotify_ready else "Missing keys"},
        "save_dir": str(SAVE_DIR),
        # legacy flags (for old dashboard code)
        "license_ok": lic_ok,
        "license_msg": lic_msg,
        "spotify_ok": spotify_ready,
    }

class LicenseSummary(BaseModel):
    mode: str
    ok: bool
    code: str
    message: str
    exp: Optional[int] = None

@app.get("/license/status", response_model=LicenseSummary)
def license_status():
    ok, code = is_license_valid(CFG)
    exp = None
    try:
        if LICENSE_PATH.exists():
            token = json.loads(LICENSE_PATH.read_text("utf-8"))
            exp = (token.get("payload") or {}).get("exp")
    except Exception:
        pass
    code_str = str(code)
    message = "OK" if ok and code_str.split(":", 1)[0] in ("ok", "grace") else _humanize(code_str)
    return LicenseSummary(mode=LICENSE_MODE, ok=bool(ok), code=code_str, message=message, exp=exp)

@app.get("/license/debug")
def license_debug():
    # Hidden unless CF_DEBUG=1
    if os.getenv("CF_DEBUG") != "1":
        raise HTTPException(status_code=404)
    pubsrc = "env" if os.getenv("CURATORFINDER_PUBKEY_B64") else ("hardcoded" if PUBLIC_KEY_B64 else "missing")
    exists = LICENSE_PATH.exists()
    payload = None
    status = None
    try:
        if exists:
            token = json.loads(LICENSE_PATH.read_text("utf-8"))
            payload = (token.get("payload") or {})
        ok, code = is_license_valid(CFG)
        status = f"{'ok' if ok else 'fail'}:{code}"
    except Exception as e:
        status = f"error:{e}"
    # Redact signature if present
    if isinstance(payload, dict):
        payload = {k: ('***' if k in {'sig'} else v) for k, v in payload.items()}
    return {
        "mode": LICENSE_MODE,
        "public_key_source": pubsrc,
        "license_path": str(LICENSE_PATH),
        "license_exists": exists,
        "last_check": status,
        "payload": payload,
    }

@app.get("/device-id")
def device_id():
    return {"device_id": _device_id()}

@app.post("/activate")
def activate(body: ActivateBody):
    ok, msg, _payload = _verify_license_token(body.token)
    if not ok:
        raise HTTPException(status_code=400, detail=f"License invalid: {_humanize(msg)}")
    LICENSE_PATH.write_text(json.dumps(body.token, indent=2), encoding="utf-8")
    try:
        os.chmod(LICENSE_PATH, 0o600)
    except Exception:
        pass
    return {"activated": True, "mode": "json-token"}

@app.post("/activate-serial")
def activate_serial(body: ActivateSerialBody):
    try:
        token = unpack_serial_to_token(body.serial.strip())
    except Exception:
        raise HTTPException(status_code=400, detail="Bad serial format.")
    ok, msg, _payload = _verify_license_token(token)
    if not ok:
        raise HTTPException(status_code=400, detail=f"License invalid: {_humanize(msg)}")
    LICENSE_PATH.write_text(json.dumps(token, indent=2), encoding="utf-8")
    try:
        os.chmod(LICENSE_PATH, 0o600)
    except Exception:
        pass
    return {"activated": True, "mode": "serial"}

@app.post("/setup")
def setup(body: SetupBody):
    CFG["spotify_client_id"] = body.client_id.strip()
    CFG["spotify_client_secret"] = body.client_secret.strip()
    CFG["license_key"] = (body.license_key or "").strip()  # legacy text
    save_config(CFG)
    return {"saved": True}

def _do_search(body: SearchBody, progress: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
    """
    Heavy search logic (runs in a worker thread).
    Streams progress via `progress({...})` if provided.
    """

    # --- progress helpers (throttled "ticks" so UI stays alive even when % doesn't move)
    last_emails_count = 0
    last_tick_ts = 0.0
    TICK_MIN_SEC = 0.35  # don't flood; UI also has heartbeat blanks
    t0 = time.time()
    ema_rate = None  # emails per second (smoothed)
    EMA_ALPHA = 0.25

    def report_progress(
        emails_count: int,
        curators_count: int,
        *,
        event: str = "progress",
        extra: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ):
        nonlocal last_tick_ts, ema_rate
        if not progress:
            return
        now = time.time()
        if not force and event == "scan" and (now - last_tick_ts) < TICK_MIN_SEC:
            return
        last_tick_ts = now
        pct = min(100, int(100 * emails_count / max(1, body.target)))

        # --- ETA: exponential moving average on emails/sec
        elapsed = max(0.001, now - t0)
        inst_rate = emails_count / elapsed
        if ema_rate is None:
            ema_rate = inst_rate
        else:
            ema_rate = (EMA_ALPHA * inst_rate) + ((1.0 - EMA_ALPHA) * ema_rate)

        remaining = max(0, body.target - emails_count)
        if remaining == 0:
            eta_sec = 0
        else:
            eta_sec = int(min(21600, remaining / ema_rate)) if (ema_rate and ema_rate > 0) else None

        msg = {
            "type": "progress",
            "pct": pct,
            "emails": emails_count,
            "curators": curators_count,
            "target": body.target,
            "event": event,
            "eta_sec": eta_sec,
        }
        if extra:
            msg.update(extra)
        progress(msg)

    # license gate
    ok, msg = is_license_valid(CFG)
    if not ok:
        raise HTTPException(status_code=402, detail=f"License required: {_humanize(msg)}")

    # Build queries (+ genre/keyword combos)
    queries = list(dict.fromkeys(body.artists + body.keywords + body.genres))
    for g in body.genres:
        for k in body.keywords:
            combo = f"{g} {k}"
            if combo not in queries:
                queries.append(combo)

    # Spotify auth (env overrides config if present)
    cid = os.environ.get("SPOTIFY_CLIENT_ID") or CFG.get("spotify_client_id")
    csec = os.environ.get("SPOTIFY_CLIENT_SECRET") or CFG.get("spotify_client_secret")
    if not cid or not csec:
        raise HTTPException(status_code=400, detail="Spotify keys not configured. Use Setup.")

    sp = spotipy.Spotify(
        auth_manager=SpotifyClientCredentials(client_id=cid, client_secret=csec),
        requests_timeout=15,
    )

    results: List[Dict[str, Any]] = []
    playlists_seen, emails_seen, curators_seen = set(), set(), set()
    processed = 0
    skipped_no_contact = 0
    skipped_editorial = 0

    # initial 0% report
    report_progress(0, 0, event="start", extra={"scanned": 0})

    for q in queries:
        # ping at query start
        report_progress(len(emails_seen), len(results), event="query_start", extra={"query": q, "scanned": processed})

        for pl in discover_playlists(sp, q, MAX_OFFSETS_PER_QUERY):
            pid = (pl.get("id") or "").strip()
            if not pid or pid in playlists_seen:
                continue
            playlists_seen.add(pid)
            processed += 1

            owner_raw = pl.get("owner")
            owner = owner_raw if isinstance(owner_raw, dict) else {}
            if is_editorial_owner(owner):
                skipped_editorial += 1
                # progress ping (editorial skip)
                report_progress(
                    len(emails_seen),
                    len(results),
                    event="skip_editorial",
                    extra={
                        "scanned": processed,
                        "skipped_editorial": skipped_editorial,
                        "query": q,
                    },
                )
                continue

            name = pl.get("name") or ""
            url  = (pl.get("external_urls") or {}).get("spotify", "")
            desc = pl.get("description") or ""
            owner_name = owner.get("display_name") or owner.get("id") or ""
            owner_handle = owner.get("id") or ""
            owner_url = (owner.get("external_urls") or {}).get("spotify", "")

            # emails from description + mailto:
            emails = extract_emails_with_context(desc)
            for addr in MAILTO_RE.findall(desc):
                addr = addr.strip()
                if addr and not addr.lower().endswith("@spotify.com"):
                    if all(addr != x["value"] for x in emails):
                        emails.append({"value": addr, "context": "mailto in description"})

            # links (ignore Spotify domains), prioritize contact-ish
            links = sorted(set(HTTP_LINK_RE.findall(desc)))
            links = [u for u in links if "open.spotify.com" not in u.lower() and "spoti.fi" not in u.lower()]
            contactish_links = [u for u in links if looks_contactish(u)]
            other_links = [u for u in links if u not in contactish_links]
            crawl_order = contactish_links + other_links

            websites = set()
            socials = {"instagram": [], "x": [], "youtube": [], "tiktok": []}

            if crawl_order:
                with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_EXTERNAL) as ex:
                    for info in ex.map(scrape_public_page, crawl_order):
                        for e in info["emails"]:
                            if e["value"].endswith("@spotify.com"):
                                continue
                            if all(e["value"] != x["value"] for x in emails):
                                emails.append(e)
                        websites.update(info["websites"])
                        for k in socials:
                            socials[k].extend(info["socials"][k])

            for k in socials:
                socials[k] = sorted(set(socials[k]))

            has_email = bool(emails)
            has_contactish_link = bool(contactish_links)
            if not (has_email or has_contactish_link):
                skipped_no_contact += 1
                # <- explicit progress ping when a playlist has no contact info
                report_progress(
                    len(emails_seen),
                    len(results),
                    event="no_contact",
                    extra={
                        "scanned": processed,
                        "skipped_no_contact": skipped_no_contact,
                        "query": q
                    }
                )
                continue

            ckey = curator_key_from(owner_handle, owner_url, owner_name)
            if ckey and ckey in curators_seen:
                # still ping a scan tick so UI feels responsive
                report_progress(
                    len(emails_seen),
                    len(results),
                    event="dup_curator",
                    extra={
                        "scanned": processed,
                        "query": q
                    }
                )
                continue
            if ckey:
                curators_seen.add(ckey)

            for e in emails:
                emails_seen.add(e["value"])

            results.append({
                "provider": "spotify",
                "source_query": q,
                "playlist": {
                    "id": pid,
                    "name": name,
                    "url": url,
                    "owner_name": owner_name,
                    "owner_handle": owner_handle,
                    "owner_url": owner_url
                },
                "contacts": {
                    "emails": emails,
                    "websites": sorted(websites),
                    "socials": socials,
                    "submission_links": contactish_links
                },
                "notes": "saved because it had email or submission/contact link; curator de-duped"
            })

            # emit progress whenever unique email count changes (force immediate)
            if len(emails_seen) != last_emails_count:
                last_emails_count = len(emails_seen)
                report_progress(last_emails_count, len(results), event="email_gain", extra={
                    "scanned": processed,
                    "skipped_no_contact": skipped_no_contact,
                    "skipped_editorial": skipped_editorial,
                    "query": q
                }, force=True)
            else:
                # otherwise light scan tick
                report_progress(len(emails_seen), len(results), event="scan", extra={
                    "scanned": processed,
                    "skipped_no_contact": skipped_no_contact,
                    "skipped_editorial": skipped_editorial,
                    "query": q
                })

            if len(emails_seen) >= body.target:
                break
        if len(emails_seen) >= body.target:
            break

    # Optional save to disk
    if body.save:
        out_json = SAVE_DIR / "curators.json"
        out_csv  = SAVE_DIR / "curators.csv"
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        write_csv(results, str(out_csv))

    # final 100%
    report_progress(len(emails_seen), len(results), event="done", extra={
        "scanned": processed,
        "skipped_no_contact": skipped_no_contact,
        "skipped_editorial": skipped_editorial
    }, force=True)

    return {
        "count_curators": len(results),
        "unique_emails": len(emails_seen),
        "results": results,
        "saved": bool(body.save),
        "save_dir": str(SAVE_DIR)
    }

@app.post("/search")
def search(body: SearchBody):
    """
    Streams newline-delimited JSON (NDJSON) with progress updates:
      {"type":"progress","pct":42,"emails":21,"curators":37,"target":50,"event":"scan","scanned":123,...}
    and finishes with either:
      {"type":"final","payload":{...}}
    or:
      {"type":"error","status":402,"detail":"..."}
    """
    q: "queue.Queue[Dict[str, Any]]" = queue.Queue()
    done = threading.Event()
    out: Dict[str, Any] = {}
    err: Optional[HTTPException] = None

    def worker():
        nonlocal out, err
        try:
            out = _do_search(body, progress=lambda msg: q.put(msg))
        except HTTPException as he:
            err = he
        except Exception as e:
            print("SEARCH ERROR:\n", traceback.format_exc())
            err = HTTPException(status_code=500, detail=f"internal: {type(e).__name__}: {e}")
        finally:
            done.set()

    threading.Thread(target=worker, daemon=True).start()

    def gen():
        # emit anything already queued immediately
        while not done.is_set() or not q.empty():
            try:
                # drain the queue fast
                while True:
                    msg = q.get_nowait()
                    yield (json.dumps(msg) + "\n").encode("utf-8")
            except queue.Empty:
                # keep-alive heartbeat line (blank)
                yield b"\n"
                time.sleep(0.3)

        if err is None:
            yield (json.dumps({"type": "final", "payload": out}) + "\n").encode("utf-8")
        else:
            yield (json.dumps({"type": "error", "status": err.status_code, "detail": err.detail}) + "\n").encode("utf-8")

    # NDJSON media type to signal line-delimited JSON (single return with no-buffer headers)
    return StreamingResponse(
        gen(),
        media_type="application/x-ndjson",
        headers={
            "X-Accel-Buffering": "no",
            "Cache-Control": "no-cache",
        },
    )
