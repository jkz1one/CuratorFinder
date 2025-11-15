# server.py — Curator Finder local API (Spotify) – Early Access (beta gate, no licensing)
#
# Endpoints:
#   GET  /, /dashboard.html -> serve dashboard.html (same origin)
#   GET  /health            -> server + spotify + beta gate status (+ save_dir)
#   GET  /config            -> minimal UX hints (no secrets)
#   POST /setup             -> save spotify keys to ~/.curator-finder/config.json
#   POST /search            -> run discovery/scrape (gated by Early Access beta), returns JSON (no streaming)

import os
import re
import sys
import json
import csv
import time
import pathlib
import concurrent.futures
from typing import List, Dict, Any, Optional, Callable

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from beta_access import check_beta_access

import traceback
import requests
from bs4 import BeautifulSoup  # noqa: F401 (kept for future external scraping)
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
from spotipy.exceptions import SpotifyException

# --- TLS certs for bundled apps (requests/spotipy)
try:
    import certifi as _certifi
    os.environ.setdefault("SSL_CERT_FILE", _certifi.where())
    os.environ.setdefault("REQUESTS_CA_BUNDLE", _certifi.where())
except Exception:
    pass


# -------------------- Load .env (app dir + config dir) --------------------
def _load_all_dotenv() -> pathlib.Path:
    """
    Load environment variables from:
      1) .env next to the app/bundle (handles dev + PyInstaller)
      2) ~/.curator-finder/.env (user config)
    without overriding already-set env vars.

    Returns the config directory path (~/.curator-finder).
    """
    try:
        base_dir = pathlib.Path(getattr(sys, "_MEIPASS", pathlib.Path(__file__).resolve().parent))
    except Exception:
        base_dir = pathlib.Path(__file__).resolve().parent

    load_dotenv(dotenv_path=base_dir / ".env", override=False)

    cfg_dir = pathlib.Path(os.path.expanduser("~/.curator-finder"))
    cfg_dir.mkdir(parents=True, exist_ok=True)
    load_dotenv(dotenv_path=cfg_dir / ".env", override=False)

    return cfg_dir


CFG_DIR = _load_all_dotenv()

# -------------------- App / CORS --------------------
app = FastAPI(title="Curator Finder API", version=os.getenv("CURATORFINDER_VERSION", "early-access-1"))

origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://127.0.0.1",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins + ["*"],  # local-only in practice
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

HERE = pathlib.Path(__file__).resolve().parent

# Serve static files (for any future assets)
app.mount("/static", StaticFiles(directory=str(HERE), html=False), name="static")


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard.html", response_class=HTMLResponse)
def dashboard():
    path = HERE / "dashboard.html"
    if not path.exists():
        raise HTTPException(status_code=404, detail="dashboard.html missing")
    return HTMLResponse(path.read_text("utf-8"))


# -------------------- Config (self-contained) --------------------
CONF_PATH = CFG_DIR / "config.json"

# Writable export dir (override with env CURATORFINDER_SAVE_DIR)
SAVE_DIR = pathlib.Path(os.getenv("CURATORFINDER_SAVE_DIR", str(CFG_DIR / "exports")))
SAVE_DIR.mkdir(parents=True, exist_ok=True)

DEFAULTS = {
    "spotify_client_id": "",
    "spotify_client_secret": "",
    "target_default": 50,
}


def load_config() -> Dict[str, Any]:
    if CONF_PATH.exists():
        try:
            data = json.loads(CONF_PATH.read_text("utf-8"))
            if isinstance(data, dict):
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

# -------------------- Scraper/Search config --------------------
USER_AGENT = "KeazeCuratorFinder/API/early-access"
SPOTIFY_PAGE_SIZE = 50
MAX_OFFSETS_PER_QUERY = 20       # up to 1000 playlists per query
MAX_WORKERS_EXTERNAL = 4
REQUEST_TIMEOUT = 10
PAUSE_BETWEEN_EXTERNAL = 0.0

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HTTP_LINK_RE = re.compile(r"https?://[^\s\"'>)]+")
MAILTO_RE = re.compile(r"mailto:([^\s\"'>)]+)", re.IGNORECASE)

# Hints for link-based contact forms / hubs
CONTACT_LINK_HINTS = (
    "submit",
    "submissions",
    "demo",
    "promos",
    "contact",
    "pitch",
    "playlist-promotion",
    "playlist submission",
)


def request_with_retry(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    timeout: int = REQUEST_TIMEOUT,
    max_retries: int = 3,
    backoff: float = 0.5,
) -> requests.Response:
    for attempt in range(max_retries):
        try:
            resp = requests.request(
                method,
                url,
                headers=headers,
                params=params,
                timeout=timeout,
            )
            if resp.status_code >= 500:
                raise HTTPException(status_code=502, detail=f"Upstream error {resp.status_code}")
            return resp
        except requests.RequestException as e:
            if attempt == max_retries - 1:
                raise HTTPException(status_code=502, detail=str(e))
            time.sleep(backoff * (2 ** attempt))

    raise HTTPException(status_code=502, detail="request failed after retries")


def fetch_playlist_page(sp: spotipy.Spotify, query: str, offset: int) -> Dict[str, Any]:
    """
    Wrap Spotipy search so that Spotify 4xx errors become HTTPExceptions
    the rest of the pipeline can understand.
    """
    try:
        return sp.search(
            q=query,
            type="playlist",
            limit=SPOTIFY_PAGE_SIZE,
            offset=offset,
        )
    except SpotifyException as exc:
        msg = getattr(exc, "msg", "") or str(exc)
        msg = msg.strip()
        raise HTTPException(status_code=400, detail=msg)


def extract_emails_with_context(text: Optional[str]) -> List[Dict[str, str]]:
    """
    Find emails in a blob of text and capture a short context window.
    """
    text = text or ""
    out: List[Dict[str, str]] = []
    seen = set()
    for m in EMAIL_RE.finditer(text):
        email = m.group(0)
        key = email.lower()
        if key in seen:
            continue
        seen.add(key)
        start = max(0, m.start() - 60)
        end = min(len(text), m.end() + 60)
        snippet = text[start:end].replace("\n", " ")
        out.append({"email": email, "value": email, "context": snippet})
    return out


def extract_links(text: Optional[str]) -> List[str]:
    text = text or ""
    return [m.group(0) for m in HTTP_LINK_RE.finditer(text)]


def is_editorial(name: str, owner_name: str) -> bool:
    n = (name or "").lower()
    o = (owner_name or "").lower()
    editorial_keywords = (
        "spotify", "filtr", "topsify", "digster", "editorial", "official", "this is ",
    )
    if any(k in n for k in editorial_keywords):
        return True
    if any(k in o for k in editorial_keywords):
        return True
    return False


def is_good_contact_link(url: str) -> bool:
    """
    Decide if a URL in the playlist description looks like a contact / submission link.

    Strategy:
      - Always ignore Spotify links themselves.
      - Treat explicit contact-ish words as strong signals.
      - Treat common “hub” domains (linktr.ee, beacons, forms, tally, airtable, etc.)
        as contact links by default, because that’s where submission forms usually live.
    """
    u = url.lower()

    # ignore Spotify links themselves
    if "open.spotify.com" in u or "spoti.fi" in u:
        return False

    # explicit hints
    if any(h in u for h in CONTACT_LINK_HINTS):
        return True

    # contact hubs / forms
    hub_domains = (
        "linktr.ee",
        "beacons.ai",
        "carrd.co",
        "notion.so",
        "google.com/forms",
        "docs.google.com/forms",
        "typeform.com",
        "form.jotform.com",
        "wufoo.com",
        "tally.so",
        "airtable.com",
    )
    if any(d in u for d in hub_domains):
        return True

    # generic socials w/out hints are weak; skip
    social_domains = (
        "instagram.com",
        "facebook.com",
        "twitter.com",
        "x.com",
        "youtube.com",
        "youtu.be",
        "soundcloud.com",
        "tiktok.com",
    )
    if any(d in u for d in social_domains):
        return False

    # fallback: allow any other non-Spotify http(s) link
    return True


@app.get("/config")
def get_config():
    """Local-only UX hints for the settings modal (no secrets)."""
    cid = (CFG.get("spotify_client_id") or "").strip()
    csec = (CFG.get("spotify_client_secret") or "").strip()

    def mask(s: str, front=4, back=4):
        if not s:
            return ""
        if len(s) <= front + back:
            return s[:2] + "…" + s[-2:]
        return f"{s[:front]}…{s[-back:]}"

    return {
        "spotify_configured": bool(cid and csec),
        "client_id_masked": mask(cid),
        "client_secret_set": bool(csec),
        "save_dir": str(SAVE_DIR),
    }


# -------------------- Helpers --------------------
def write_csv(curators: List[Dict[str, Any]], path: str) -> None:
    """
    Write a simple CSV export from nested curator records:

      {
        "playlist": {...},
        "owner": {...},
        "contacts": {
          "emails": [{"value":..., "context":...}, ...],
          "submissions": [{"url":...}, ...]
        }
      }
    """
    if not curators:
        return

    rows: List[Dict[str, str]] = []
    for rec in curators:
        pl = rec.get("playlist") or {}
        owner = rec.get("owner") or {}
        contacts = rec.get("contacts") or {}
        emails = contacts.get("emails") or []
        subs = contacts.get("submissions") or []

        primary_email = emails[0]["value"] if emails else ""
        email_ctx = emails[0].get("context", "") if emails else ""
        sub_links = " ".join(s.get("url", "") for s in subs if s.get("url"))

        rows.append(
            {
                "email": primary_email,
                "email_context": email_ctx,
                "playlist_name": pl.get("name", ""),
                "playlist_url": pl.get("url", ""),
                "owner_name": owner.get("name", ""),
                "owner_id": owner.get("id", ""),
                "submission_links": sub_links,
            }
        )

    fieldnames = ["email", "email_context", "playlist_name", "playlist_url", "owner_name", "owner_id", "submission_links"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


# -------------------- Pydantic models --------------------
class SetupBody(BaseModel):
    client_id: str
    client_secret: str


class SearchBody(BaseModel):
    artists: List[str] = []
    keywords: List[str] = []
    genres: List[str] = []
    target: int = 100
    save: bool = False  # also write curators.json/csv on disk


# -------------------- Endpoints --------------------
@app.get("/health")
def health():
    ok, beta = check_beta_access()
    spotify_ready = bool(CFG.get("spotify_client_id")) and bool(CFG.get("spotify_client_secret"))

    return {
        "server": True,
        "version": app.version,
        "beta": beta,
        "spotify": {"configured": spotify_ready, "message": "OK" if spotify_ready else "Missing keys"},
        "save_dir": str(SAVE_DIR),
    }


@app.post("/setup")
def setup(body: SetupBody):
    CFG["spotify_client_id"] = body.client_id.strip()
    CFG["spotify_client_secret"] = body.client_secret.strip()
    save_config(CFG)
    return {"saved": True}


def _clean_query(q: str) -> str:
    """Strip obvious junk from a Spotify search string."""
    q = (q or "").strip()
    q = re.sub(r"[\r\n\t]+", " ", q)
    q = re.sub(r"\s{2,}", " ", q)
    return q


def _do_search(body: SearchBody, progress: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
    """
    Heavy search logic. NO streaming here; FastAPI will run this in a worker thread.
    Returns nested curator records matching the dashboard UI shape.
    """

    # --- beta gate ---
    ok, info = check_beta_access()
    if not ok:
        message = (info or {}).get("message") or "Early Access beta expired or invalid."
        raise HTTPException(status_code=403, detail=message)

    # Build queries (+ genre combos), with simple sanitization
    base_queries: List[str] = []
    for raw in (body.artists + body.keywords + body.genres):
        cleaned = _clean_query(raw)
        if cleaned:
            base_queries.append(cleaned)

    queries: List[str] = list(dict.fromkeys(base_queries))

    for g in body.genres:
        g_clean = _clean_query(g)
        if not g_clean:
            continue
        for kw in ("playlist", "mix", "radio"):
            combo = _clean_query(f"{g_clean} {kw}")
            if combo and combo not in queries:
                queries.append(combo)

    if not queries:
        raise HTTPException(
            status_code=400,
            detail="Please enter at least one artist, keyword, or genre.",
        )

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
    emails_seen = set()
    processed = 0

    def report_progress(event: str, extra: Optional[Dict[str, Any]] = None):
        if not progress:
            return
        msg: Dict[str, Any] = {
            "type": "progress",
            "event": event,
            "processed": processed,
            "emails": len(emails_seen),
            "curators": len(results),
            "target": body.target,
        }
        if extra:
            msg.update(extra)
        # currently only used for debug/print, can be wired to logs if you want
        print("[search]", msg)

    def handle_playlist(pl: Dict[str, Any]):
        nonlocal processed

        # Defensive: skip totally bogus entries
        if not isinstance(pl, dict):
            report_progress("skip_bad_playlist", {"reason": "not a dict"})
            return

        name = pl.get("name") or ""
        owner = pl.get("owner") or {}
        if not isinstance(owner, dict):
            owner = {}
        owner_name = owner.get("display_name") or owner.get("id") or ""
        processed += 1

        # Skip Spotify/editorial stuff
        if is_editorial(name, owner_name):
            report_progress("skip_editorial", {"playlist": name})
            return

        description = pl.get("description") or ""
        emails = extract_emails_with_context(description)

        # also pick up mailto: links
        for addr in MAILTO_RE.findall(description):
            addr = addr.strip()
            if not addr:
                continue
            if all(addr.lower() != e["email"].lower() for e in emails):
                emails.append({"email": addr, "value": addr, "context": "mailto in description"})

        links = extract_links(description)
        contact_links = [u for u in links if is_good_contact_link(u)]

        if not emails and not contact_links:
            report_progress("skip_no_contact", {"playlist": name})
            return

        playlist_id = pl.get("id") or ""
        playlist_url = pl.get("external_urls", {}).get("spotify", "")
        owner_id = owner.get("id") or ""

        # Build nested curator record(s)
        if emails:
            for e in emails:
                em = (e.get("email") or e.get("value") or "").strip()
                if not em:
                    continue
                key = em.lower()
                if key in emails_seen:
                    continue
                emails_seen.add(key)

                results.append(
                    {
                        "playlist": {
                            "id": playlist_id,
                            "name": name,
                            "url": playlist_url,
                        },
                        "owner": {
                            "name": owner_name,
                            "id": owner_id,
                            "links": [],
                        },
                        "contacts": {
                            "emails": [
                                {
                                    "value": em,
                                    "context": e.get("context", ""),
                                }
                            ],
                            "submissions": [{"url": u} for u in contact_links],
                        },
                        "notes": "saved because it had email and/or submission/contact link",
                    }
                )
        else:
            # No direct email, but we DO have contact_links.
            results.append(
                {
                    "playlist": {
                        "id": playlist_id,
                        "name": name,
                        "url": playlist_url,
                    },
                    "owner": {
                        "name": owner_name,
                        "id": owner_id,
                        "links": [],
                    },
                    "contacts": {
                        "emails": [],
                        "submissions": [{"url": u} for u in contact_links],
                    },
                    "notes": "saved because it had submission/contact link only",
                }
            )

        report_progress("scan", {"playlist": name})

    def process_query(q: str):
        offset = 0
        for _ in range(MAX_OFFSETS_PER_QUERY):
            try:
                page = fetch_playlist_page(sp, q, offset)
            except HTTPException as e:
                # Spotify explicitly rejected this query; log and stop this query.
                report_progress("error", {"query": q, "detail": str(e.detail)})
                break

            # Defensive: Spotify/spotipy misbehaving or network glitch
            if not page or not isinstance(page, dict):
                report_progress("error", {"query": q, "detail": "Empty or non-dict response from Spotify"})
                break

            playlists_container = page.get("playlists")
            if not isinstance(playlists_container, dict):
                report_progress("error", {"query": q, "detail": "Missing 'playlists' key in Spotify response"})
                break

            playlists = playlists_container.get("items") or []
            if not isinstance(playlists, list) or not playlists:
                # No more playlists for this query
                break

            for p in playlists:
                if not isinstance(p, dict):
                    report_progress("skip_bad_playlist", {"query": q, "reason": "playlist item not dict"})
                    continue
                handle_playlist(p)
                if len(emails_seen) >= body.target:
                    return

            offset += SPOTIFY_PAGE_SIZE
            if len(emails_seen) >= body.target:
                break
            time.sleep(PAUSE_BETWEEN_EXTERNAL)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS_EXTERNAL) as executor:
        futures = [executor.submit(process_query, q) for q in queries]
        for f in concurrent.futures.as_completed(futures):
            try:
                f.result()
            except Exception as e:  # defensive
                print("Query worker error:", e, file=sys.stderr)

    if not results and processed == 0:
        raise HTTPException(
            status_code=400,
            detail="Spotify search failed for all queries. Double-check your search terms and Spotify credentials.",
        )

    saved = False
    if body.save:
        out_json = SAVE_DIR / "curators.json"
        out_csv = SAVE_DIR / "curators.csv"
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        write_csv(results, str(out_csv))
        saved = True

    return {
        "count_curators": len(results),
        "unique_emails": len(emails_seen),
        "results": results,
        "saved": saved,
        "save_dir": str(SAVE_DIR),
    }


@app.post("/search")
def search(body: SearchBody):
    """
    Simple JSON endpoint (no NDJSON streaming).
    The dashboard will await the full JSON payload and then render results.
    """
    try:
        return _do_search(body)
    except HTTPException:
        raise
    except Exception:
        print("SEARCH ERROR:\n", traceback.format_exc(), file=sys.stderr)
        raise HTTPException(status_code=500, detail="Internal error during search.")
