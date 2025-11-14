import os, json, pathlib
APP_NAME = "curator-finder"
HOME = pathlib.Path.home()
CONF_DIR = pathlib.Path(os.getenv("CURATOR_FINDER_HOME", HOME / f".{APP_NAME}"))
CONF_DIR.mkdir(parents=True, exist_ok=True)
CONF_FILE = CONF_DIR / "config.json"

DEFAULTS = {
  "spotify": {"client_id": "", "client_secret": "", "redirect_uri": "http://127.0.0.1:8080/callback"},
  "license_key": ""
}

def load():
    if CONF_FILE.exists():
        try: return {**DEFAULTS, **json.loads(CONF_FILE.read_text())}
        except Exception: pass
    return DEFAULTS.copy()

def save(cfg: dict):
    CONF_FILE.write_text(json.dumps(cfg, indent=2))
