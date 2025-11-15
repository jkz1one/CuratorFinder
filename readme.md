---

# **Curator Finder**

### Playlist Curator Search Engine • Local-First • Desktop App (macOS & Windows)

Curator Finder is a local-first playlist intelligence tool for artists and managers.
It scrapes, filters, enriches, and organizes curator contact data all on-device. No cloud, no SaaS, no tracking.

Built with a **FastAPI backend**, a **custom Spotify ingestion pipeline**, and a clean, responsive **dashboard UI** packaged into a cross-platform desktop app.

<img width="1202" height="773" alt="Screenshot 2025-11-14 at 11 30 11 PM" src="https://github.com/user-attachments/assets/638014fb-452f-4197-bb66-6eea073c2853" />

---

## 🚀 What It Does

* Run curator searches by **artist**, **genre**, and **keywords**
* Extract **emails**, submission links, owner names, socials
* Filter by: *has email*, *has link*, *hide contacted*
* Toggle **“marked as contacted”** (saved locally)
* Export clean CRM-ready CSVs
* 100% local: no remote backend, no accounts required
* Optimized for **speed, privacy, and real-world outreach**

---

## 🧱 Under the Hood

* **Python + FastAPI** backend (async)
* **Vanilla JS dashboard** (zero frameworks, fast & lightweight)
* **NDJSON** streaming support for real-time progress
* **PyInstaller** builds for macOS & Windows
* **Local config store** in `~/.curator-finder/config.json`

---

## 🔑 Access System (Keygen → Early Access Gate)

Earlier versions of Curator Finder used a full **cryptographic licensing system**, including:

* Ed25519 public/private keys
* Signed license tokens
* Serial number activation
* Device-bound verification
* Offline license file validation

**The licensing system was a bit too heavy for early access testing.**
So for this Early Access release, the entire licensing layer was replaced with a **beta gate** using  three environment variables:

```env
CF_BETA_CODE=your-code
CF_BETA_CODE_USER=identifier
CF_BETA_EXPIRES=2025-12-31
```
---

## 📦 Running From Source

```bash
git clone https://github.com/jkz1one/curatorfinder
cd curator-finder
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env. .env
```

Then run:

```bash
# Terminal 1 - backend
python server.py

# Terminal 2 - desktop launcher
python desktop.py
```

---

## 🏗️ Building Releases

### macOS

```bash
pyinstaller CuratorFinder.spec
# Output: dist/Curator Finder.app
```

### Windows

```powershell
pyinstaller CuratorFinder.spec
# Output: dist/CuratorFinder.exe
```

Zip and distribute the output.

---

## 📁 Project Layout

```
server.py           # FastAPI backend
desktop.py          # Desktop launcher
dashboard.html      # UI
beta_access.py      # Early Access gate
finder.py           # Spotify + search pipeline
config.py           # Config/environment loader
CuratorFinder.spec  # PyInstaller build spec
requirements.txt
```

User configuration lives at:

```
~/.curator-finder/config.json
```

---

💡 Why This Project Exists

Curator Finder was built to solve a clear problem: artists and teams need reliable, structured curator contact data without slow websites, rate limits, or privacy tradeoffs. Running everything locally keeps the workflow fast, stable, and fully in the user’s control.

The stack is intentionally minimal. A small FastAPI service handles search, enrichment, and cleanup. The dashboard is plain HTML/CSS/JS so it loads instantly and stays transparent. Filtering, marking contacted, and exporting all work in the browser with no accounts, no cloud, and no hidden steps.

---



