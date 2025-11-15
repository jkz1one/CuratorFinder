---

# **Curator Finder **

### Playlist Curator Search Engine • Local-First • Desktop App (macOS & Windows)

Curator Finder is a **local-first playlist intelligence tool** for artists and managers.
It scrapes, filters, enriches, and organizes curator contact data — **all on-device**, no cloud, no SaaS, no tracking.

Built with a **FastAPI backend**, a **custom Spotify ingestion pipeline**, and a clean, responsive **dashboard UI** packaged into a cross-platform desktop app.

---

## 🚀 What It Does

* Run curator searches by **artist**, **genre**, and **keywords**
* Extract **emails**, **submission links**, **owner names**, **socials**
* Filter by: *has email*, *has link*, *hide contacted*
* Toggle **“marked as contacted”** (saved locally)
* Export **clean CRM-ready CSVs**
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

This was fully implemented and functional.

**The licensing system was a bit too heavy for early access testing.**
So for this Early Access release, the entire licensing layer was replaced with a **simple, frictionless beta gate** using just three environment variables:

```env
CF_BETA_CODE=your-code
CF_BETA_CODE_USER=identifier
CF_BETA_EXPIRES=2025-12-31
```

This keeps distribution controlled while eliminating onboarding friction.

It also demonstrates the ability to build **complex licensing**, and the judgment to simplify when a product stage demands it.

---

## 📦 Running From Source

```bash
git clone https://github.com/<you>/curator-finder
cd curator-finder
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
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

## 💡 Why This Project Matters

This repo shows end-to-end product engineering ability:

* **Full-stack delivery** (backend → UI → desktop packaging)
* **Local-first architecture** (fast, private, zero infrastructure)
* **Practical UX design** focused on workflow efficiency
* **Real distribution** (macOS + Windows binaries)
* **Ability to build complex systems** (cryptographic licensing)
* **Ability to simplify strategically** (beta access gate)
* **Ability to ship**
  — not just experiment

This is a compact but production-ready example of designing, engineering, and delivering a complete tool independently.

---

If you want a **shorter recruiter-facing version**, a **landing page version**, or a **project badge/branding logo**, I can generate that too.
