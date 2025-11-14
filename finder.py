#!/usr/bin/env python3
# finder.py — personal-use curator contact finder (Spotify bios + linked pages)
# Saves ONLY playlists that have an email or a submission/contact-style link.
# De-dupes by curator so each curator appears at most once.
# Also writes CSV next to JSON.

import os
import re
import time
import json
import csv
import argparse
import concurrent.futures
from typing import List, Dict, Any, Iterable, Optional

import requests
from bs4 import BeautifulSoup
import spotipy
from spotipy.oauth2 import SpotifyClientCredentials

# -------------------- CONFIG --------------------
USER_AGENT = "KeazeCuratorFinder/1.3"
SPOTIFY_PAGE_SIZE = 50
MAX_OFFSETS_PER_QUERY = 20       # up to 1000 playlists per query
MAX_WORKERS_EXTERNAL = 4
REQUEST_TIMEOUT = 10
PAUSE_BETWEEN_EXTERNAL = 0.0

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
HTTP_LINK_RE = re.compile(r"https?://[^\s)]+")
MAILTO_RE = re.compile(r"mailto:([^\s\"'>)]+)", re.IGNORECASE)
CONTEXT_WORDS = ("submit", "submission", "contact", "book", "press", "demo")

CONTACT_LINK_HINTS = (
    "submit", "submission", "contact", "demo", "press", "book",
    "linktr.ee", "beacons.ai", "carrd.co", "notion.so",
    "google.com/forms", "docs.google.com/forms", "typeform.com",
    "form.jotform.com", "wufoo.com", "tally.so", "airtable.com"
)

SKIP_OWNER_CONTAINS = ("spotify", "filtr", "topsify", "digster", "umg", "sony", "warnermusic", "warner")

# -------------------- HELPERS --------------------
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

def write_csv(json_data, csv_path):
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

# -------------------- MAIN --------------------
def main():
    ap = argparse.ArgumentParser(description="Find curator contacts from Spotify playlist bios (personal use).")
    ap.add_argument("--artists", nargs="*", default=[], help="Artist names to search")
    ap.add_argument("--keywords", nargs="*", default=[], help="Keywords/moods/phrases")
    ap.add_argument("--genres", nargs="*", default=[], help="Genres/micro-genres")
    ap.add_argument("--target", type=int, default=100, help="Stop after this many unique emails")
    ap.add_argument("--out", default="curators.json", help="Output JSON file")
    args = ap.parse_args()

    queries = list(dict.fromkeys(args.artists + args.keywords + args.genres))
    for g in args.genres:
        for k in args.keywords:
            combo = f"{g} {k}"
            if combo not in queries:
                queries.append(combo)

    sp = spotipy.Spotify(auth_manager=SpotifyClientCredentials(
        client_id=os.environ.get("SPOTIFY_CLIENT_ID"),
        client_secret=os.environ.get("SPOTIFY_CLIENT_SECRET")
    ))

    results, playlists_seen, emails_seen, curators_seen = [], set(), set(), set()

    for q in queries:
        print(f"[search] {q}")
        for pl in discover_playlists(sp, q, MAX_OFFSETS_PER_QUERY):
            if not isinstance(pl, dict):
                continue

            pid = (pl.get("id") or "").strip()
            if not pid or pid in playlists_seen:
                continue
            playlists_seen.add(pid)

            owner_raw = pl.get("owner")
            owner = owner_raw if isinstance(owner_raw, dict) else {}
            if is_editorial_owner(owner):
                continue

            name = pl.get("name") or ""
            url = (pl.get("external_urls") or {}).get("spotify", "")
            desc = pl.get("description") or ""
            owner_name = owner.get("display_name") or owner.get("id") or ""
            owner_handle = owner.get("id") or ""
            owner_url = (owner.get("external_urls") or {}).get("spotify", "")

            emails = extract_emails_with_context(desc)
            for addr in MAILTO_RE.findall(desc):
                addr = addr.strip()
                if addr and not addr.lower().endswith("@spotify.com"):
                    if all(addr != x["value"] for x in emails):
                        emails.append({"value": addr, "context": "mailto in description"})

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
                continue

            ckey = curator_key_from(owner_handle, owner_url, owner_name)
            if ckey and ckey in curators_seen:
                continue
            if ckey:
                curators_seen.add(ckey)

            new_count = 0
            for e in emails:
                if e["value"] not in emails_seen:
                    emails_seen.add(e["value"])
                    new_count += 1

            print(f"  • {name} ({owner_name}) → {('+%d new emails ' % new_count) if new_count else ''}[contacts: {'email' if has_email else ''}{' + link' if has_contactish_link else ''}]")

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

            if len(emails_seen) >= args.target:
                with open(args.out, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
                csv_path = args.out.replace(".json", ".csv")
                write_csv(results, csv_path)
                print(f"\n[done] hit target of {args.target} unique emails")
                print(f"       wrote {len(results)} curator entries to {args.out} and {csv_path}")
                return

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    csv_path = args.out.replace(".json", ".csv")
    write_csv(results, csv_path)
    print(f"\n[done] wrote {len(results)} curator entries to {args.out} and {csv_path}")
    print(f"       unique emails collected: {len(emails_seen)}")

if __name__ == "__main__":
    main()
