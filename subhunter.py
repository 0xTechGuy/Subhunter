#!/usr/bin/env python3
"""
subhunter.py – Discover, verify, and crawl JavaScript files from live sub-domains.

CLI
----
python subhunter.py <root-domain>

Example
-------
python subhunter.py tesla.com
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import json
import logging
import re
import socket
import sys
import time
from pathlib import Path
from typing import Iterable, List, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

###############################################################################
# Configuration
###############################################################################

RISKY_KEYWORDS: set[str] = {
    "facebook", "paypal", "google", "instagram", "microsoft", "apple"
}

DEMO_SUBDOMAINS: list[str] = [
    "developer.mozilla.org",
    "docs.python.org",
    "api.github.com",
    "www.wikipedia.org",
]

HEADERS = {"User-Agent": "subhunter/2.0 (+https://github.com/your-handle)"}

###############################################################################
# Logging
###############################################################################

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("subhunter")

# Suppress urllib3 and requests connection/certificate warnings
logging.getLogger("urllib3").setLevel(logging.ERROR)
logging.getLogger("requests.packages.urllib3").setLevel(logging.ERROR)

###############################################################################
# HTTP session helpers
###############################################################################

def build_session() -> requests.Session:
    """Return a requests.Session with sane retry defaults."""
    retry_policy = Retry(
        total=5,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET", "HEAD"),
    )
    adapter = HTTPAdapter(max_retries=retry_policy, pool_maxsize=25)
    sess = requests.Session()
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    sess.headers.update(HEADERS)
    return sess

###############################################################################
# Utility functions
###############################################################################

def suspicious(host: str) -> bool:
    """True if host looks phishy or unusually long."""
    host_l = host.lower()
    if any(
        kw in host_l and not host_l.endswith(kw)  # google-fake.com
        for kw in RISKY_KEYWORDS
    ):
        return True
    return host.count("-") > 3 or len(host) > 100

def resolve(host: str) -> bool:
    """DNS resolve test (no banner grabbing)."""
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False

def extract_js(html: str, base: str) -> Set[str]:
    """Return absolute JS URLs found in HTML."""
    js_links: set[str] = set()
    for match in re.findall(r'src=["\']([^"\']+\.js)["\']', html, flags=re.I):
        full = match if match.startswith(("http://", "https://")) else f"http://{base}/{match.lstrip('/')}"
        js_links.add(full)
    return js_links

###############################################################################
# crt.sh queries
###############################################################################

def fetch_from_crtsh(domain: str, sess: requests.Session) -> List[str]:
    log.info("Waiting 3 seconds before querying crt.sh to avoid rate limiting…")
    time.sleep(3)  # Be polite to crt.sh
    log.info("Querying crt.sh for %s …", domain)
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        resp = sess.get(url, timeout=60)  # Increased timeout to 60 seconds
        if resp.status_code == 503:
            log.error("crt.sh is rate limiting or overloaded (503). Please wait a few minutes and try again.")
            time.sleep(10)  # Wait a bit before returning, in case user is looping
            return []
        resp.raise_for_status()
        seen: set[str] = set()
        for entry in resp.json():
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lower()
                if "*" in name or suspicious(name) or not name.endswith(domain):
                    continue
                seen.add(name)
        return sorted(seen)
    except Exception as exc:
        log.warning("crt.sh request failed: %s", exc)
        return []

###############################################################################
# Core workflow
###############################################################################

def probe_http(host: str, sess: requests.Session) -> bool:
    """Return True if host answers with 200 OK on port 80 or 443."""
    for scheme in ("https://", "http://"):
        try:
            r = sess.get(f"{scheme}{host}", timeout=5, allow_redirects=True)  # Lowered timeout to 5s
            if r.status_code == 200:
                return True
        except requests.RequestException:
            continue
    return False

def gather_js(host: str, sess: requests.Session) -> Set[str]:
    """Return JS URLs discovered on host (best-effort)."""
    try:
        r = sess.get(f"http://{host}", timeout=10)
        if r.ok:
            return extract_js(r.text, host)
    except requests.RequestException:
        pass
    return set()

###############################################################################
# File helpers
###############################################################################

def write_lines(path: Path, lines: Iterable[str]) -> None:
    lines = list(lines)
    path.write_text("\n".join(sorted(set(lines))) + "\n", encoding="utf-8")
    log.info("Wrote %s (%d lines)", path, len(lines))

###############################################################################
# CLI parsing
###############################################################################

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Fast sub-domain enumerator.")
    p.add_argument(
        "domain",
        help="Root domain to scan (e.g. tesla.com). "
        "Use DEMO to fetch hard-coded always-up sub-domains instead.",
    )
    p.add_argument(
        "-o",
        "--outdir",
        type=Path,
        default=Path.cwd(),
        help="Directory to write results (default: current dir).",
    )
    p.add_argument(
        "--workers",
        type=int,
        default=20,
        help="Max parallel HTTP probes (default: 20).",
    )
    return p.parse_args()

###############################################################################
# Main
###############################################################################

def main() -> None:
    args = parse_args()
    sess = build_session()

    # ------------------------------------------------------------------ enum --
    if args.domain.upper() == "DEMO":
        subdomains = DEMO_SUBDOMAINS
    else:
        subdomains = fetch_from_crtsh(args.domain, sess)

    if not subdomains:
        log.error("No sub-domains discovered – aborting.")
        sys.exit(1)

    # ---------------------- DNS resolve filter before HTTP checks ------------
    log.info("Resolving subdomains before HTTP checks…")
    resolved = [sub for sub in subdomains if resolve(sub)]
    log.info("Resolved %d/%d subdomains.", len(resolved), len(subdomains))

    # --------------------------------------------------------------- probing --
    log.info("Checking which resolved hosts are live (HTTP 200)…")
    live: list[str] = []
    with futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for host, ok in zip(
            resolved, pool.map(lambda h: probe_http(h, sess), resolved)
        ):
            if ok:
                live.append(host)

    # --------------------------------------------------------- JS extraction --
    log.info("Extracting JavaScript URLs …")
    js_links: set[str] = set()
    with futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for links in pool.map(lambda h: gather_js(h, sess), live):
            js_links.update(links)

    # ----------------------------------------------------------------- output --
    out = args.outdir / args.domain.replace(".", "_")
    out.mkdir(parents=True, exist_ok=True)

    write_lines(out / "subs.txt", subdomains)
    write_lines(out / "live.txt", live)
    write_lines(out / "js.txt", js_links)

    # Also persist as JSON for programmatic use.
    (out / "result.json").write_text(
        json.dumps(
            {"all_subdomains": subdomains, "live_subdomains": live, "js_files": sorted(js_links)},
            indent=2,
        ),
        encoding="utf-8",
    )

    log.info("Finished! Results saved in %s", out)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log.warning("\n[!] Interrupted by user. Exiting gracefully.")
        sys.exit(0)
