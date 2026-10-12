"""CVE matching via the NVD API.

Strategy: aggressive + smart + cached.

  aggressive — query NVD for every detected service+version
  smart      — deduplicate identical lookups within a run; skip
               services with no version info
  cached     — persist results to ~/.cache/sscan/cve_cache.json so
               the same lookup returns instantly on subsequent runs
               for up to 30 days
"""
import json
import os
import time
from datetime import datetime, timedelta

import requests


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_DIR = os.path.expanduser("~/.cache/sscan")
CACHE_FILE = os.path.join(CACHE_DIR, "cve_cache.json")
CACHE_TTL_DAYS = 30
RATE_LIMIT_DELAY = 0.6  # NVD allows 5 req / 30 s without a key


# ---------------------------------------------------------------------------
# Cache management
# ---------------------------------------------------------------------------

def _load_cache():
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache):
    os.makedirs(CACHE_DIR, mode=0o700, exist_ok=True)
    tmp = CACHE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(cache, f, indent=2)
    os.replace(tmp, CACHE_FILE)


def _cache_key(product, version):
    return f"{product.strip().lower()}::{version.strip().lower()}"


def _is_fresh(entry):
    try:
        cached_at = datetime.fromisoformat(entry.get("cached_at", ""))
    except ValueError:
        return False
    return datetime.utcnow() - cached_at < timedelta(days=CACHE_TTL_DAYS)


# ---------------------------------------------------------------------------
# NVD query
# ---------------------------------------------------------------------------

def _query_nvd(product, version, api_key=None):
    """Query NVD for CVEs matching a product+version. Returns a list of dicts."""
    params = {
        "keywordSearch": f"{product} {version}".strip(),
        "resultsPerPage": 20,
    }
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        r = requests.get(NVD_API, params=params, headers=headers, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] NVD lookup failed: {e}")
        return []

    out = []
    for item in r.json().get("vulnerabilities", []):
        cve = item["cve"]
        score = 0.0
        severity = "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m = cve.get("metrics", {}).get(key)
            if m:
                score = float(m[0]["cvssData"].get("baseScore", 0.0))
                severity = m[0]["cvssData"].get("baseSeverity", "UNKNOWN")
                break
        out.append({
            "id": cve["id"],
            "description": (cve["descriptions"][0]["value"][:300]
                            if cve.get("descriptions") else ""),
            "score": score,
            "severity": severity,
        })
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def match_services(results, min_cvss=0.0, api_key=None, use_cache=True):
    """For every open port with a detected product/version, query NVD for CVEs.

    Returns {host: [ {port, service, id, description, score, severity}, ... ]}
    """
    cache = _load_cache() if use_cache else {}
    seen_in_run = {}   # dedup within this run

    findings = {}
    cache_dirty = False

    for host, hdata in results.items():
        findings[host] = []
        for proto, ports in hdata["protocols"].items():
            for port, pdata in ports.items():
                if pdata.get("state") != "open":
                    continue

                product = (pdata.get("product") or "").strip()
                version = (pdata.get("version") or "").strip()

                # Smart skip: no product info → nothing to match against
                if not product:
                    continue

                label = f"{product} {version}".strip()
                key = _cache_key(product, version)

                # Cache hit
                if use_cache and key in cache and _is_fresh(cache[key]):
                    cves = cache[key]["cves"]
                    source = "cache"
                # Dedup within this run
                elif key in seen_in_run:
                    cves = seen_in_run[key]
                    source = "dedup"
                # Live query
                else:
                    print(f"[*] SSCAN: checking {host}:{port} ({label}) for CVEs...")
                    cves = _query_nvd(product, version, api_key)
                    seen_in_run[key] = cves
                    if use_cache:
                        cache[key] = {
                            "cached_at": datetime.utcnow().isoformat(),
                            "product": product,
                            "version": version,
                            "cves": cves,
                        }
                        cache_dirty = True
                    source = "live"
                    time.sleep(RATE_LIMIT_DELAY)

                for cve in cves:
                    if cve["score"] < min_cvss:
                        continue
                    findings[host].append({
                        "port": port,
                        "service": label,
                        "source": source,
                        **cve,
                    })

    if cache_dirty:
        try:
            _save_cache(cache)
        except OSError as e:
            print(f"[!] Could not write CVE cache: {e}")

    return findings