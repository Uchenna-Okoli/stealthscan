"""CVE matching via the NVD API."""
import time
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_nvd(product, version, api_key=None):
    params = {"keywordSearch": f"{product} {version}".strip(),
              "resultsPerPage": 20}
    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    try:
        r = requests.get(NVD_API, params=params, headers=headers, timeout=30)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] NVD error: {e}")
        return []

    out = []
    for item in r.json().get("vulnerabilities", []):
        cve = item["cve"]
        score, severity = 0.0, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m = cve.get("metrics", {}).get(key)
            if m:
                score = m[0]["cvssData"].get("baseScore", 0.0)
                severity = m[0]["cvssData"].get("baseSeverity", "UNKNOWN")
                break
        out.append({
            "id": cve["id"],
            "description": cve["descriptions"][0]["value"][:200],
            "score": score,
            "severity": severity,
        })
    time.sleep(0.6)  # NVD rate limit: 5 requests / 30 s without an API key
    return out


def match_services(results, min_cvss=0.0, api_key=None):
    findings = {}
    for host, hdata in results.items():
        findings[host] = []
        for proto, ports in hdata["protocols"].items():
            for port, pdata in ports.items():
                if pdata["state"] != "open" or not pdata["product"]:
                    continue
                label = f"{pdata['product']} {pdata['version']}".strip()
                print(f"[*] CVE lookup: {host}:{port} ({label})")
                for cve in query_nvd(pdata["product"], pdata["version"], api_key):
                    if cve["score"] >= min_cvss:
                        findings[host].append({"port": port, "service": label, **cve})
    return findings