"""Risk assessment for SSCAN.

Computes CVSS-based risk ratings for individual ports, hosts, and
entire networks. Also computes vulnerability density — the fraction
of open ports that have known CVEs.

This module is deliberately independent of Nmap. It works on the
plain dicts produced by scanner.py.
"""


# ---------------------------------------------------------------------------
# Risk tiers
# ---------------------------------------------------------------------------

# CVSS v3 qualitative severity ratings (per FIRST.org spec).
# Scores in the range [low, high] map to the named tier.

TIERS = [
    ("CRITICAL", 9.0, 10.0),
    ("HIGH",     7.0,  8.9),
    ("MEDIUM",   4.0,  6.9),
    ("LOW",      0.1,  3.9),
    ("NONE",     0.0,  0.0),
]


def cvss_to_tier(score):
    """Map a CVSS base score to a severity tier name."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"
    for name, low, high in TIERS:
        if low <= s <= high:
            return name
    return "UNKNOWN"


def tier_rank(tier):
    """Numeric rank for a tier, so we can compare severities.

    Higher rank = more severe. CRITICAL=5, HIGH=4, MEDIUM=3, LOW=2, NONE=1.
    """
    order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "NONE": 1}
    return order.get(tier, 0)


# ---------------------------------------------------------------------------
# Per-port assessment
# ---------------------------------------------------------------------------

def assess_port(port_cves):
    """Compute the risk for a single port from its CVE list.

    `port_cves` is a list of dicts, each having at least:
        {"id": "CVE-...", "score": 7.5, "severity": "HIGH", ...}

    Returns a dict:
        {
            "port": int,
            "cve_count": int,
            "max_cvss": float,
            "top_tier": "HIGH" | "MEDIUM" | ...,
            "risk": float,           # the max CVSS, or 0.0 if none
            "cves": [...],           # sorted by CVSS descending
        }
    """
    if not port_cves:
        return {
            "port": None,
            "cve_count": 0,
            "max_cvss": 0.0,
            "top_tier": "NONE",
            "risk": 0.0,
            "cves": [],
        }

    sorted_cves = sorted(port_cves,
                         key=lambda v: float(v.get("score", 0.0)),
                         reverse=True)
    max_cvss = float(sorted_cves[0].get("score", 0.0))
    top_tier = cvss_to_tier(max_cvss)

    return {
        "port": sorted_cves[0].get("port"),
        "cve_count": len(sorted_cves),
        "max_cvss": max_cvss,
        "top_tier": top_tier,
        "risk": max_cvss,
        "cves": sorted_cves,
    }


# ---------------------------------------------------------------------------
# Per-host assessment
# ---------------------------------------------------------------------------

def assess_host(host_data, host_findings):
    """Compute risk for an entire host.

    `host_data`  — the dict from scanner.py's results: {"state": ..., "protocols": {...}}
    `host_findings` — the CVE list for this host: [{"port": 21, "id": "...", ...}, ...]

    Returns a dict:
        {
            "host_risk": float,          # max CVSS across all ports
            "host_tier": "HIGH" | ...,
            "ports": { 21: {...}, 22: {...}, ... },
            "open_ports": int,
            "ports_with_cves": int,
            "density_pct": float,        # ports_with_cves / open_ports * 100
            "high_severity_pct": float,  # ports with CVSS >= 7.0 / open_ports * 100
            "total_cves": int,
        }
    """
    # Group CVEs by port
    by_port = {}
    for cve in (host_findings or []):
        port = cve.get("port")
        if port is None:
            continue
        by_port.setdefault(port, []).append(cve)

    # Enumerate open ports
    open_ports = []
    for proto, ports in host_data.get("protocols", {}).items():
        for port, pdata in ports.items():
            if pdata.get("state") == "open":
                open_ports.append(port)

    # Assess each port
    port_assessments = {}
    for port in open_ports:
        port_assessments[port] = assess_port(by_port.get(port, []))

    # Host-level aggregation
    if not port_assessments:
        host_risk = 0.0
    else:
        host_risk = max(a["risk"] for a in port_assessments.values())

    host_tier = cvss_to_tier(host_risk)

    total_open = len(open_ports)
    ports_with_cves = sum(1 for a in port_assessments.values()
                          if a["cve_count"] > 0)
    high_sev_ports = sum(1 for a in port_assessments.values()
                         if a["max_cvss"] >= 7.0)

    density_pct = (ports_with_cves / total_open * 100.0) if total_open else 0.0
    high_severity_pct = (high_sev_ports / total_open * 100.0) if total_open else 0.0

    total_cves = sum(a["cve_count"] for a in port_assessments.values())

    return {
        "host_risk": host_risk,
        "host_tier": host_tier,
        "ports": port_assessments,
        "open_ports": total_open,
        "ports_with_cves": ports_with_cves,
        "density_pct": round(density_pct, 1),
        "high_severity_pct": round(high_severity_pct, 1),
        "total_cves": total_cves,
    }


# ---------------------------------------------------------------------------
# Network-level assessment (for subnet scans)
# ---------------------------------------------------------------------------

def assess_network(results, findings):
    """Compute aggregate risk for a subnet scan.

    `results`  — the full results dict {host: host_data, ...}
    `findings` — the full findings dict {host: [cve, ...], ...}

    Returns a dict with counts and a network-wide risk tier.
    """
    if not results:
        return {
            "hosts_scanned": 0,
            "hosts_up": 0,
            "hosts_with_cves": 0,
            "network_risk": 0.0,
            "network_tier": "NONE",
            "tier_counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                            "LOW": 0, "CLEAN": 0},
            "total_open_ports": 0,
            "total_cves": 0,
            "network_density_pct": 0.0,
            "hosts": {},
        }

    hosts_up = 0
    hosts_with_cves = 0
    total_open = 0
    total_cves = 0
    max_host_risk = 0.0
    per_host = {}

    for host, hdata in results.items():
        if hdata.get("state") != "up":
            continue
        hosts_up += 1

        host_assessment = assess_host(hdata, findings.get(host, []))
        per_host[host] = host_assessment

        if host_assessment["total_cves"] > 0:
            hosts_with_cves += 1

        total_open += host_assessment["open_ports"]
        total_cves += host_assessment["total_cves"]
        max_host_risk = max(max_host_risk, host_assessment["host_risk"])

    # Count hosts by tier
    tier_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0}
    for h in per_host.values():
        t = h["host_tier"]
        if t == "NONE":
            tier_counts["CLEAN"] += 1
        elif t in tier_counts:
            tier_counts[t] += 1

    network_tier = cvss_to_tier(max_host_risk)
    if network_tier == "NONE" and hosts_up > 0:
        network_tier = "CLEAN"

    # Network-level density: total CVEs on network / total open ports
    network_density = (total_cves / total_open * 100.0) if total_open else 0.0

    return {
        "hosts_scanned": len(results),
        "hosts_up": hosts_up,
        "hosts_with_cves": hosts_with_cves,
        "network_risk": max_host_risk,
        "network_tier": network_tier,
        "tier_counts": tier_counts,
        "total_open_ports": total_open,
        "total_cves": total_cves,
        "network_density_pct": round(network_density, 1),
        "hosts": per_host,
    }