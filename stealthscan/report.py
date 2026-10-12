"""Report generation for SSCAN."""
import csv
import json
from datetime import datetime

from . import risk


def export(results, findings, args):
    base = args.output or "sscan_report"
    formats = ["json", "csv", "text"] if args.format == "all" else [args.format]

    written = []
    for fmt in formats:
        if fmt == "json":
            written.append(_write_json(base, results, findings))
        elif fmt == "csv":
            written.append(_write_csv(base, results, findings))
        elif fmt == "text":
            written.append(_write_text(base, results, findings))

    if written:
        print(f"[*] Report written to: {', '.join(written)}")


def _write_json(base, results, findings):
    path = f"{base}.json"
    net = risk.assess_network(results, findings)
    payload = {
        "tool": "SSCAN",
        "version": "0.2.0",
        "generated": datetime.utcnow().isoformat() + "Z",
        "scan": results,
        "vulnerabilities": findings,
        "risk": {
            "network_tier": net["network_tier"],
            "network_risk": net["network_risk"],
            "network_density_pct": net["network_density_pct"],
            "hosts": {h: {
                "host_tier": a["host_tier"],
                "host_risk": a["host_risk"],
                "density_pct": a["density_pct"],
                "high_severity_pct": a["high_severity_pct"],
                "total_cves": a["total_cves"],
                "open_ports": a["open_ports"],
            } for h, a in net["hosts"].items()},
        },
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    return path


def _write_csv(base, results, findings):
    path = f"{base}.csv"
    net = risk.assess_network(results, findings)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["host", "host_risk", "host_tier",
                    "proto", "port", "state", "service",
                    "product", "version",
                    "cve", "cvss", "cve_severity", "port_tier"])
        for host, h in results.items():
            assessment = net["hosts"].get(host, {})
            h_tier = assessment.get("host_tier", "NONE")
            h_risk = assessment.get("host_risk", 0.0)
            for proto, ports in h["protocols"].items():
                for port, p in ports.items():
                    port_assess = assessment.get("ports", {}).get(port, {})
                    port_tier = port_assess.get("top_tier", "NONE")
                    matched = [v for v in findings.get(host, [])
                               if v["port"] == port]
                    if not matched:
                        w.writerow([host, h_risk, h_tier,
                                    proto, port, p["state"], p["service"],
                                    p["product"], p["version"],
                                    "", "", "", port_tier])
                    for v in matched:
                        w.writerow([host, h_risk, h_tier,
                                    proto, port, p["state"], p["service"],
                                    p["product"], p["version"],
                                    v["id"], v["score"], v["severity"],
                                    port_tier])
    return path


def _write_text(base, results, findings):
    path = f"{base}.txt"
    net = risk.assess_network(results, findings)
    with open(path, "w") as f:
        f.write("SSCAN Report\n")
        f.write("=" * 74 + "\n")
        f.write(f"Generated: {datetime.utcnow().isoformat()}Z\n")
        f.write("=" * 74 + "\n")

        for host in sorted(results.keys()):
            h = results[host]
            a = net["hosts"].get(host, {})
            tier = a.get("host_tier", "NONE")
            hrisk = a.get("host_risk", 0.0)
            f.write(f"\n[HOST] {host}  —  state: {h['state']}   "
                    f"RISK: {tier} ({hrisk:.1f})\n")

            for proto, ports in h["protocols"].items():
                for port in sorted(ports.keys()):
                    p = ports[port]
                    pa = a.get("ports", {}).get(port, {})
                    f.write(f"  {port}/{proto}  {p['state']:<10}  "
                            f"{p['service']:<12}  "
                            f"{p['product']} {p['version']}  "
                            f"[{pa.get('cve_count', 0)} CVEs, "
                            f"max CVSS {pa.get('max_cvss', 0.0):.1f}, "
                            f"{pa.get('top_tier', 'NONE')}]\n")

            for v in findings.get(host, []):
                f.write(f"    [!] {v['id']} (CVSS {v['score']})  "
                        f"{v['severity']}  {v['description'][:80]}...\n")

        # Network summary
        if len(results) > 1:
            f.write("\n" + "=" * 74 + "\n")
            f.write("NETWORK RISK SUMMARY\n")
            f.write("=" * 74 + "\n")
            f.write(f"Hosts scanned:    {net['hosts_scanned']}\n")
            f.write(f"Hosts up:         {net['hosts_up']}\n")
            f.write(f"Hosts with CVEs:  {net['hosts_with_cves']}\n")
            f.write(f"Total CVEs:       {net['total_cves']}\n")
            f.write(f"Network risk:     {net['network_tier']} "
                    f"({net['network_risk']:.1f})\n")
            f.write(f"Density:          {net['network_density_pct']}%\n")
    return path