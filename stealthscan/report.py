"""Output exporters."""
import csv
import json


def export(results, findings, args):
    base = args.output or "stealthscan_report"
    formats = ["json", "csv", "text"] if args.format == "all" else [args.format]

    for fmt in formats:
        if fmt == "json":
            with open(f"{base}.json", "w") as f:
                json.dump({"scan": results, "vulnerabilities": findings}, f, indent=2)
        elif fmt == "csv":
            with open(f"{base}.csv", "w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["host", "proto", "port", "state", "service",
                            "product", "version", "cve", "cvss", "severity"])
                for host, h in results.items():
                    for proto, ports in h["protocols"].items():
                        for port, p in ports.items():
                            matched = [v for v in findings.get(host, [])
                                       if v["port"] == port]
                            if not matched:
                                w.writerow([host, proto, port, p["state"],
                                            p["service"], p["product"],
                                            p["version"], "", "", ""])
                            for v in matched:
                                w.writerow([host, proto, port, p["state"],
                                            p["service"], p["product"],
                                            p["version"], v["id"],
                                            v["score"], v["severity"]])
        elif fmt == "text":
            with open(f"{base}.txt", "w") as f:
                for host, h in results.items():
                    f.write(f"\n=== {host} ({h['state']}) ===\n")
                    for proto, ports in h["protocols"].items():
                        for port, p in ports.items():
                            f.write(f"  {port}/{proto}  {p['state']}  "
                                    f"{p['product']} {p['version']}\n")
                    for v in findings.get(host, []):
                        f.write(f"    [!] {v['id']} (CVSS {v['score']}): "
                                f"{v['description'][:80]}...\n")