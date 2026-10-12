"""SSCAN orchestration layer."""
import nmap
import sys
import time

from .utils import confirm_scan, expand_targets
from .report import export
from .vuln_matcher import match_services
from . import risk


BANNER = r"""
╭─────────────────────────────────────────────────────────────╮
│                                                             │
│   SSCAN  v0.2.0                                             │
│   Network reconnaissance and vulnerability assessment       │
│                                                             │
│   For authorized testing only.                              │
│                                                             │
╰─────────────────────────────────────────────────────────────╯
"""

SUBTLE_BANNER = "\n  SSCAN v0.2.0 — For authorized testing only.\n"


def print_banner(subtle=False):
    print(SUBTLE_BANNER if subtle else BANNER)


# ---------------------------------------------------------------------------
# Argument translation
# ---------------------------------------------------------------------------

def build_engine_args(args):
    a = []

    if args.ping:
        a.append("-sn")
    elif args.list_scan:
        a.append("-sL")
    elif args.syn:
        a.append("-sS")
    elif args.connect:
        a.append("-sT")
    elif args.ack:
        a.append("-sA")
    elif getattr(args, "fin", False):
        a.append("-sF")
    elif getattr(args, "null", False):
        a.append("-sN")
    elif getattr(args, "xmas", False):
        a.append("-sX")
    elif args.udp:
        a.append("-sU")

    if args.ping or args.list_scan:
        pass
    elif getattr(args, "ports", None):
        a.extend(["-p", args.ports])
    elif getattr(args, "top_ports", None):
        a.extend(["--top-ports", str(args.top_ports)])
    else:
        a.extend(["--top-ports", "1000"])

    if args.service:
        a.append("-sV")
        a.append("--version-intensity")
        a.append("2")
    if args.os:
        a.append("-O")
        a.append("--max-os-tries")
        a.append("1")

    # NSE scripts — restrict vuln category to services that actually have scripts
    if getattr(args, "script", None):
        if args.script == "vuln":
            a.append('--script=vuln and (http or ftp or smb or ssh or '
                     'ssl or mysql or mssql or oracle or rdp or vnc)')
        else:
            a.append(f"--script={args.script}")

    a.append(f"-T{args.timing}")
    a.append("--max-retries")
    a.append("1")
    if getattr(args, "rate", None):
        a.extend(["--min-rate", str(args.rate)])

    if args.decoys:
        a.extend(["-D", args.decoys])
    if args.source_port:
        a.extend(["-g", str(args.source_port)])
    if args.fragment:
        a.append("-f")
    if args.randomize:
        a.append("--randomize-hosts")

    return " ".join(a)


build_nmap_args = build_engine_args


# ---------------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------------

def print_host_report(host, hdata, host_findings, assessment):
    state = hdata.get("state", "unknown")
    tier = assessment["host_tier"]
    hrisk = assessment["host_risk"]
    print(f"\n[HOST] {host}  —  state: {state}   RISK: {tier} ({hrisk:.1f})")

    protocols = hdata.get("protocols", {})
    has_ports = any(p for p in protocols.values())

    if not has_ports:
        print("  (no ports detected by SSCAN)")
    else:
        for proto in sorted(protocols.keys()):
            ports = protocols[proto]
            if not ports:
                continue
            print(f"\n  {proto.upper()} ports:")
            print(f"  {'PORT':<8} {'STATE':<10} {'SERVICE':<14} "
                  f"{'VERSION':<28} {'CVEs':<5} {'MAX':<5} RISK")
            print(f"  {'-'*8} {'-'*10} {'-'*14} {'-'*28} {'-'*5} {'-'*5} {'-'*10}")
            for port in sorted(ports.keys()):
                p = ports[port]
                pa = assessment["ports"].get(port, {})
                svc = (p.get("service") or "-")[:14]
                prod = p.get("product") or ""
                ver = p.get("version") or ""
                label = (f"{prod} {ver}".strip() or "-")[:28]
                ccount = pa.get("cve_count", 0)
                maxcvss = pa.get("max_cvss", 0.0)
                ptier = pa.get("top_tier", "NONE")
                print(f"  {port:<8} {p.get('state', '?'):<10} {svc:<14} "
                      f"{label:<28} {ccount:<5} {maxcvss:<5.1f} {ptier}")

    if host_findings:
        print(f"\n  Detected CVEs on {host}:")
        for v in host_findings[:20]:
            cid = v.get("id", "?")
            score = v.get("score", 0.0)
            tier2 = risk.cvss_to_tier(score)
            port = v.get("port", "?")
            desc = (v.get("description", "") or "")[:90]
            print(f"    [{port}] {cid:<16} CVSS {score:>4.1f}  {tier2:<8}  {desc}")
        if len(host_findings) > 20:
            print(f"    ... and {len(host_findings) - 20} more")

    if assessment["open_ports"] > 0:
        print(f"\n  Vulnerability density: "
              f"{assessment['ports_with_cves']} of {assessment['open_ports']} "
              f"open ports have CVEs ({assessment['density_pct']}%)")
        print(f"  High-severity density: "
              f"{assessment['high_severity_pct']}% of open ports have "
              f"CVEs with CVSS >= 7.0")


def print_network_summary(net_assessment, cidr):
    print("\n" + "=" * 74)
    print(f"  NETWORK RISK SUMMARY — {cidr}")
    print("=" * 74)
    print(f"  Hosts scanned:    {net_assessment['hosts_scanned']}")
    print(f"  Hosts up:         {net_assessment['hosts_up']}")
    print(f"  Hosts with CVEs:  {net_assessment['hosts_with_cves']}")
    print(f"  Total open ports: {net_assessment['total_open_ports']}")
    print(f"  Total CVEs:       {net_assessment['total_cves']}")
    print()
    tc = net_assessment["tier_counts"]
    bar_max = max(tc.values()) if tc.values() else 1
    for tier in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"]:
        count = tc.get(tier, 0)
        bar = "█" * int((count / bar_max) * 30) if bar_max else ""
        print(f"    {tier:<9} {count:>3}   {bar}")
    print()
    print(f"  Network risk:   {net_assessment['network_tier']} "
          f"({net_assessment['network_risk']:.1f})")
    print(f"  Density:        {net_assessment['network_density_pct']}% of "
          f"open ports have CVEs")
    print("=" * 74 + "\n")


def print_results(results, findings, elapsed, cidr=None):
    if not results:
        print("\n[!] No hosts found.")
        return

    print("\n" + "=" * 74)
    print("  SSCAN RESULTS")
    print("=" * 74)
    print(f"  Hosts scanned: {len(results)}   Time: {elapsed:.2f}s")
    print("=" * 74)

    net_assessment = risk.assess_network(results, findings)

    for host in sorted(results.keys()):
        assessment = net_assessment["hosts"].get(host)
        if assessment is None:
            assessment = risk.assess_host(results[host], findings.get(host, []))
        print_host_report(host, results[host],
                          findings.get(host, []), assessment)

    if len(results) > 1:
        label = cidr or "(multiple targets)"
        print_network_summary(net_assessment, label)
    else:
        h = next(iter(net_assessment["hosts"].values()))
        print(f"\n  Summary: {h['total_cves']} CVE(s) across "
              f"{h['open_ports']} open port(s), tier {h['host_tier']}.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run_scan(args):
    targets = expand_targets(args.targets)

    cidr = None
    for t in targets:
        if "/" in t:
            cidr = t
            break

    print_banner(subtle=bool(args.output) or args.yes)

    if not args.yes:
        confirm_scan(targets, build_engine_args(args))

    engine_args = build_engine_args(args)
    print(f"[*] SSCAN scanning: {' '.join(targets)}")
    print(f"[*] Mode: {_describe_mode(args)}")
    print("[*] Scanning...")

    nm = nmap.PortScanner()
    start = time.time()

    try:
        nm.scan(hosts=" ".join(targets), arguments=engine_args)
    except KeyboardInterrupt:
        elapsed = time.time() - start
        print(f"\n[!] Scan interrupted by user after {elapsed:.2f}s.")
        sys.exit(130)
    except nmap.PortScannerError as e:
        print(f"[!] Scan engine error: {e}")
        print(f"[!] Engine command was: nmap {engine_args} {' '.join(targets)}")
        return {}, {}

    elapsed = time.time() - start

    results = {}
    for host in nm.all_hosts():
        results[host] = {"state": nm[host].state(), "protocols": {}}
        for proto in nm[host].all_protocols():
            results[host]["protocols"][proto] = {}
            for port in nm[host][proto].keys():
                p = nm[host][proto][port]
                results[host]["protocols"][proto][port] = {
                    "state": p.get("state", ""),
                    "service": p.get("name", ""),
                    "product": p.get("product", ""),
                    "version": p.get("version", ""),
                    "extrainfo": p.get("extrainfo", ""),
                }

    if not results:
        print(f"[!] No hosts returned results after {elapsed:.2f}s.")
        return {}, {}

    # CVE matching
    findings = {}
    script_wants_vuln = bool(getattr(args, "script", None)
                             and "vuln" in args.script)
    vuln_fast = getattr(args, "vuln_fast", False)

    if script_wants_vuln and not vuln_fast:
        print("\n[*] SSCAN: matching detected services against CVEs...")
        findings = match_services(
            results,
            min_cvss=getattr(args, "min_cvss", 0.0),
            use_cache=not getattr(args, "no_cache", False),
        )
    elif vuln_fast:
        print("\n[*] SSCAN: fast mode — NSE script results only, "
              "skipping NVD lookups.")

    print_results(results, findings, elapsed, cidr=cidr)
    export(results, findings, args)
    return results, findings


def _describe_mode(args):
    parts = []
    if args.ping:
        parts.append("ping sweep")
    elif args.list_scan:
        parts.append("list scan")
    elif args.syn:
        parts.append("TCP SYN")
    elif args.connect:
        parts.append("TCP connect")
    elif args.ack:
        parts.append("TCP ACK")
    elif getattr(args, "fin", False):
        parts.append("TCP FIN")
    elif getattr(args, "null", False):
        parts.append("TCP NULL")
    elif getattr(args, "xmas", False):
        parts.append("TCP Xmas")
    elif args.udp:
        parts.append("UDP")
    if args.service:
        parts.append("service detection")
    if args.os:
        parts.append("OS detection")
    if getattr(args, "vuln_fast", False):
        parts.append("vuln-fast")
    elif getattr(args, "script", None):
        parts.append(f"NSE:{args.script}")
    parts.append(f"timing T{args.timing}")
    return ", ".join(parts)