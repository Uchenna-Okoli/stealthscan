"""StealthScan orchestration layer."""
import nmap
import time
import sys

from .utils import confirm_scan, expand_targets
from .report import export
from .vuln_matcher import match_services


BANNER = r"""
╭─────────────────────────────────────────────────────────────╮
│                                                             │
│   StealthScan  v0.1.0                                       │
│   Network reconnaissance and vulnerability matching         │
│                                                             │
│   For authorized testing only.                              │
│                                                             │
╰─────────────────────────────────────────────────────────────╯
"""

SUBTLE_BANNER = "\n  StealthScan v0.1.0 — For authorized testing only.\n"


def print_banner(subtle=False):
    print(SUBTLE_BANNER if subtle else BANNER)


def build_engine_args(args):
    """Translate CLI flags into the engine argument string."""
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
    elif args.udp:
        a.append("-sU")

    # Ports
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

    if getattr(args, "script", None):
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


def print_results(results, findings, elapsed):
    if not results:
        print("\n[!] No hosts found.")
        return

    print("\n" + "=" * 74)
    print("  STEALTHSCAN RESULTS")
    print("=" * 74)
    print(f"  Hosts scanned: {len(results)}   Time: {elapsed:.2f}s")
    print("=" * 74)

    total_open = 0
    total_cves = 0

    for host in sorted(results.keys()):
        hdata = results[host]
        state = hdata.get("state", "unknown")
        print(f"\n[HOST] {host}  —  state: {state}")

        protocols = hdata.get("protocols", {})
        has_ports = any(ports for ports in protocols.values())

        if not has_ports:
            print("  (no ports detected by StealthScan)")
        else:
            for proto in sorted(protocols.keys()):
                ports = protocols[proto]
                if not ports:
                    continue
                print(f"\n  {proto.upper()} ports:")
                print(f"  {'PORT':<8} {'STATE':<12} {'SERVICE':<15} VERSION")
                print(f"  {'-' * 8} {'-' * 12} {'-' * 15} {'-' * 30}")
                for port in sorted(ports.keys()):
                    pdata = ports[port]
                    svc = pdata.get("service", "") or "-"
                    prod = pdata.get("product", "") or ""
                    ver = pdata.get("version", "") or ""
                    label = (f"{prod} {ver}".strip() or "-")[:44]
                    print(f"  {port:<8} {pdata.get('state', '?'):<12} "
                          f"{svc:<15} {label}")
                    if pdata.get("state") == "open":
                        total_open += 1

        host_cves = findings.get(host, []) if findings else []
        if host_cves:
            print(f"\n  CVEs found on {host}:")
            for v in host_cves:
                cid = v.get("id", "?")
                score = v.get("score", 0.0)
                port = v.get("port", "?")
                desc = (v.get("description", "") or "")[:100]
                print(f"    [!] {cid}  (CVSS {score})  port {port}")
                if desc:
                    print(f"        {desc}...")
                total_cves += 1

    print("\n" + "=" * 74)
    print(f"  SUMMARY: {len(results)} host(s), {total_open} open port(s), "
          f"{total_cves} CVE(s)")
    print("=" * 74 + "\n")


def run_scan(args):
    targets = expand_targets(args.targets)

    print_banner(subtle=bool(args.output) or args.yes)

    if not args.yes:
        confirm_scan(targets, build_engine_args(args))

    engine_args = build_engine_args(args)
    print(f"[*] StealthScan scanning: {' '.join(targets)}")
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

    findings = {}
    if getattr(args, "vuln", False):
        print("\n[*] Matching services against known CVEs...")
        findings = match_services(results, min_cvss=args.min_cvss)

    print_results(results, findings, elapsed)
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
    elif args.udp:
        parts.append("UDP")
    if args.service:
        parts.append("service detection")
    if args.os:
        parts.append("OS detection")
    if getattr(args, "script", None):
        parts.append(f"NSE:{args.script}")
    parts.append(f"timing T{args.timing}")
    return ", ".join(parts)