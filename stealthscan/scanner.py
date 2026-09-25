"""Nmap orchestration layer for StealthScan.

This module is responsible for:
  1. Translating StealthScan's CLI flags into an Nmap argument string.
  2. Running Nmap via python-nmap (which shells out to the system nmap binary).
  3. Parsing Nmap's structured output into a plain dict.
  4. Running optional CVE matching.
  5. Printing a human-readable report to the terminal.
  6. Exporting the same data to JSON / CSV / text files.
"""
import nmap

from .utils import confirm_scan, expand_targets
from .report import export
from .vuln_matcher import match_services


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = r"""
  ____  _             _   _     ____
 / ___|| |_ ___  ___ | |_| |_  / ___|  ___ __ _ _ __
 \___ \| __/ _ \/ _ \| __| __| \___ \ / __/ _` | '_ \
  ___) | ||  __/  __/| |_| |_   ___) | (_| (_| | | | |
 |____/ \__\___|\___| \__|\__| |____/ \___\__,_|_| |_|
        Nmap orchestration with CVE matching
"""

SUBTLE_BANNER = "\n  StealthScan v0.1.0 — Nmap orchestration with CVE matching\n"


def print_banner(subtle=False):
    """Print StealthScan's banner.

    Interactive runs get the ASCII art. Scripted runs (--yes or -o given)
    get a one-line header so the output stays clean for logs.
    """
    print(SUBTLE_BANNER if subtle else BANNER)


# ---------------------------------------------------------------------------
# Argument translation
# ---------------------------------------------------------------------------

def build_nmap_args(args):
    """Translate StealthScan's parsed CLI flags into an Nmap argument string.

    Returns a single string, e.g. "-sS -p 1-65535 -sV -T4".
    """
    a = []

    # ---- Scan type ----
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

    # ---- Ports ----
    if getattr(args, "ports", None):
        a.extend(["-p", args.ports])
    elif not (args.ping or args.list_scan):
        a.extend(["-p", "1-65535"])

    # ---- Detection ----
    if args.service:
        a.append("-sV")
    if args.os:
        a.append("-O")

    # ---- NSE scripts ----
    if getattr(args, "script", None):
        a.append(f"--script={args.script}")

    # ---- Timing ----
    a.append(f"-T{args.timing}")

    # ---- Stealth ----
    if args.decoys:
        a.extend(["-D", args.decoys])
    if args.source_port:
        a.extend(["-g", str(args.source_port)])
    if args.fragment:
        a.append("-f")
    if args.randomize:
        a.append("--randomize-hosts")
    if args.rate:
        a.extend(["--min-rate", str(args.rate)])

    return " ".join(a)


# ---------------------------------------------------------------------------
# Terminal output
# ---------------------------------------------------------------------------

def print_results(results, findings):
    """Print a human-readable scan report to the terminal."""
    if not results:
        print("\n[!] No hosts returned any results.")
        print("[!] Check that the target is reachable and that you ran with sudo.")
        return

    print("\n" + "=" * 74)
    print("  STEALTHSCAN RESULTS")
    print("=" * 74)

    for host in sorted(results.keys()):
        hdata = results[host]
        state = hdata.get("state", "unknown")
        print(f"\n[HOST] {host}  —  state: {state}")

        protocols = hdata.get("protocols", {})
        if not protocols:
            print("  (no ports reported by Nmap)")
        else:
            for proto in sorted(protocols.keys()):
                ports = protocols[proto]
                if not ports:
                    print(f"  {proto.upper()}: no ports")
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
                    print(
                        f"  {port:<8} {pdata.get('state', '?'):<12} "
                        f"{svc:<15} {label}"
                    )

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

    print("\n" + "=" * 74 + "\n")


# ---------------------------------------------------------------------------
# Main scan entry point
# ---------------------------------------------------------------------------

def run_scan(args):
    """Execute a scan based on parsed CLI args."""
    targets = expand_targets(args.targets)

    # Banner — subtle if scripted
    print_banner(subtle=bool(args.output) or args.yes)

    # Confirmation gate
    if not args.yes:
        confirm_scan(targets, build_nmap_args(args))

    # Run Nmap
    nm = nmap.PortScanner()
    nmap_str = build_nmap_args(args)
    print(f"[*] Running: nmap {nmap_str} {' '.join(targets)}")
    print("[*] Scanning... (this can take a while for large port ranges)")

    try:
        nm.scan(hosts=" ".join(targets), arguments=nmap_str)
    except nmap.PortScannerError as e:
        print(f"[!] Nmap error: {e}")
        print(f"[!] Command was: nmap {nmap_str} {' '.join(targets)}")
        return {}, {}

    # Extract results
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
        print(f"[!] No hosts returned results.")
        print(f"[!] Nmap command was: nmap {nmap_str} {' '.join(targets)}")
        return {}, {}

    # CVE matching
    findings = {}
    if getattr(args, "vuln", False):
        print("\n[*] Running CVE lookup against NVD...")
        findings = match_services(results, min_cvss=args.min_cvss)

    # Output
    print_results(results, findings)
    export(results, findings, args)

    return results, findings