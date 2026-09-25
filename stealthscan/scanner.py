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
# 1. Argument translation
# ---------------------------------------------------------------------------

def build_nmap_args(args):
    """Translate StealthScan's parsed CLI flags into an Nmap argument string.

    Nmap is the actual scanning engine — this function just decides which
    of Nmap's flags to pass through based on what the user asked for.

    Returns a single string, e.g. "-sS -p 1-65535 -sV -T4".
    """
    a = []

    # ---- Scan type (mutually exclusive — enforced in cli.py) ----
    if args.ping:
        a.append("-sn")           # ping / host discovery only
    elif args.list_scan:
        a.append("-sL")           # list scan — resolve targets, send no packets
    elif args.syn:
        a.append("-sS")           # TCP SYN (stealth) scan
    elif args.connect:
        a.append("-sT")           # TCP connect scan
    elif args.ack:
        a.append("-sA")           # TCP ACK scan (firewall mapping)
    elif args.udp:
        a.append("-sU")           # UDP scan

    # ---- Port specification ----
    # Precedence:
    #   1. If user gave -p SPEC, use that literally.
    #   2. Otherwise, if this is a scan that uses ports, default to full range.
    #   3. If it's a ping or list scan, no -p flag at all.
    if getattr(args, "ports", None):
        a.extend(["-p", args.ports])
    elif not (args.ping or args.list_scan):
        a.extend(["-p", "1-65535"])

    # ---- Detection ----
    if args.service:
        a.append("-sV")           # service/version detection
    if args.os:
        a.append("-O")            # OS detection

    # ---- NSE scripts (vuln, vulners, etc.) ----
    if getattr(args, "script", None):
        a.append(f"--script={args.script}")

    # ---- Timing template ----
    a.append(f"-T{args.timing}")

    # ---- Stealth / evasion ----
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
# 2. Terminal output
# ---------------------------------------------------------------------------

def print_results(results, findings):
    """Print a human-readable scan report to the terminal.

    `results` structure:
        {
            "10.0.0.1": {
                "state": "up",
                "protocols": {
                    "tcp": {
                        22:  {"state": "open",   "service": "ssh",  "product": "OpenSSH", "version": "8.4"},
                        80:  {"state": "closed", "service": "http", "product": "", "version": ""},
                    },
                    "udp": { ... },
                },
            },
            ...
        }

    `findings` structure:
        {
            "10.0.0.1": [
                {"port": 22, "service": "OpenSSH 8.4",
                 "id": "CVE-2023-12345", "score": 7.5, "severity": "HIGH",
                 "description": "..."},
                ...
            ],
        }
    """
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

        # CVE findings for this host
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
# 3. Main scan entry point
# ---------------------------------------------------------------------------

def run_scan(args):
    """Execute a scan based on parsed CLI args.

    Steps:
      1. Expand/normalize the target list.
      2. Ask for confirmation (unless --yes was given).
      3. Hand the work to Nmap via python-nmap.
      4. Parse Nmap's structured result into a plain dict.
      5. Optionally run CVE matching against the detected services.
      6. Print a human-readable report.
      7. Export the same data to files if the user asked for output.
    """
    targets = expand_targets(args.targets)

    # 1. Confirmation gate (skipped with --yes)
    if not args.yes:
        confirm_scan(targets, build_nmap_args(args))

    # 2. Build and run the Nmap command
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

    # 3. Extract results into a plain dict
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
        print(f"[!] Try running that command directly to see why.")
        return {}, {}

    # 4. Optional CVE matching
    findings = {}
    if getattr(args, "vuln", False):
        print("\n[*] Running CVE lookup against NVD...")
        findings = match_services(results, min_cvss=args.min_cvss)

    # 5. Terminal output
    print_results(results, findings)

    # 6. File export (only if -o was given, OR always — adjust as you prefer)
    export(results, findings, args)

    return results, findings