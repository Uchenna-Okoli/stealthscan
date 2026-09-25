"""Nmap orchestration layer."""
import nmap
from .utils import confirm_scan, expand_targets
from .report import export
from .vuln_matcher import match_services


def build_nmap_args(args):
    """Translate StealthScan flags into an Nmap argument string."""
    a = []

    # Scan type — Nmap's own flags
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

    # Ports — only if the user asked for something specific
    # (Nmap defaults to top 1000 if -p is omitted; StealthScan also defaults
    # to top 1000 rather than all 65535 for speed unless -p- is given)
    if args.ports:
        a.extend(["-p", args.ports])
    elif not (args.ping or args.list_scan):
        a.extend(["-p", "1-65535"])  # full range by default

    # Detection
    if args.service:
        a.append("-sV")
    if args.os:
        a.append("-O")

    # NSE scripts
    if args.script:
        a.append(f"--script={args.script}")

    # Timing
    a.append(f"-T{args.timing}")

    # Stealth
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


def run_scan(args):
    targets = expand_targets(args.targets)

    if not args.yes:
        confirm_scan(targets, build_nmap_args(args))

    nm = nmap.PortScanner()
    nmap_str = build_nmap_args(args)
    print(f"[*] Running: nmap {nmap_str} {' '.join(targets)}")
    nm.scan(hosts=" ".join(targets), arguments=nmap_str)

    results = {}
    for host in nm.all_hosts():
        results[host] = {"state": nm[host].state(), "protocols": {}}
        for proto in nm[host].all_protocols():
            results[host]["protocols"][proto] = {}
            for port in nm[host][proto].keys():
                p = nm[host][proto][port]
                results[host]["protocols"][proto][port] = {
                    "state": p["state"],
                    "service": p.get("name", ""),
                    "product": p.get("product", ""),
                    "version": p.get("version", ""),
                }

    findings = {}
    if args.vuln:
        findings = match_services(results, min_cvss=args.min_cvss)

    export(results, findings, args)
    return results, findings