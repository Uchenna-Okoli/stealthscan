"""Command-line interface for StealthScan.

Mirrors Nmap's own flags where possible:
    -sn          ping / host discovery
    -sL          list scan
    -sS          TCP SYN (stealth) scan
    -sT          TCP connect scan
    -sA          TCP ACK scan
    -sU          UDP scan
    -sV          service/version detection
    -O           OS detection
    -p <spec>    port spec: 80, 1-1000, -
    --script=vuln  run Nmap vuln NSE scripts

Long descriptive flags (--ping, --syn, ...) are kept as aliases so
older invocations still work.
"""
import argparse
from .scanner import run_scan


def build_parser():
    p = argparse.ArgumentParser(
        prog="stealthscan",
        description="StealthScan — Nmap orchestration with CVE matching. "
                    "Only use on networks you own or have written permission to test.",
        epilog="Examples:\n"
               "  sudo stealthscan 10.0.0.1\n"
               "  sudo stealthscan -sS -sV -p- 10.0.0.1\n"
               "  sudo stealthscan -sn 192.168.1.0/24\n"
               "  sudo stealthscan -sT -p 1-1000 10.0.0.1 10.0.0.2\n"
               "  sudo stealthscan -sS -sV --script=vuln 10.0.0.1\n"
               "  sudo stealthscan -sS -O 10.0.0.1\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Targets — one or more, exactly like Nmap
    p.add_argument("targets", nargs="+", help="One or more IPs, CIDRs, or ranges")

    # ---- Scan types (Nmap-style flags, with long aliases) ----
    g = p.add_argument_group("Scan Types")
    g.add_argument("-sn", "--ping", action="store_true",
                   dest="ping", help="Ping / host discovery only")
    g.add_argument("-sL", "--list", action="store_true",
                   dest="list_scan", help="List scan (no packets sent)")
    g.add_argument("-sS", "--syn", action="store_true",
                   dest="syn", help="TCP SYN (stealth) scan")
    g.add_argument("-sT", "--connect", action="store_true",
                   dest="connect", help="TCP connect scan")
    g.add_argument("-sA", "--ack", action="store_true",
                   dest="ack", help="TCP ACK scan")
    g.add_argument("-sU", "--udp", action="store_true",
                   dest="udp", help="UDP scan")

    # ---- Detection ----
    d = p.add_argument_group("Detection")
    d.add_argument("-sV", "--service", action="store_true",
                   dest="service", help="Service/version detection")
    d.add_argument("-O", "--os", action="store_true",
                   dest="os", help="OS detection")

    # ---- Port specification ----
    pt = p.add_argument_group("Ports")
    pt.add_argument("-p", dest="ports", metavar="SPEC",
                    help="Port spec: 80, 1-1000, or - for all 65535")

    # ---- Vulnerability scanning ----
    v = p.add_argument_group("Vulnerability Scanning")
    v.add_argument("--script", dest="script", metavar="NAME",
                   help="NSE script(s), e.g. --script=vuln or --script=vulners")
    v.add_argument("--vuln", action="store_true",
                   dest="vuln", help="Alias for --script=vuln, plus NVD CVE lookup")
    v.add_argument("--min-cvss", type=float, default=0.0,
                   help="Minimum CVSS to report when using --vuln")

    # ---- Stealth / evasion ----
    s = p.add_argument_group("Stealth / Evasion")
    s.add_argument("-T", "--timing", choices=list("012345"), default="3")
    s.add_argument("-D", "--decoys", help="e.g. RND:5 or 1.1.1.1,ME")
    s.add_argument("-g", "--source-port", type=int, help="Spoof source port")
    s.add_argument("-f", "--fragment", action="store_true",
                   help="Fragment packets")
    s.add_argument("--randomize", action="store_true",
                   help="Randomize host order")
    s.add_argument("--rate", type=int, help="Max packets/sec (--min-rate)")
    s.add_argument("--stealth-profile",
                   choices=["paranoid", "sneaky", "polite", "normal", "aggressive"])

    # ---- Output ----
    o = p.add_argument_group("Output")
    o.add_argument("-o", "--output", help="Output basename")
    o.add_argument("--format", choices=["json", "csv", "text", "all"],
                   default="text")

    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip confirmation prompt")
    return p


def main():
    args = build_parser().parse_args()

    # ---- Conflict checks ----
    scans = [args.ping, args.list_scan, args.syn, args.connect, args.ack, args.udp]
    if sum(bool(x) for x in scans) > 1:
        raise SystemExit("[!] Choose only one of: -sn, -sL, -sS, -sT, -sA, -sU")

    # ---- --vuln is a friendly alias for --script=vuln plus NVD lookup ----
    if args.vuln and not args.script:
        args.script = "vuln"

    # ---- If no scan type was given, default to -sS (SYN) ----
    if not any(scans):
        args.syn = True

    # ---- OS detection and UDP typically require service detection ----
    if args.os and not args.service:
        args.service = True

    run_scan(args)


if __name__ == "__main__":
    main()