"""Command-line interface for StealthScan."""
import argparse
import sys
from .scanner import run_scan


def _normalize_argv(argv):
    """Rewrite Nmap-style single-dash flags into double-dash equivalents."""
    single_dash_flags = {
        "-sn", "-sL", "-sS", "-sT", "-sA", "-sU", "-sV",
        "-O", "-p",
    }
    out = []
    for tok in argv:
        if tok in single_dash_flags:
            out.append("-" + tok)
        elif tok.startswith("-p") and len(tok) > 2:
            out.append("--p")
            out.append(tok[2:])
        else:
            out.append(tok)
    return out


def build_parser():
    p = argparse.ArgumentParser(
        prog="stealthscan",
        description="StealthScan — network reconnaissance with CVE matching. "
                    "Only use on networks you own or have written permission to test.",
        epilog="Examples:\n"
               "  sudo stealthscan 10.0.0.1\n"
               "  sudo stealthscan -sS -sV -p- 10.0.0.1\n"
               "  sudo stealthscan --subnet 192.168.1.0/24\n"
               "  sudo stealthscan --subnet 192.168.1.0/24 -sn\n"
               "  sudo stealthscan --subnet 192.168.1.0/24 -sS -sV --top-ports 100\n",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("targets", nargs="*", help="One or more IPs, CIDRs, or ranges")

    sub = p.add_argument_group("Subnet")
    sub.add_argument("--subnet", metavar="CIDR",
                     help="Scan an entire subnet, e.g. 192.168.1.0/24")

    g = p.add_argument_group("Scan Types")
    g.add_argument("--sn", "--ping", action="store_true", dest="ping",
                   help="Ping / host discovery only (fast)")
    g.add_argument("--sL", "--list", action="store_true", dest="list_scan",
                   help="List scan (no packets sent)")
    g.add_argument("--sS", "--syn", action="store_true", dest="syn",
                   help="TCP SYN (stealth) scan")
    g.add_argument("--sT", "--connect", action="store_true", dest="connect",
                   help="TCP connect scan")
    g.add_argument("--sA", "--ack", action="store_true", dest="ack",
                   help="TCP ACK scan")
    g.add_argument("--sU", "--udp", action="store_true", dest="udp",
                   help="UDP scan")

    d = p.add_argument_group("Detection")
    d.add_argument("--sV", "--service", action="store_true", dest="service",
                   help="Service/version detection")
    d.add_argument("--O", "--os", action="store_true", dest="os",
                   help="OS detection")

    pt = p.add_argument_group("Ports")
    pt.add_argument("--p", dest="ports", metavar="SPEC",
                    help="Port spec: 80, 1-1000, or - for all 65535")
    pt.add_argument("--top-ports", type=int, metavar="N",
                    help="Scan the top N most common ports (e.g. 100, 1000)")
    pt.add_argument("--all-ports", action="store_true",
                    help="Shortcut for -p- (all 65535 ports)")

    v = p.add_argument_group("Vulnerability Scanning")
    v.add_argument("--script", dest="script", metavar="NAME",
                   help="NSE script(s), e.g. --script=vuln")
    v.add_argument("--vuln", action="store_true",
                   help="Quick vuln scan (implies --script=vuln --sV)")
    v.add_argument("--min-cvss", type=float, default=0.0)

    s = p.add_argument_group("Stealth / Evasion")
    s.add_argument("-T", "--timing", choices=list("012345"), default="4",
                   help="Timing template (default: 4 = aggressive)")
    s.add_argument("-D", "--decoys", help="e.g. RND:5 or 1.1.1.1,ME")
    s.add_argument("-g", "--source-port", type=int)
    s.add_argument("-f", "--fragment", action="store_true")
    s.add_argument("--randomize", action="store_true")
    s.add_argument("--rate", type=int, default=1000,
                   help="Min packets/sec (default: 1000)")

    o = p.add_argument_group("Output")
    o.add_argument("-o", "--output")
    o.add_argument("--format", choices=["json", "csv", "text", "all"],
                   default="text")

    p.add_argument("-y", "--yes", action="store_true",
                   help="Skip confirmation prompt")
    return p


def main():
    args = build_parser().parse_args(_normalize_argv(sys.argv[1:]))

    # Fold --subnet into targets
    if args.subnet:
        args.targets.append(args.subnet)

    if not args.targets:
        raise SystemExit("[!] No targets given. Provide an IP, CIDR, or --subnet.")

    scans = [args.ping, args.list_scan, args.syn,
             args.connect, args.ack, args.udp]
    if sum(bool(x) for x in scans) > 1:
        raise SystemExit("[!] Choose only one of: -sn, -sL, -sS, -sT, -sA, -sU")

    if args.vuln:
        if not args.script:
            args.script = "vuln"
        args.service = True

    if args.all_ports:
        args.ports = "-"

    if not any(scans):
        args.syn = True

    run_scan(args)


if __name__ == "__main__":
    main()