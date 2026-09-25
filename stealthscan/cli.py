"""Command-line interface for StealthScan."""
import argparse
from .scanner import run_scan


def build_parser():
    p = argparse.ArgumentParser(
        prog="stealthscan",
        description="StealthScan — Nmap orchestration with CVE matching. "
                    "Only use on networks you own or have written permission to test.",
    )
    p.add_argument("targets", nargs="+", help="IP, CIDR, or range")

    g = p.add_argument_group("Scan Types")
    g.add_argument("--syn", action="store_true", help="TCP SYN (stealth) scan")
    g.add_argument("--connect", action="store_true", help="TCP connect scan")
    g.add_argument("--udp", action="store_true", help="UDP scan")
    g.add_argument("--ping", action="store_true", help="Ping/host-discovery only")

    d = p.add_argument_group("Detection")
    d.add_argument("--service", action="store_true", help="Service/version detection")
    d.add_argument("--os", action="store_true", help="OS detection")

    s = p.add_argument_group("Stealth / Evasion")
    s.add_argument("-T", "--timing", choices=list("012345"), default="3")
    s.add_argument("--decoys", help="e.g. RND:5 or 1.1.1.1,ME")
    s.add_argument("--source-port", type=int, help="Spoof source port (-g)")
    s.add_argument("--fragment", action="store_true", help="Fragment packets (-f)")
    s.add_argument("--randomize", action="store_true", help="Randomize host order")
    s.add_argument("--rate", type=int, help="Max packets/sec")
    s.add_argument("--stealth-profile",
                   choices=["paranoid", "sneaky", "polite", "normal", "aggressive"])

    v = p.add_argument_group("Vulnerability Matching")
    v.add_argument("--vuln", action="store_true", help="Match services to CVEs")
    v.add_argument("--min-cvss", type=float, default=0.0)

    o = p.add_argument_group("Output")
    o.add_argument("-o", "--output", help="Output basename")
    o.add_argument("--format", choices=["json", "csv", "text", "all"], default="text")

    p.add_argument("--yes", action="store_true", help="Skip confirmation prompt")
    return p


def main():
    args = build_parser().parse_args()
    run_scan(args)


if __name__ == "__main__":
    main()