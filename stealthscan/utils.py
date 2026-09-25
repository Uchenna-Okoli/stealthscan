"""Helpers: target parsing, safety confirmation."""
import sys


def expand_targets(targets):
    """Pass targets through; Nmap handles CIDR and ranges natively."""
    return [t.strip() for t in targets if t.strip()]


def confirm_scan(targets, nmap_args):
    print(f"\n[!] Scanning {len(targets)} target(s): "
          f"{targets[:5]}{'...' if len(targets) > 5 else ''}")
    print(f"[!] Nmap args: {nmap_args}")
    print("[!] Only scan networks you own or have written permission to test.")
    if input("Proceed? [y/N] ").strip().lower() != "y":
        print("[*] Aborted.")
        sys.exit(0)