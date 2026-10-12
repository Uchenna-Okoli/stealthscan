"""Helper functions: target expansion, confirmation."""
import sys


def expand_targets(targets):
    """Normalize target list. CIDR notation is passed through as-is."""
    out = []
    for t in targets:
        t = t.strip()
        if not t:
            continue
        if t.endswith(".*"):
            base = t[:-2]
            out.append(f"{base}.0/24")
        else:
            out.append(t)
    return out


def confirm_scan(targets, engine_args):
    preview = ", ".join(targets[:5])
    if len(targets) > 5:
        preview += f", ... (+{len(targets) - 5} more)"
    print(f"\n[!] Scanning {len(targets)} target(s): {preview}")
    print(f"[!] StealthScan args: {engine_args}")
    print("[!] Only scan networks you own or have written permission to test.")
    try:
        if input("Proceed? [y/N] ").strip().lower() != "y":
            print("[*] Aborted.")
            sys.exit(0)
    except KeyboardInterrupt:
        print("\n[*] Aborted.")
        sys.exit(130)