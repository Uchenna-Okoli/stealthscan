"""Interactive scan builder for SSCAN.

Shown when sscan is run with no arguments. Presents a menu of common
scan profiles, prompts for a target and options, and returns an argv
list ready to hand back to cli.main() for normal parsing.
"""


MENU = r"""
╭─────────────────────────────────────────────────────────────╮
│                                                             │
│   SSCAN  v0.2.0                                             │
│   Interactive Scan Builder                                  │
│                                                             │
│   For authorized testing only.                              │
│                                                             │
╰─────────────────────────────────────────────────────────────╯

  What would you like to do?

   1) Ping sweep          — find live hosts (fast, safe)
   2) Quick scan          — top 100 ports, SYN (recommended)
   3) Service detection   — identify services and versions
   4) OS detection        — fingerprint the operating system
   5) Full port scan      — all 65,535 TCP ports (thorough, slow)
   6) Vulnerability scan  — CVEs + risk assessment
   7) Full recon          — SYN + services + OS + vuln
   8) UDP scan            — DNS, NTP, SNMP and other UDP services
   9) Custom              — build your own sscan command
   0) Exit
"""


# Scan profiles: maps menu choice to (description, base argv).
# The target is appended by the caller.

PROFILES = {
    "1": ("Ping sweep",
          ["-sn"]),
    "2": ("Quick scan (top 100 ports, SYN)",
          ["-sS", "--top-ports", "100"]),
    "3": ("Service detection",
          ["-sS", "-sV", "--top-ports", "1000"]),
    "4": ("OS detection",
          ["-sS", "-O", "--top-ports", "1000"]),
    "5": ("Full port scan (all 65,535)",
          ["-sS", "--all-ports"]),
    "6": ("Vulnerability scan (CVEs + risk)",
          ["-sS", "--script=vuln", "--top-ports", "1000"]),
    "7": ("Full recon (SYN + services + OS + vuln)",
          ["-sS", "-sV", "-O", "--script=vuln", "--top-ports", "1000"]),
    "8": ("UDP scan",
          ["-sU", "--top-ports", "100"]),
}


def show_menu():
    """Print the menu. Returns True on success."""
    print(MENU)
    return True


def get_choice():
    """Prompt the user for a menu choice. Returns the raw string."""
    try:
        return input("  Select [0-9]: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return "0"


def get_target():
    """Prompt for a target. Returns the raw string, or None on cancel."""
    print()
    print("  Target can be a single IP, a CIDR range, or multiple targets")
    print("  separated by spaces.")
    print("  Examples:  192.168.1.5    192.168.1.0/24    10.0.0.1 10.0.0.2")
    print()
    try:
        raw = input("  Target: ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return None
    return raw or None


def confirm_run(argv):
    """Show the final command and ask for confirmation.

    Returns True to run, False to cancel.
    """
    cmd = "sudo sscan " + " ".join(argv)
    print()
    print("  The following command will run:")
    print()
    print(f"    {cmd}")
    print()
    try:
        ans = input("  Run it? [Y/n]: ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        print()
        return False
    return ans in ("", "y", "yes")


def build_argv_from_choice(choice, target):
    """Given a menu choice and a target, produce the full argv list."""
    profile = PROFILES.get(choice)
    if not profile:
        return None
    _, base = profile
    return list(base) + [target, "--yes"]


def run_interactive():
    """Full interactive flow.

    Returns an argv list on success (ready to hand to cli.main), or None
    if the user cancelled.
    """
    show_menu()
    choice = get_choice()

    if choice == "0" or choice == "":
        print("\n  Bye.\n")
        return None

    if choice == "9":
        return run_custom()

    if choice not in PROFILES:
        print(f"\n  [!] Unknown choice: {choice}")
        return None

    target = get_target()
    if not target:
        print("\n  [!] No target given. Aborting.\n")
        return None

    argv = build_argv_from_choice(choice, target)
    if not argv:
        print("\n  [!] Could not build command.\n")
        return None

    if not confirm_run(argv):
        print("\n  Cancelled.\n")
        return None

    print()
    return argv


def run_custom():
    """Let the user paste a full sscan command line.

    Returns an argv list, or None on cancel.
    """
    print()
    print("  Enter your sscan flags and target (do NOT include 'sudo sscan').")
    print("  Example:  -sS -sV --top-ports 500 192.168.1.0/24 --yes")
    print()
    try:
        raw = input("  > ").strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return None
    if not raw:
        return None
    return raw.split()