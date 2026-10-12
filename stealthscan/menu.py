"""Interactive scan builder for SSCAN.

Two-level menu:
  1. Top level: choose a category
  2. Second level: choose a specific scan within that category

Includes a guided helper that recommends a scan based on what
you're trying to accomplish.
"""


# ---------------------------------------------------------------------------
# Scan catalog — every scan SSCAN can do, with guidance for each
# ---------------------------------------------------------------------------

# Each entry:
#   key:      identifier used by the caller
#   name:     short display name
#   flags:    argv flags to pass to sscan (target appended later)
#   what:     what the scan does
#   finds:    what you get from it
#   time:     rough duration hint
#   root:     needs sudo?
#   when:     when to choose this scan

CATALOG = {
    # --- Discovery ---
    "ping": {
        "name": "Ping sweep",
        "flags": ["-sn"],
        "what": "Sends ICMP echo and TCP pings to find live hosts",
        "finds": "List of hosts that responded",
        "time": "seconds",
        "root": False,
        "when": "You want to know which hosts are up before scanning ports",
    },
    "list": {
        "name": "List scan",
        "flags": ["-sL"],
        "what": "Resolves target hostnames, sends no packets",
        "finds": "A list of resolved IPs and hostnames",
        "time": "instant",
        "root": False,
        "when": "You want to expand a range into individual hosts without scanning",
    },

    # --- TCP scans ---
    "syn": {
        "name": "TCP SYN scan (stealth)",
        "flags": ["-sS", "--top-ports", "1000"],
        "what": "Half-open TCP scan — sends SYN, never completes the handshake",
        "finds": "Open / closed / filtered TCP ports",
        "time": "seconds to minutes",
        "root": True,
        "when": "Default choice for TCP port discovery — fast and quiet",
    },
    "connect": {
        "name": "TCP connect scan",
        "flags": ["-sT", "--top-ports", "1000"],
        "what": "Full TCP handshake scan — like a browser connecting",
        "finds": "Open / closed TCP ports",
        "time": "seconds to minutes",
        "root": False,
        "when": "You don't have root, or you want the least suspicious TCP scan",
    },
    "ack": {
        "name": "TCP ACK scan",
        "flags": ["-sA", "--top-ports", "1000"],
        "what": "Sends bare ACK packets to map firewall rules",
        "finds": "Filtered vs unfiltered ports (does NOT find open ports)",
        "time": "seconds",
        "root": True,
        "when": "You want to know which ports a firewall is filtering",
    },
    "fin": {
        "name": "TCP FIN scan",
        "flags": ["-sF", "--top-ports", "1000"],
        "what": "Sends FIN-only packets — can bypass some older firewalls",
        "finds": "Open / closed / filtered ports (closed on some systems)",
        "time": "seconds",
        "root": True,
        "when": "You're testing a target behind a legacy firewall",
    },
    "null": {
        "name": "TCP NULL scan",
        "flags": ["-sN", "--top-ports", "1000"],
        "what": "Sends packets with no TCP flags set",
        "finds": "Open / closed / filtered (same caveats as FIN)",
        "time": "seconds",
        "root": True,
        "when": "You're testing firewall behavior on non-Windows targets",
    },
    "xmas": {
        "name": "TCP Xmas scan",
        "flags": ["-sX", "--top-ports", "1000"],
        "what": "Sends packets with FIN, PSH, URG flags (\"lit up like a tree\")",
        "finds": "Open / closed / filtered (same caveats as FIN)",
        "time": "seconds",
        "root": True,
        "when": "You're testing firewall behavior on non-Windows targets",
    },
    "fulltcp": {
        "name": "Full TCP port scan (all 65,535 ports)",
        "flags": ["-sS", "--all-ports"],
        "what": "SYN scan across every possible TCP port",
        "finds": "Every open TCP port on the target",
        "time": "minutes to hours",
        "root": True,
        "when": "You need complete coverage and have time",
    },

    # --- UDP ---
    "udp": {
        "name": "UDP scan (top 100 UDP ports)",
        "flags": ["-sU", "--top-ports", "100"],
        "what": "Scans common UDP services",
        "finds": "Open UDP ports (DNS, NTP, SNMP, etc.)",
        "time": "minutes",
        "root": True,
        "when": "You want to find UDP services — slower than TCP",
    },
    "udpfull": {
        "name": "Full UDP scan (all 65,535 UDP ports)",
        "flags": ["-sU", "--all-ports"],
        "what": "Scans every UDP port",
        "finds": "Every open UDP port",
        "time": "hours",
        "root": True,
        "when": "You need complete UDP coverage and have lots of time",
    },

    # --- Detection ---
    "service": {
        "name": "Service and version detection",
        "flags": ["-sS", "-sV", "--top-ports", "1000"],
        "what": "Identifies what service runs on each open port and its version",
        "finds": "Service names, versions, product info",
        "time": "seconds to minutes",
        "root": True,
        "when": "You want to know what's running, not just which ports are open",
    },
    "os": {
        "name": "OS detection",
        "flags": ["-sS", "-O", "--top-ports", "1000"],
        "what": "Fingerprints the target's operating system",
        "finds": "OS family and version guess",
        "time": "seconds to minutes",
        "root": True,
        "when": "You need to know what OS the target is running",
    },
    "both": {
        "name": "Service + OS detection",
        "flags": ["-sS", "-sV", "-O", "--top-ports", "1000"],
        "what": "Combines service detection with OS fingerprinting",
        "finds": "Services, versions, and OS",
        "time": "minutes",
        "root": True,
        "when": "You want a full profile of what the target is",
    },

    # --- Vulnerability ---
    "vuln": {
        "name": "Vulnerability scan (CVEs + risk assessment)",
        "flags": ["-sS", "--script=vuln", "--top-ports", "1000"],
        "what": "Runs NSE vuln scripts and matches detected services to CVEs",
        "finds": "CVE IDs, CVSS scores, per-port and per-host risk ratings",
        "time": "minutes",
        "root": True,
        "when": "You want to find known vulnerabilities on the target",
    },
    "vuln-full": {
        "name": "Vulnerability scan (all ports)",
        "flags": ["-sS", "--script=vuln", "--all-ports"],
        "what": "Vulnerability scan across every TCP port",
        "finds": "Complete CVE map with risk assessment",
        "time": "hours",
        "root": True,
        "when": "You need the most complete vulnerability picture",
    },

    # --- Full recon ---
    "recon": {
        "name": "Full recon (services + OS + vulnerabilities)",
        "flags": ["-sS", "-sV", "-O", "--script=vuln", "--top-ports", "1000"],
        "what": "Everything at once — SYN scan, service detection, OS detection, vuln scan",
        "finds": "The most complete single-host picture SSCAN can produce",
        "time": "minutes",
        "root": True,
        "when": "You want a comprehensive one-shot scan of a host",
    },

    # --- Subnet ---
    "subnet-ping": {
        "name": "Subnet ping sweep",
        "flags": ["-sn"],
        "what": "Host discovery across a subnet",
        "finds": "Live hosts on the network",
        "time": "seconds",
        "root": False,
        "when": "You want to see what's alive on a network",
    },
    "subnet-quick": {
        "name": "Subnet quick scan (top 100 ports)",
        "flags": ["-sS", "--top-ports", "100"],
        "what": "Fast port scan across a subnet",
        "finds": "Open ports on each live host",
        "time": "minutes",
        "root": True,
        "when": "You want a fast overview of services on a network",
    },
    "subnet-vuln": {
        "name": "Subnet vulnerability scan",
        "flags": ["-sS", "--script=vuln", "--top-ports", "100"],
        "what": "Vulnerability scan across a subnet",
        "finds": "CVEs on every live host, plus network-wide risk rating",
        "time": "tens of minutes",
        "root": True,
        "when": "You need a network-wide vulnerability assessment",
    },
}


# ---------------------------------------------------------------------------
# Categories — the top-level menu
# ---------------------------------------------------------------------------

CATEGORIES = [
    ("1", "Discovery",  ["ping", "list"]),
    ("2", "TCP scans",  ["syn", "connect", "ack", "fin", "null", "xmas", "fulltcp"]),
    ("3", "UDP scans",  ["udp", "udpfull"]),
    ("4", "Detection",  ["service", "os", "both"]),
    ("5", "Vulnerability", ["vuln", "vuln-full"]),
    ("6", "Full recon", ["recon"]),
    ("7", "Subnet scans", ["subnet-ping", "subnet-quick", "subnet-vuln"]),
    ("8", "Guided helper", None),   # special: runs the guided flow
    ("9", "Custom command", None),  # special: user types raw flags
    ("0", "Exit", None),
]


# ---------------------------------------------------------------------------
# Guided helper — maps goals to scan recommendations
# ---------------------------------------------------------------------------

GUIDE_QUESTIONS = [
    {
        "prompt": "What are you trying to do?",
        "options": [
            ("1", "Find live hosts on a network",
             "subnet-ping", "Ping sweep finds every responsive host quickly."),
            ("2", "See what ports are open on one host",
             "syn", "TCP SYN scan gives you open ports fast and quiet."),
            ("3", "Identify what services are running",
             "service", "Service detection probes each open port for a banner."),
            ("4", "Find known vulnerabilities",
             "vuln", "Vulnerability scan matches services to CVEs and rates risk."),
            ("5", "Get the deepest possible picture of one host",
             "recon", "Full recon combines services, OS, and vulnerabilities."),
            ("6", "Assess an entire network",
             "subnet-vuln", "Subnet vulnerability scan covers every live host."),
            ("7", "Test firewall rules",
             "ack", "ACK scan shows filtered vs unfiltered, revealing firewall behavior."),
            ("8", "Scan UDP services too",
             "udp", "UDP scan finds DNS, NTP, SNMP, and other UDP services."),
        ],
    },
]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

BANNER = r"""
╭─────────────────────────────────────────────────────────────╮
│                                                             │
│   SSCAN  v0.2.0                                             │
│   Interactive Scan Builder                                  │
│                                                             │
│   For authorized testing only.                              │
│                                                             │
╰─────────────────────────────────────────────────────────────╯
"""


def print_banner():
    print(BANNER)


def print_main_menu():
    print("  What would you like to do?\n")
    for key, label, _ in CATEGORIES:
        print(f"   {key}) {label}")
    print()


def print_category(category_key):
    """Show the scans within one category. Returns the list of scan keys."""
    cat = next((c for c in CATEGORIES if c[0] == category_key), None)
    if not cat or cat[2] is None:
        return []
    _, label, scan_keys = cat

    print(f"\n  {label}\n")
    for i, key in enumerate(scan_keys, start=1):
        entry = CATALOG[key]
        root = " [root]" if entry["root"] else ""
        print(f"   {i}) {entry['name']}{root}")
        print(f"      {entry['what']}")
        print(f"      Time: {entry['time']}    Finds: {entry['finds']}")
        print()
    print(f"   0) Back")
    print()
    return scan_keys


def print_scan_detail(key):
    """Show full detail for one scan and ask for confirmation."""
    entry = CATALOG[key]
    print()
    print("  " + "─" * 60)
    print(f"  {entry['name']}")
    print("  " + "─" * 60)
    print(f"  What it does:   {entry['what']}")
    print(f"  What you get:   {entry['finds']}")
    print(f"  Typical time:   {entry['time']}")
    print(f"  Needs root:     {'yes' if entry['root'] else 'no'}")
    print(f"  When to use:    {entry['when']}")
    print(f"  Underlying:     sscan {' '.join(entry['flags'])} <target>")
    print()


# ---------------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------------

def ask(prompt):
    try:
        return input(prompt).strip()
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def get_target():
    print()
    print("  Target can be:")
    print("    single IP     →   192.168.1.5")
    print("    CIDR range    →   192.168.1.0/24")
    print("    IP range      →   192.168.1.1-50")
    print("    multiple      →   10.0.0.1 10.0.0.2 10.0.0.3")
    print()
    raw = ask("  Target: ")
    return raw or None


def confirm_run(argv):
    cmd = "sudo sscan " + " ".join(argv)
    print()
    print("  Ready to run:")
    print()
    print(f"    {cmd}")
    print()
    ans = ask("  Run it? [Y/n]: ")
    if ans is None:
        return False
    return ans.lower() in ("", "y", "yes")


# ---------------------------------------------------------------------------
# Flows
# ---------------------------------------------------------------------------

def flow_pick_scan():
    """Top-level flow: pick category → pick scan → target → confirm."""
    while True:
        print_main_menu()
        choice = ask("  Select [0-9]: ")
        if choice is None or choice == "0":
            print("\n  Bye.\n")
            return None

        # Guided helper
        if choice == "8":
            return flow_guided()

        # Custom command
        if choice == "9":
            return flow_custom()

        # Category
        cat = next((c for c in CATEGORIES if c[0] == choice), None)
        if not cat or cat[2] is None:
            print(f"\n  [!] Unknown choice: {choice}\n")
            continue

        argv = flow_within_category(cat[2])
        if argv is not None:
            return argv
        # else: user chose Back, loop to main menu


def flow_within_category(scan_keys):
    """Show scans in a category; user picks one; returns final argv or None."""
    while True:
        print_category(scan_keys and _find_category_key_for(scan_keys))
        choice = ask("  Select a scan number [0 to go back]: ")
        if choice is None or choice == "0":
            return None

        try:
            idx = int(choice) - 1
            if idx < 0 or idx >= len(scan_keys):
                raise ValueError
        except ValueError:
            print(f"\n  [!] Invalid choice: {choice}\n")
            continue

        key = scan_keys[idx]
        print_scan_detail(key)

        ans = ask("  Use this scan? [Y/n]: ")
        if ans is None or ans.lower() not in ("", "y", "yes"):
            continue

        target = get_target()
        if not target:
            print("\n  [!] No target given.\n")
            continue

        argv = list(CATALOG[key]["flags"]) + [target, "--yes"]
        if not confirm_run(argv):
            print("\n  Cancelled.\n")
            return None
        print()
        return argv


def _find_category_key_for(scan_keys):
    """Reverse-lookup which top-level category contains these scan keys."""
    for key, label, keys in CATEGORIES:
        if keys == scan_keys:
            return key
    return None


def flow_guided():
    """Guided helper: asks what you're trying to do, recommends a scan."""
    print()
    print("  ── Guided Helper ──")
    print()
    for q in GUIDE_QUESTIONS:
        print(f"  {q['prompt']}\n")
        for key, text, _, _ in q["options"]:
            print(f"   {key}) {text}")
        print()

        choice = ask("  Select [1-8]: ")
        if choice is None or choice == "":
            return None

        opt = next((o for o in q["options"] if o[0] == choice), None)
        if not opt:
            print(f"\n  [!] Unknown choice: {choice}\n")
            return None

        _, text, scan_key, reason = opt
        entry = CATALOG[scan_key]

        print()
        print(f"  Recommendation: {entry['name']}")
        print(f"  Why: {reason}")
        print()
        print_scan_detail(scan_key)

        ans = ask("  Use this scan? [Y/n]: ")
        if ans is None or ans.lower() not in ("", "y", "yes"):
            return None

        target = get_target()
        if not target:
            print("\n  [!] No target given.\n")
            return None

        argv = list(entry["flags"]) + [target, "--yes"]
        if not confirm_run(argv):
            print("\n  Cancelled.\n")
            return None
        print()
        return argv


def flow_custom():
    """User types raw sscan flags."""
    print()
    print("  Enter your sscan flags and target.")
    print("  Do NOT include 'sudo sscan' — SSCAN adds it when running.")
    print()
    print("  Example:  -sS -sV --top-ports 500 192.168.1.0/24 --yes")
    print()
    raw = ask("  > ")
    if not raw:
        return None
    argv = raw.split()

    if not confirm_run(argv):
        print("\n  Cancelled.\n")
        return None
    print()
    return argv


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_interactive():
    """Called by cli.main() when no arguments are given.

    Returns an argv list (ready to hand to cli.main), or None to exit.
    """
    print_banner()
    return flow_pick_scan()