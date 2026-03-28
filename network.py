#!/usr/bin/env python3
"""
network.py — Local Network Device Scanner
Raspberry Pi 4B / Pi OS 64-bit

Dependencies:
    sudo apt install nmap python3-pip -y
    sudo pip3 install scapy colorama manuf --break-system-packages

Usage:
    sudo python3 network.py [OPTIONS]

    (root/sudo required for ARP + raw socket scanning)
"""

import argparse
import base64
import datetime
import signal
import socket
import subprocess
import sys
import time

# ── dependency guard ──────────────────────────────────────────────────────────
try:
    from scapy.all import ARP, Ether, srp, conf
except ImportError:
    print("[!] scapy not found.  Run:  sudo pip3 install scapy --break-system-packages")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
except ImportError:
    print("[!] colorama not found.  Run:  sudo pip3 install colorama --break-system-packages")
    sys.exit(1)

try:
    import manuf
    MANUF_AVAILABLE = True
except ImportError:
    MANUF_AVAILABLE = False

# ── colour palette ────────────────────────────────────────────────────────────
C = {
    "title":    Fore.CYAN    + Style.BRIGHT,
    "header":   Fore.WHITE   + Style.BRIGHT,
    "ip":       Fore.GREEN   + Style.BRIGHT,
    "mac":      Fore.YELLOW,
    "hostname": Fore.MAGENTA,
    "vendor":   Fore.CYAN,
    "devtype":  Fore.BLUE    + Style.BRIGHT,
    "latency":  Fore.WHITE,
    "time":     Fore.WHITE   + Style.DIM,
    "found":    Fore.GREEN,
    "warn":     Fore.YELLOW  + Style.BRIGHT,
    "err":      Fore.RED     + Style.BRIGHT,
    "sep":      Fore.WHITE   + Style.DIM,
    "reset":    Style.RESET_ALL,
}

# ── device-type heuristics (vendor keyword -> type label) ─────────────────────
VENDOR_KEYWORDS = [
    (["apple",   "iphone", "ipad"],                  "Apple Mobile"),
    (["samsung", "galaxy", "oneplus", "xiaomi",
      "huawei",  "oppo",  "realme", "motorola",
      "lg elec", "htc",   "sony mobile"],            "Android Mobile"),
    (["raspberry", "raspberrypi"],                    "Raspberry Pi"),
    (["intel", "dell", "hp inc", "hewlett",
      "lenovo", "asus",  "acer",  "gigabyte",
      "micro-star", "msi",  "toshiba"],              "Computer / Laptop"),
    (["synology", "qnap", "western digital",
      "seagate", "drobo"],                           "NAS / Storage"),
    (["cisco",  "juniper", "mikrotik",
      "ubiquiti", "netgear", "tp-link",
      "d-link",  "zyxel",  "aruba",
      "linksys", "asus tek"],                        "Router / Switch"),
    (["amazon", "echo",  "alexa", "ring"],           "Amazon Device"),
    (["google", "nest",  "chromecast"],              "Google / Nest"),
    (["philips", "hue",  "ikea", "sengled",
      "osram",  "lifx", "tuya",  "shelly",
      "espressif"],                                  "Smart Home / IoT"),
    (["xbox",   "nintendo", "sony interactive",
      "playstation", "valve"],                       "Gaming Console"),
    (["canon",  "epson",  "brother", "hp laserjet",
      "ricoh",  "lexmark", "zebra tech"],            "Printer"),
    (["vmware", "virtual", "parallels",
      "xen",   "proxmox", "nutanix"],               "Virtual Machine"),
    (["hikvision", "dahua", "axis comm",
      "hanwha", "amcrest", "reolink"],              "IP Camera"),
    (["supermicro", "ibm",  "hewlett packard ent",
      "oracle", "fujitsu"],                         "Server"),
]

# Emoji prefix map (kept separate so type strings stay plain for filtering)
TYPE_EMOJI = {
    "Apple Mobile":     "📱",
    "Android Mobile":   "📱",
    "Raspberry Pi":     "🍓",
    "Computer / Laptop":"💻",
    "NAS / Storage":    "🗄️ ",
    "Router / Switch":  "🌐",
    "Amazon Device":    "🔊",
    "Google / Nest":    "🏠",
    "Smart Home / IoT": "💡",
    "Gaming Console":   "🎮",
    "Printer":          "🖨️ ",
    "Virtual Machine":  "☁️ ",
    "IP Camera":        "📷",
    "Server":           "🖥️ ",
    "Unknown":          "❓",
}


def guess_device_type(vendor):
    v = vendor.lower()
    for keywords, label in VENDOR_KEYWORDS:
        if any(k in v for k in keywords):
            return label
    return "Unknown"


def format_type(raw_type):
    emoji = TYPE_EMOJI.get(raw_type, "❓")
    return f"{emoji} {raw_type}"


# ── filter helper ─────────────────────────────────────────────────────────────
def device_matches_filters(d, vendor_filter, type_filter):
    """Return True if device passes all active filters (case-insensitive partial match)."""
    if vendor_filter:
        if vendor_filter.lower() not in d.get("vendor", "").lower():
            return False
    if type_filter:
        if type_filter.lower() not in d.get("devtype", "").lower():
            return False
    return True


# ── sweep code helpers ────────────────────────────────────────────────────────
def encode_sweep_code(seen_devices):
    """Encode all known MACs into a compact base64 sweep code string."""
    # MACs are 17 chars each (XX:XX:XX:XX:XX:XX), join with comma, encode
    mac_list = ",".join(sorted(seen_devices.keys()))
    return base64.urlsafe_b64encode(mac_list.encode()).decode()


def decode_sweep_code(code):
    """Decode a sweep code back into a set of MAC address strings."""
    try:
        mac_list = base64.urlsafe_b64decode(code.encode()).decode()
        return set(m.strip().upper() for m in mac_list.split(",") if m.strip())
    except Exception:
        return None


def print_sweep_code(seen_devices, sweep_num):
    code = encode_sweep_code(seen_devices)
    print()
    print(C["warn"] + f"  Sweep #{sweep_num} code ({len(seen_devices)} device(s) encoded):" + C["reset"])
    print(C["title"] + f"  {code}" + C["reset"])
    print(C["time"]  + "  Use with --filter <code> to show only NEW devices next run." + C["reset"])
    print()



def get_local_cidr():
    """Best-effort: find the Pi default-route interface CIDR."""
    try:
        out = subprocess.check_output(
            ["ip", "route", "show", "default"], text=True
        )
        iface = out.split("dev")[1].split()[0]
        out2 = subprocess.check_output(
            ["ip", "-o", "-f", "inet", "addr", "show", iface], text=True
        )
        cidr = out2.split()[3]
        return cidr
    except Exception:
        return "192.168.1.0/24"


def resolve_hostname(ip, timeout=0.5):
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def ping_latency(ip):
    try:
        out = subprocess.check_output(
            ["ping", "-c", "1", "-W", "1", ip],
            stderr=subprocess.DEVNULL, text=True
        )
        for part in out.split():
            if part.startswith("time="):
                return part.replace("time=", "") + " ms"
        return "< 1 ms"
    except Exception:
        return "—"


# ── scanner ───────────────────────────────────────────────────────────────────
def arp_scan(cidr, timeout=3):
    conf.verb = 0
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    answered, _ = srp(pkt, timeout=timeout, retry=1)
    devices = []
    for sent, received in answered:
        devices.append({
            "ip":  received.psrc,
            "mac": received.hwsrc.upper(),
        })
    return devices


def enrich_device(d, parser=None):
    ip  = d["ip"]
    mac = d["mac"]

    vendor = ""
    if MANUF_AVAILABLE and parser:
        try:
            vendor = parser.get_manuf(mac) or ""
        except Exception:
            vendor = ""

    raw_type      = guess_device_type(vendor) if vendor else "Unknown"
    d["vendor"]   = vendor or "Unknown"
    d["devtype"]  = raw_type                   # plain string — used for filtering
    d["hostname"] = resolve_hostname(ip)
    d["latency"]  = ping_latency(ip)
    d["seen"]     = datetime.datetime.now().strftime("%H:%M:%S")
    return d


# ── display ───────────────────────────────────────────────────────────────────
BANNER = r"""
  _   _      _                      _
 | \ | | ___| |___      _____  _ __| | __
 |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ /
 | |\  |  __/ |_ \ V  V / (_) | |  |   <
 |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\
          Network Scanner - Pi Edition
"""


def print_banner(cidr, args):
    print(C["title"] + BANNER + C["reset"])
    print(C["sep"] + "-" * 68 + C["reset"])
    print(C["time"] + f"  Target  : {cidr}")
    if args.time:
        print(C["time"] + f"  Timeout : {args.time}s total")
    else:
        print(C["time"] + "  Mode    : Continuous (Ctrl+C to stop)")
    if args.devices:
        print(C["time"] + f"  Stop at : {args.devices} device(s) found")
    if args.vendor:
        print(C["warn"] + f"  Filter  : vendor contains \"{args.vendor}\"")
    if args.type:
        print(C["warn"] + f"  Filter  : type contains \"{args.type}\"")
    if args.filter:
        baseline = decode_sweep_code(args.filter)
        count = len(baseline) if baseline else 0
        print(C["warn"] + f"  Filter  : hiding {count} device(s) from sweep code (new devices only)")
    if args.code:
        print(C["warn"] + "  Code    : sweep code will be printed after each sweep")
    print(C["sep"] + "-" * 68 + C["reset"])
    print()


def print_device(d, index):
    line_sep = C["sep"] + "  " + "." * 64 + C["reset"]
    print(C["sep"] + f"  [{index:>3}] " + C["reset"] + C["time"] + f"found at {d['seen']}" + C["reset"])
    print(C["ip"]      + f"        IP       : {d['ip']}" + C["reset"])
    print(C["mac"]     + f"        MAC      : {d['mac']}" + C["reset"])
    if d.get("hostname"):
        print(C["hostname"] + f"        Hostname : {d['hostname']}" + C["reset"])
    print(C["vendor"]  + f"        Vendor   : {d['vendor']}" + C["reset"])
    print(C["devtype"] + f"        Type     : {format_type(d['devtype'])}" + C["reset"])
    print(C["latency"] + f"        Latency  : {d['latency']}" + C["reset"])
    print(line_sep)


def print_summary(devices, start_time, vendor_filter=None, type_filter=None):
    elapsed = time.time() - start_time
    print()
    print(C["header"] + "-" * 68 + C["reset"])
    label = "matching device(s)" if (vendor_filter or type_filter) else "device(s)"
    print(C["header"] + f"  Scan complete -- {len(devices)} {label} found in {elapsed:.1f}s" + C["reset"])
    print(C["header"] + "-" * 68 + C["reset"])

    type_counts = {}
    for d in devices.values():
        t = d.get("devtype", "Unknown")
        type_counts[t] = type_counts.get(t, 0) + 1

    for dtype, count in sorted(type_counts.items(), key=lambda x: -x[1]):
        print(C["devtype"] + f"    {format_type(dtype):<35}" + C["ip"] + f"  x{count}" + C["reset"])
    print()


# ── argument parser ───────────────────────────────────────────────────────────
def build_parser():
    p = argparse.ArgumentParser(
        prog="network.py",
        description="Colour-coded local network device scanner for Raspberry Pi.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 network.py                              # scan forever, Ctrl+C to stop
  sudo python3 network.py --time 60                   # stop after 60 seconds
  sudo python3 network.py --devices 10                # stop after 10 matching devices
  sudo python3 network.py --vendor amazon             # only show Amazon devices
  sudo python3 network.py --vendor apple              # only show Apple devices
  sudo python3 network.py --type phone                # only show phones (Apple + Android)
  sudo python3 network.py --type router               # only show routers/switches
  sudo python3 network.py --type "smart home"         # only show smart home / IoT devices
  sudo python3 network.py --type camera               # only show IP cameras
  sudo python3 network.py --vendor google --time 120  # Google devices, 2 minute scan
  sudo python3 network.py --cidr 10.0.0.0/24          # custom subnet

Sweep code workflow (snapshot diff):
  Step 1 — scan your baseline network and get a code:
    sudo python3 network.py --time 30 --code

  Step 2 — copy the printed sweep code, then run again later:
    sudo python3 network.py --filter <sweep_code>

  Only devices NOT in your baseline will be shown — great for
  spotting phones, guests, or unknown devices that joined later.

Available --type keywords (partial match, case-insensitive):
  phone        apple mobile     android mobile   raspberry
  computer     laptop           nas              storage
  router       switch           amazon           google
  nest         smart home       iot              gaming
  console      printer          virtual          camera
  server       unknown

Notes:
  * Must be run with sudo (raw socket / ARP)
  * Requires:  scapy  colorama  manuf
      sudo pip3 install scapy colorama manuf --break-system-packages
        """,
    )
    p.add_argument(
        "--time", "-t",
        type=int,
        metavar="SECONDS",
        default=None,
        help="Total scan duration in seconds. Omit to run until Ctrl+C.",
    )
    p.add_argument(
        "--devices", "-d",
        type=int,
        metavar="COUNT",
        default=None,
        help="Stop after this many matching devices are found.",
    )
    p.add_argument(
        "--vendor", "-v",
        type=str,
        metavar="NAME",
        default=None,
        help=(
            "Only show devices whose vendor contains this string (case-insensitive). "
            "E.g. --vendor amazon   --vendor apple   --vendor tp-link"
        ),
    )
    p.add_argument(
        "--type", "-T",
        type=str,
        metavar="TYPE",
        default=None,
        help=(
            "Only show devices whose type label contains this string (case-insensitive). "
            "E.g. --type phone   --type router   --type 'smart home'   --type camera"
        ),
    )
    p.add_argument(
        "--cidr", "-c",
        type=str,
        metavar="CIDR",
        default=None,
        help="Network range to scan (e.g. 192.168.1.0/24). Auto-detected if omitted.",
    )
    p.add_argument(
        "--interval", "-i",
        type=float,
        metavar="SECONDS",
        default=10.0,
        help="Seconds between ARP sweeps (default: 10).",
    )
    p.add_argument(
        "--sweep-timeout", "-s",
        type=int,
        metavar="SECONDS",
        default=3,
        help="Per-sweep ARP timeout in seconds (default: 3).",
    )
    p.add_argument(
        "--code", "-C",
        action="store_true",
        default=False,
        help="Print a sweep code after each sweep encoding all found devices.",
    )
    p.add_argument(
        "--filter", "-f",
        type=str,
        metavar="SWEEP_CODE",
        default=None,
        help=(
            "Only show devices NOT present in this sweep code. "
            "Generate a code with --code, then pass it here next run to see new devices only."
        ),
    )
    return p


# ── main ──────────────────────────────────────────────────────────────────────
def main():
    parser = build_parser()
    args   = parser.parse_args()

    vendor_filter = args.vendor
    type_filter   = args.type

    # decode baseline sweep code if --filter was given
    baseline_macs = set()
    if args.filter:
        decoded = decode_sweep_code(args.filter)
        if decoded is None:
            print(C["err"] + "  [!] Invalid sweep code passed to --filter. Was it copied correctly?" + C["reset"])
            sys.exit(1)
        baseline_macs = decoded

    # graceful Ctrl+C
    stop_flag = {"stop": False}

    def _sigint(sig, frame):
        stop_flag["stop"] = True
        print(C["warn"] + "\n  [!] Ctrl+C received -- finishing up..." + C["reset"])

    signal.signal(signal.SIGINT, _sigint)

    # manuf parser
    manuf_parser = None
    if MANUF_AVAILABLE:
        try:
            manuf_parser = manuf.MacParser()
        except Exception:
            pass

    cidr = args.cidr or get_local_cidr()
    print_banner(cidr, args)

    seen_devices  = {}   # mac -> enriched dict (ALL devices, unfiltered)
    start_time    = time.time()
    display_count = 0    # devices that passed filters and were printed
    sweep         = 0

    while not stop_flag["stop"]:
        sweep += 1
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(C["time"] + f"  >> Sweep #{sweep} -- {ts}  ({cidr})" + C["reset"])

        raw = arp_scan(cidr, timeout=args.sweep_timeout)
        new_this_sweep = 0

        for r in raw:
            mac = r["mac"]
            if mac not in seen_devices:
                d = enrich_device(r, manuf_parser)
                seen_devices[mac] = d  # always store; avoids re-enriching

                if not device_matches_filters(d, vendor_filter, type_filter):
                    continue  # stored but not shown -- doesn't match filters

                # --filter: hide devices that were in the baseline sweep
                if baseline_macs and mac in baseline_macs:
                    continue

                display_count += 1
                new_this_sweep += 1
                print_device(d, display_count)

                # --devices applies to displayed (matching) devices only
                if args.devices and display_count >= args.devices:
                    print(C["found"] + f"  [+] Reached {args.devices} matching device(s) -- stopping." + C["reset"])
                    stop_flag["stop"] = True
                    break

        if new_this_sweep == 0:
            if vendor_filter or type_filter or baseline_macs:
                print(C["time"] + "     (no new matching devices this sweep)\n" + C["reset"])
            else:
                print(C["time"] + "     (no new devices this sweep)\n" + C["reset"])

        # print sweep code if --code flag is set
        if args.code:
            print_sweep_code(seen_devices, sweep)

        if stop_flag["stop"]:
            break

        # --time limit
        if args.time and (time.time() - start_time) >= args.time:
            print(C["found"] + f"  [+] Time limit ({args.time}s) reached -- stopping." + C["reset"])
            break

        # interruptible wait between sweeps
        deadline = time.time() + args.interval
        while time.time() < deadline and not stop_flag["stop"]:
            if args.time and (time.time() - start_time) >= args.time:
                stop_flag["stop"] = True
                break
            time.sleep(0.25)

    # summary: apply vendor/type filters AND baseline exclusion
    matched = {
        mac: d for mac, d in seen_devices.items()
        if device_matches_filters(d, vendor_filter, type_filter)
        and (not baseline_macs or mac not in baseline_macs)
    }
    print_summary(matched, start_time, vendor_filter, type_filter)


if __name__ == "__main__":
