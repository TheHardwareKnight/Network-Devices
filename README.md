# 🌐 Network Devices

A colour-coded Linux terminal tool for scanning your local network and identifying connected devices by IP, MAC, vendor, and type.

---

## What Is It?

**Network Devices** is a Python script that scans your local network and lists every active device it finds — phones, computers, routers, smart home gadgets, cameras, and more. It runs entirely from the terminal and requires no GUI or web interface.

Each device is displayed with:

- 🟢 **IP address**
- 🟡 **MAC address**
- 🟣 **Hostname** (if resolvable via reverse DNS)
- 🔵 **Vendor** (manufacturer looked up from the MAC address)
- 💙 **Device type** (guessed from the vendor — phone, router, NAS, smart home, etc.)
- ⚪ **Latency** (ping round-trip time)
- ⚪ **Time first seen**

---

## How It Works

The script sends an **ARP broadcast** across your local subnet — every active device on the network responds with its MAC address and IP. This means it finds devices even if they block ping (like Amazon Echos or phones with ICMP disabled).

Once a device responds, the script:

1. Looks up the MAC address prefix against a vendor database (`manuf`) to identify the manufacturer
2. Matches the vendor name against a list of keywords to guess the device type
3. Attempts a reverse DNS lookup to find the hostname
4. Pings the device to measure latency
5. Prints everything to the terminal in colour-coded output

Scans run in **sweeps** — each sweep sends a fresh ARP broadcast and only prints devices not seen before, so the output stays clean across multiple sweeps.

---

## Requirements

- Linux (Ubuntu, Debian, Fedora, Arch, Kali, Raspberry Pi OS, etc.)
- Python 3.8+
- `sudo` / root access (required for raw ARP sockets)

---

## Installation

**1. Clone the repository:**

```bash
git clone https://github.com/TheHardwareKnight/Network-Devices
cd Network-Devices
```

**2. Install Python dependencies:**

```bash
sudo pip3 install -r requirements.txt --break-system-packages
```

> `--break-system-packages` is required on Debian 12+, Ubuntu 23.04+, and Raspberry Pi OS Bookworm. It is safe to use here.

**3. Run it:**

```bash
sudo python3 network.py
```

---

## Usage

```bash
sudo python3 network.py [OPTIONS]
```

### Arguments

| Argument | Short | Description |
|---|---|---|
| `--help` | `-h` | Show help and exit |
| `--time SECONDS` | `-t` | Stop scanning after this many seconds |
| `--devices COUNT` | `-d` | Stop after this many matching devices are found |
| `--vendor NAME` | `-v` | Only show devices whose vendor contains this string |
| `--type TYPE` | `-T` | Only show devices whose type contains this string |
| `--cidr CIDR` | `-c` | Manually set the subnet to scan (e.g. `192.168.1.0/24`) |
| `--interval SECONDS` | `-i` | Seconds between sweeps (default: 10) |
| `--sweep-timeout SECONDS` | `-s` | Per-sweep ARP wait time in seconds (default: 3) |
| `--code` | `-C` | Print a sweep code after each sweep |
| `--filter SWEEP_CODE` | `-f` | Only show devices *not* in the given sweep code |

### Examples

```bash
# Scan forever, Ctrl+C to stop
sudo python3 network.py

# Scan for 60 seconds then exit
sudo python3 network.py --time 60

# Only show Amazon devices
sudo python3 network.py --vendor amazon

# Only show phones
sudo python3 network.py --type phone

# Only show routers and switches
sudo python3 network.py --type router

# Scan a specific subnet
sudo python3 network.py --cidr 10.0.0.0/24
```

---

## Sweep Codes — Spot New Devices

The sweep code feature lets you take a snapshot of your network, then later scan for only **new devices** that weren't there before. Useful for spotting unexpected guests or unknown devices.

**Step 1 — scan your baseline and save the code:**

```bash
sudo python3 network.py --time 30 --code
```

A code is printed at the end of each sweep:

```
  Sweep #1 code (12 device(s) encoded):
  QzQ6OTU6MDA6NDc6Mjg6NEQsQUE6QkI6Q0M6...

  Use with --filter <code> to show only NEW devices next run.
```

**Step 2 — run again later with that code:**

```bash
sudo python3 network.py --filter QzQ6OTU6MDA6NDc6Mjg6NEQsQUE6QkI6Q0M6...
```

Only devices **not** in the baseline will be shown. The code is based on MAC addresses rather than IPs, so it stays accurate even if devices reconnect on a different IP.

---

## Device Types

| `--type` keyword | Matches |
|---|---|
| `phone` | Apple Mobile, Android Mobile |
| `apple` | Apple Mobile |
| `android` | Android Mobile |
| `raspberry` | Raspberry Pi |
| `computer` | Computer / Laptop |
| `nas` | NAS / Storage |
| `router` | Router / Switch |
| `amazon` | Amazon Device |
| `google` | Google / Nest |
| `smart home` | Smart Home / IoT |
| `gaming` | Gaming Console |
| `printer` | Printer |
| `virtual` | Virtual Machine |
| `camera` | IP Camera |
| `server` | Server |
| `unknown` | Unrecognised devices |

---

## Notes

- Devices that block ping will still show up — ARP bypasses ICMP filtering. Latency will just show `—`
- The script must be run with `sudo` because ARP scanning requires raw socket access
- If a vendor can't be identified from the MAC, device type will show as `❓ Unknown`
- If you have multiple network interfaces, use `--cidr` to specify which subnet to scan

---

## License

MIT — do whatever you like with it.
