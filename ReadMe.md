# Camera/Wifi Sniffer CLI (In Development)

A terminal-based WiFi monitoring tool that automates monitor mode, channel hopping, and real-time device tracking. It uses `airodump-ng` as the packet capture engine and provides a clean, reactive UI using the `rich` library.

---

## Features

* **Automated Monitor Mode:** Automatically handles the interface transition and cleans up system network daemons (`NetworkManager`, `wpa_supplicant`) on exit.
* **Intelligent Channel Hopping:** Cycles through 2.4GHz/5GHz channels independently of the capture process.
* **Real-time Tracking:** Displays a live, sorted table of detected devices.
* **Target Filtering:** Filter results by a specific list of MAC addresses or OUI prefixes provided via CSV.
* **Proximity Estimation:** Estimates physical distance based on RSSI and frequency.
* **Clean UI:** Uses `rich` for a responsive, clean terminal dashboard.
* **Camera-Mac-Address Database (WIP):** A Camera Detection Database for major companies like Ring, Hikivision, etc you can pass with the --find flag

---

## Prerequisites & Setup

This script requires `aircrack-ng` and standard Linux networking utilities installed:

```bash
sudo apt update
sudo apt install aircrack-ng iw

```

### Virtual Environment Setup

It is highly recommended to run this in a virtual environment to manage dependencies:

```bash
# Create the virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install dependencies
pip install rich

```

---

## Usage

The script must be run with **root/sudo** privileges. When using a virtual environment with `sudo`, you must preserve the environment's `PATH` to ensure the correct Python and libraries are used.

### Execution Command

```bash
sudo env "PATH=$PATH" python3 main.py --interface <interface> [options]

```

### Options

| Argument | Description |
| --- | --- |
| `--interface` | The base interface to use (e.g., `wlan0`). |
| `--find` | Path to a CSV file containing MAC addresses to watch. |
| `--band` | Frequency band to scan: `bg` (2.4GHz), `a` (5GHz), or `abg` (both). |
| `--all` | Print ALL detected devices (ignores the `--find` filter). |
| `--hop-interval` | Seconds to dwell on each channel (default: 0.5). |

### CSV Format for `--find`

Create a simple CSV file (e.g., `targets.csv`):

```csv
AA:BB:CC:DD:EE:FF,My Laptop
11:22:33,Company Prefix

```

### Examples

**Scan all devices on both bands:**

```bash
sudo env "PATH=$PATH" python3 main.py --interface wlan0 --all --band abg

```

**Monitor specific targets in a file:**

```bash
sudo env "PATH=$PATH" python3 main.py --interface wlan0 --find targets.csv --band bg

```

---

## Disclaimer

This tool is for **educational and authorized security auditing purposes only**. Ensure you have explicit permission to monitor wireless traffic in your environment. Unauthorized monitoring may be illegal.

---

## How it Works

1. **Preparation:** The script calls `airmon-ng check kill` to stop conflicting services.
2. **Monitor Mode:** It uses `airmon-ng` and `iw` to switch your wireless card into monitor mode.
3. **Hopping:** A background thread iterates through channels by executing `iw dev <iface> set channel <x>`.
4. **Capture:** `airodump-ng` is spawned in the background to capture traffic and write periodically to a temporary CSV file.
5. **UI:** The main thread polls the CSV file, processes the data, calculates distances, and updates the `rich` Live table.
6. **Cleanup:** On `Ctrl+C`, the script restores the original interface state and restarts your network services.


## Creds, Add your username/other info when Contributing :)
OpLumina
