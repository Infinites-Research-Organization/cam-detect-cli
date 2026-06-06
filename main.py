#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import math
import os
import re
import subprocess
import time
import threading
import signal
import sys
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich import box

# -------------------------------------------------------------
# Global console & monitor-interface placeholder
# -------------------------------------------------------------
console = Console()
MON_INTERFACE = None

# -------------------------------------------------------------
# Argument parsing
# -------------------------------------------------------------
def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Advanced WiFi Monitor, Tracker & OUI Matcher"
    )
    parser.add_argument(
        "--interface", required=True, help="Base interface (e.g., wlan0)"
    )
    parser.add_argument(
        "--find", required=False, help="Path to target MAC CSV"
    )
    parser.add_argument(
        "--band",
        default="bg",
        choices=["bg", "a", "abg"],
        help="bg (2.4GHz), a (5GHz), or abg (both) scanning",
    )
    parser.add_argument(
        "--all",
        "--no-list",
        action="store_true",
        help="Print ALL detected devices instead of filtering by the CSV target list",
    )
    parser.add_argument(
        "--hop-interval",
        type=float,
        default=0.5,
        help="Seconds to dwell on each channel (default: 0.5)",
    )
    args = parser.parse_args()

    if not args.all and not args.find:
        parser.error(
            "--find <csv-filepath> is required unless running in --all / --no-list mode."
        )
    return args


# -------------------------------------------------------------
# Cleanup & signal handling
# -------------------------------------------------------------
def cleanup_and_restore():
    global MON_INTERFACE

    if MON_INTERFACE:
        console.print(
            f"\n[bold yellow][*][/bold yellow] Disabling monitor mode on {MON_INTERFACE}..."
        )
        try:
            subprocess.run(
                ["sudo", "airmon-ng", "stop", MON_INTERFACE],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except Exception:
            pass

    console.print("[bold blue][*][/bold blue] Restarting system network daemons...")
    for svc in ("NetworkManager", "wpa_supplicant"):
        try:
            subprocess.run(
                ["sudo", "systemctl", "restart", svc],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except Exception:
            pass

    console.print("[bold green][+][/bold green] Network stack successfully restored. Goodbye!")
    sys.exit(0)


def signal_handler(sig, frame):
    cleanup_and_restore()


# -------------------------------------------------------------
# Enable monitor mode
# -------------------------------------------------------------
def start_monitor_mode(interface, *, timeout=15):
    """Enable monitor mode on *interface* and return the new monitor name."""
    global MON_INTERFACE

    console.print("[bold yellow][*] Killing interfering network processes…[/bold yellow]")
    subprocess.run(
        ["sudo", "airmon-ng", "check", "kill"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=timeout,
    )
    time.sleep(1)

    console.print(f"[bold blue][*] Enabling monitor mode on {interface}…[/bold blue]")

    # Capture PHY id before the change
    phy_id = None
    try:
        iw_before = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=timeout
        ).stdout
        m = re.search(rf"phy#(\d+).*?Interface\s+{re.escape(interface)}\b", iw_before, re.DOTALL)
        if m:
            phy_id = m.group(1)
    except Exception:
        pass

    # Start monitor mode
    result = subprocess.run(
        ["sudo", "airmon-ng", "start", interface],
        capture_output=True, text=True, timeout=timeout,
    )
    stdout = (result.stdout or "") + (result.stderr or "")

    # Preferred airmon-ng parsing
    m = re.search(r"monitor mode (?:vif )?enabled\s*(?:on|as)?\s*([a-zA-Z0-9_-]+)", stdout, re.IGNORECASE)
    if m:
        MON_INTERFACE = m.group(1).strip()
        console.print(f"[bold green][+] Monitor mode active on: [bold cyan]{MON_INTERFACE}[/bold cyan]")
        return MON_INTERFACE

    console.print("[bold yellow][!] Interface not found in airmon-ng output; inspecting iw dev…[/bold yellow]")

    # Fallback using iw dev
    try:
        iw_after = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=timeout
        ).stdout

        # Look inside the same PHY block first
        if phy_id:
            phy_blocks = re.split(r"phy#\d+", iw_after)
            for blk in phy_blocks:
                iface_m = re.search(r"Interface\s+([a-zA-Z0-9_-]+)", blk)
                type_m = re.search(r"type\s+monitor", blk)
                if iface_m and type_m:
                    MON_INTERFACE = iface_m.group(1)
                    console.print(f"[bold green][+] Detected monitor interface: [bold cyan]{MON_INTERFACE}[/bold cyan]")
                    return MON_INTERFACE

        # Any monitor-type interface as last resort
        iface = re.search(r"Interface\s+([a-zA-Z0-9_-]+)\s.*?type\s+monitor", iw_after, re.DOTALL)
        if iface:
            MON_INTERFACE = iface.group(1)
            console.print(f"[bold green][+] Fallback monitor interface: [bold cyan]{MON_INTERFACE}[/bold cyan]")
            return MON_INTERFACE
    except Exception as e:
        console.print(f"[bold red][!] Error querying interfaces: {e}")

    console.print("[bold red][!] Failed to determine monitor interface. Exiting.")
    sys.exit(1)


# -------------------------------------------------------------
# Load target MAC addresses (exact & OUI prefix)
# -------------------------------------------------------------
def load_mac_targets(filepath):
    exact_targets = {}
    prefix_targets = {}

    if not filepath or not os.path.exists(filepath):
        return exact_targets, prefix_targets

    with open(filepath, mode="r", encoding="utf-8", errors="ignore") as f:
        reader = csv.reader(f)
        next(reader, None)  # skip header if present
        for row in reader:
            if not row:
                continue
            mac_raw = row[0].strip() if len(row) > 0 else ""
            org_name = (row[1].strip() if len(row) > 1 else "").strip() or "Unknown"
            clean_mac = re.sub(r"[^a-fA-F0-9]", "", mac_raw).upper()
            if not clean_mac:
                continue
            if len(clean_mac) == 6:  # OUI prefix only
                prefix_targets[clean_mac] = org_name
            else:
                exact_targets[clean_mac] = org_name
    return exact_targets, prefix_targets


# -------------------------------------------------------------
# Channel hopper – runs independently of airodump-ng
# -------------------------------------------------------------

BAND_CHANNELS = {
    "bg":  list(range(1, 14)),
    "a":   [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116,
            120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165],
    "abg": list(range(1, 14)) + [36, 40, 44, 48, 52, 56, 60, 64, 100,
            104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 149, 153,
            157, 161, 165],
}

# Shared state so the UI can show the current channel
_hop_state = {"current": None, "index": 0}
_hop_lock  = threading.Lock()


def channel_hopper(interface: str, band: str, interval: float, stop_event: threading.Event):
    """
    Continuously cycle through channels using `iw dev <iface> set channel`.
    Uses a stop_event so it exits cleanly when the main loop finishes.

    Key fix vs. the original:
      - airodump-ng is launched WITHOUT a fixed channel (-c), so it does not
        fight with our hopper.
      - We dwell `interval` seconds on each channel (configurable via
        --hop-interval, default 0.5 s).
      - We update _hop_state so the UI can display the current channel.
    """
    channels = BAND_CHANNELS.get(band, BAND_CHANNELS["bg"])
    idx = 0
    while not stop_event.is_set():
        ch = channels[idx % len(channels)]
        with _hop_lock:
            _hop_state["current"] = ch
            _hop_state["index"]   = idx
        try:
            subprocess.run(
                ["sudo", "iw", "dev", interface, "set", "channel", str(ch)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=2,
            )
        except Exception:
            pass
        idx += 1
        stop_event.wait(interval)   # interruptible sleep


def channel_to_freq(ch: int) -> int:
    """Convert channel number to approximate centre frequency (MHz)."""
    if 1 <= ch <= 13:
        return 2407 + ch * 5
    if ch == 14:
        return 2484
    if 36 <= ch <= 177:
        return 5000 + ch * 5
    return 2412  # fallback


# -------------------------------------------------------------
# Distance calculation (Free-space path loss)
# -------------------------------------------------------------
def calculate_distance(rssi: int, channel: int = 6) -> str:
    try:
        freq = channel_to_freq(channel)
        # FSPL rearranged: d = 10 ^ ((FSPL_dB - 20*log10(f) + 27.55) / 20)
        exp  = (27.55 - (20 * math.log10(freq)) + abs(rssi)) / 20.0
        dist = 10 ** exp
        if dist < 1:
            return f"~{dist*100:.0f}cm"
        if dist < 1000:
            return f"~{dist:.1f}m"
        return ">1km"
    except Exception:
        return "?"


# -------------------------------------------------------------
# UI table generation – stable, no Spinner inside Live
# -------------------------------------------------------------
def generate_ui_table(live_matches: dict, is_all_mode: bool, scan_start: float) -> Table:
    elapsed = int(time.time() - scan_start)
    with _hop_lock:
        cur_ch = _hop_state["current"]

    ch_str   = f"ch {cur_ch}" if cur_ch else "scanning…"
    title_mode = "All Devices" if is_all_mode else "Filtered Targets"
    title = (
        f"🎯 [bold magenta]{title_mode}[/bold magenta]  "
        f"[dim]│ elapsed {elapsed}s │ hopping {ch_str}[/dim]"
    )

    table = Table(title=title, box=box.SIMPLE_HEAVY, expand=True)
    table.add_column("Org / Label",    justify="left",   style="green",     max_width=28, overflow="fold")
    table.add_column("MAC Address",    justify="center", style="cyan",      no_wrap=True)
    table.add_column("SSID",          justify="left",   style="bright_blue", max_width=22, overflow="fold")
    table.add_column("Ch",            justify="center", style="yellow",    no_wrap=True)
    table.add_column("RSSI",          justify="center", style="bold red",  no_wrap=True)
    table.add_column("Est. Dist",     justify="center", style="bold white", no_wrap=True)
    table.add_column("Last Seen",     justify="right",  style="dim",       no_wrap=True)

    if not live_matches:
        table.add_row("Waiting for airodump-ng…", "-", "-", "-", "-", "-", "-")
        return table

    # Sort strongest signal first
    sorted_items = sorted(
        live_matches.items(),
        key=lambda kv: kv[1].get("rssi", -1000),
        reverse=True,
    )

    for _, dev in sorted_items:
        age      = int(time.time() - dev.get("last_seen", time.time()))
        rssi_val = dev.get("rssi")
        rssi_str = f"{rssi_val} dBm" if isinstance(rssi_val, int) else "-"
        age_str  = f"{age}s ago" if age < 3600 else f"{age//60}m ago"

        # Dim rows that haven't been seen recently
        row_style = "dim" if age > 30 else ""
        table.add_row(
            dev.get("org",      "Unknown"),
            dev.get("mac",      "-"),
            dev.get("ssid",     ""),
            str(dev.get("channel", "?")),
            rssi_str,
            dev.get("distance", "?"),
            age_str,
            style=row_style,
        )

    return table


# -------------------------------------------------------------
# CSV parsing helpers
# -------------------------------------------------------------
def parse_airodump_csv(path: str):
    """
    Parse airodump-ng CSV output.  Returns two lists:
      ap_rows      – rows from the AP section (above the blank line)
      client_rows  – rows from the station/client section (below)
    """
    ap_rows, client_rows = [], []
    in_clients = False

    try:
        with open(path, mode="r", errors="ignore") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or all(c.strip() == "" for c in row):
                    in_clients = True
                    continue
                first = row[0].strip()
                if "BSSID" in first or "Station" in first:
                    continue
                if in_clients:
                    client_rows.append(row)
                else:
                    ap_rows.append(row)
    except (IOError, PermissionError):
        pass

    return ap_rows, client_rows


def clean_mac(raw: str) -> str:
    return re.sub(r"[^a-fA-F0-9]", "", raw).upper()


def fmt_mac(clean: str) -> str:
    c = clean[:12]
    return ":".join(c[i:i+2] for i in range(0, len(c), 2))


# -------------------------------------------------------------
# Main monitoring / matching loop
# -------------------------------------------------------------
def monitor_and_match(
    monitor_iface: str,
    exact_targets: dict,
    prefix_targets: dict,
    band: str,
    is_all_mode: bool,
    hop_interval: float,
):
    csv_prefix = "/tmp/wardriver_scan"
    csv_file   = f"{csv_prefix}-01.csv"

    # Clean stale output from any previous run
    for f in [csv_file]:
        try:
            if os.path.exists(f):
                os.remove(f)
        except Exception:
            pass

    # ── Start channel hopper ──────────────────────────────────
    stop_hop = threading.Event()
    hopper   = threading.Thread(
        target=channel_hopper,
        args=(monitor_iface, band, hop_interval, stop_hop),
        daemon=True,
    )
    hopper.start()
    console.print(f"[bold green][+][/bold green] Channel hopper started "
                  f"({len(BAND_CHANNELS[band])} channels, {hop_interval}s dwell each)")

    # Give the hopper a moment to set the first channel
    time.sleep(0.3)

    # ── Launch airodump-ng WITHOUT -c so it doesn't pin a channel ──
    console.print("[bold blue][*][/bold blue] Spawning airodump-ng background scanner...")
    proc = subprocess.Popen(
        [
            "sudo", "airodump-ng",
            monitor_iface,
            "-w", csv_prefix,
            "--output-format", "csv",
            "--write-interval", "1",   # flush CSV every second
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    console.print("[bold green][+][/bold green] Scanner running – press Ctrl+C to stop.\n")
    time.sleep(2)  # let airodump create its CSV before we try to open it

    live_matches: dict = {}
    prev_snapshot      = None
    scan_start         = time.time()

    # ── Live display loop ────────────────────────────────────
    # Use screen=False so the terminal doesn't go into alt-screen;
    # this avoids the garbled-output bug that screen=True causes when
    # Rich's internal state gets out of sync with the terminal.
    with Live(
        generate_ui_table(live_matches, is_all_mode, scan_start),
        refresh_per_second=2,
        screen=False,
        transient=False,
    ) as live:
        try:
            while True:
                time.sleep(0.4)

                if not os.path.exists(csv_file):
                    continue

                ap_rows, _ = parse_airodump_csv(csv_file)

                for row in ap_rows:
                    if len(row) < 4:
                        continue

                    raw_mac  = row[0].strip()
                    cmac     = clean_mac(raw_mac)
                    if len(cmac) < 12:
                        continue

                    # ── Match logic ──────────────────────────
                    org_name    = None
                    match_found = False

                    if is_all_mode:
                        match_found = True
                        org_name    = exact_targets.get(cmac) \
                                   or prefix_targets.get(cmac[:6]) \
                                   or "Unknown"
                    else:
                        if cmac in exact_targets:
                            org_name    = exact_targets[cmac]
                            match_found = True
                        elif cmac[:6] in prefix_targets:
                            org_name    = prefix_targets[cmac[:6]]
                            match_found = True

                    if not match_found:
                        continue

                    # ── Extract fields ───────────────────────
                    # airodump-ng AP CSV columns:
                    # 0:BSSID 1:First time seen 2:Last time seen 3:channel
                    # 4:Speed 5:Privacy 6:Cipher 7:Auth 8:Power 9:beacons
                    # 10:# IV 11:LAN IP 12:ID-length 13:ESSID 14:Key

                    try:
                        channel_raw = row[3].strip()
                        channel     = int(channel_raw) if channel_raw.lstrip("-").isdigit() else 0
                    except (ValueError, IndexError):
                        channel = 0

                    try:
                        rssi_raw = row[8].strip() if len(row) > 8 else ""
                        rssi_int = int(re.sub(r"[^0-9-]", "", rssi_raw))
                        if rssi_int > 0 or rssi_int < -150:
                            continue          # nonsense value – skip
                    except (ValueError, IndexError):
                        continue

                    ssid = row[13].strip() if len(row) > 13 else ""

                    live_matches[cmac] = {
                        "org":      org_name,
                        "mac":      fmt_mac(cmac),
                        "ssid":     ssid,
                        "channel":  channel if channel > 0 else "?",
                        "rssi":     rssi_int,
                        "distance": calculate_distance(rssi_int, channel if channel > 0 else 6),
                        "last_seen": time.time(),
                    }

                # Only redraw when something changed (prevents flicker)
                snapshot = tuple((k, v["rssi"], v["last_seen"]) for k, v in sorted(live_matches.items()))
                if snapshot != prev_snapshot:
                    live.update(generate_ui_table(live_matches, is_all_mode, scan_start))
                    prev_snapshot = snapshot

        except KeyboardInterrupt:
            console.print("\n[bold yellow]Interrupted – stopping scan…[/bold yellow]")
        finally:
            stop_hop.set()
            try:
                proc.terminate()
                proc.wait(timeout=4)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            for f in [csv_file]:
                try:
                    if os.path.exists(f):
                        os.remove(f)
                except Exception:
                    pass


# -------------------------------------------------------------
# Entry point
# -------------------------------------------------------------
if __name__ == "__main__":
    if os.geteuid() != 0:
        console.print(
            "[bold red][!][/bold red] Error: Script must be run as root ([bold]sudo[/bold])."
        )
        sys.exit(1)

    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    args = parse_arguments()
    exact, prefixes = load_mac_targets(args.find)

    try:
        monitor_name = start_monitor_mode(args.interface)
        monitor_and_match(
            monitor_name,
            exact,
            prefixes,
            args.band,
            args.all,
            args.hop_interval,
        )
    finally:
        cleanup_and_restore()
