# 📡 WiFi Deauth Tool

A powerful, interactive WiFi security auditing tool built with Python and Scapy. This tool provides a streamlined workflow for identifying Access Points (APs), scanning for connected clients, and performing authorized deauthentication attacks for educational and authorized penetration testing purposes.

---

## ✨ Features

- **Automatic Monitor Mode**: Handles the transition of your wireless interface to monitor mode, including killing interfering processes (NetworkManager, wpa_supplicant).
- **Dual-Band Scanning**: Supports both 2.4GHz and 5GHz channel hopping to find all nearby Access Points.
- **Live Signal Visualization**: Real-time RSSI (signal strength) extraction with color-coded ASCII bars and quality labels.
- **Client Discovery**: Scans for active clients communicating with a specific target Access Point.
- **Smart Selection Loop**: Allows re-selecting targets (APs or Stations) without needing to re-scan the entire environment.
- **Robust infinite Attack**: Fixed deauth loop logic ensuring continuous packet delivery.
- **Safety First**: Includes a full attack summary and confirmation prompt before launching any frames.
- **Clean Exit**: Automatically restores your wireless interface to managed mode and restarts NetworkManager on exit or interruption (Ctrl+C).

---

## 🛠️ Installation & Build

### Prerequisites
- **Linux**: Python 3.12+, Scapy, Netifaces, and `iw`/`ip` tools.
- **Privileges**: Must be run as root (`sudo`).

### Build from Source
If you wish to compile the scripts into standalone executables:

```bash
# For Linux
pyinstaller --onefile my_scapy_v2.py
```

---

## 🚀 Usage

### Executables
- **Linux**: Available in the `dist/` directory.
- **Windows**: Available in the `output/` directory (Note: Windows support for monitor mode is hardware and driver dependent).

### Running via Python
```bash
sudo $(which python) my_scapy_v2.py
```

### 📋 Interactive Parameter Table

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| **Interface Index** | Integer | N/A | Choose the wireless adapter to use for the session. |
| **AP Index** | Integer | N/A | Select the target Access Point from the discovered list. |
| **Client Index** | Integer | `0` | Select a specific client or `0` for a **BROADCAST** attack (targets all). |
| **Packet Count** | Integer | `100` | Number of deauth frames to send. Set to `0` for **Infinite Loop**. |
| **Interval** | Float | `0.1` | Time in seconds between each packet. |
| **Reason Code** | Integer | `7` | IEEE 802.11 reason code for deauthentication (7 = Class 3 frame received from nonassociated STA). |

---

## 📊 Signal Strength Reference

| Label | RSSI Range | Description |
| :--- | :--- | :--- |
| 🟢 **Excellent** | ≥ -50 dBm | Maximum performance, very close to target. |
| 🟢 **Good** | -50 to -60 dBm | Very stable and fast connection. |
| 🟡 **Fair** | -60 to -70 dBm | Reasonable signal for most operations. |
| 🔴 **Weak** | -70 to -80 dBm | Unstable, prone to packet loss. |
| 🔴 **Very Weak** | < -80 dBm | Likely to disconnect or fail. |

---

## ⚠️ Disclaimer

**Educational / Authorized Testing Only.**
Unauthorised use of this tool against networks you do not own or have explicit written permission to test is **illegal**. The authors and contributors are not responsible for any misuse or damage caused by this program. Use responsibly.

---

Authored by [itsrajadarsh](https://github.com/itsrajadarsh)
