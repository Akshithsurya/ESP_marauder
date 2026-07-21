<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:E7352C,100:00979D&height=200&section=header&text=ESP_Penetrator&fontSize=55&fontColor=ffffff&animation=fadeIn&fontAlignY=38&desc=ESP32%20%2F%20ESP8266%20Security%20Testing%20Suite&descAlignY=58&descSize=18" width="100%"/>

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=20&duration=3000&pause=800&color=E7352C&center=true&vCenter=true&width=600&lines=Recon+%7C+Deauth+%7C+Handshake+Capture;Evil+Portal+%7C+PMKID+%7C+Beacon+Flood;Educational+%26+Authorized-Use+Only" alt="Typing SVG" />

![ESP32](https://img.shields.io/badge/ESP32-E7352C?style=for-the-badge&logo=espressif&logoColor=white)
![ESP8266](https://img.shields.io/badge/ESP8266-black?style=for-the-badge&logo=espressif&logoColor=white)
![Arduino](https://img.shields.io/badge/Arduino_IDE-00979D?style=for-the-badge&logo=arduino&logoColor=white)
![License](https://img.shields.io/badge/License-Educational_Use-yellow?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-2.4-blue?style=for-the-badge)

</div>

---

## ⚠️ Legal Disclaimer

> **This software is a security testing tool intended for educational purposes and authorized testing only.**

| ⚠️ | Rule |
|---|---|
| 🔒 | Use strictly on networks you own or have explicit permission to audit. |
| 🚫 | Misuse to disrupt networks you do not own is illegal. |
| 📜 | The authors assume no liability for misuse of this code. |

---

## 📖 Introduction

This firmware provides a comprehensive suite of WiFi penetration testing tools for the ESP32 and ESP8266 platforms — reconnaissance, active attacks, credential harvesting (Evil Portal), and packet monitoring (Sniffer), all controlled from a lightweight onboard web dashboard.

<div align="center">
<img src="https://img.shields.io/badge/Dual--Core%20Stable-ESP32-success?style=flat-square"/>
<img src="https://img.shields.io/badge/Single--Core%20Constrained-ESP8266-orange?style=flat-square"/>
<img src="https://img.shields.io/badge/Interface-Web%20Dashboard-informational?style=flat-square"/>
</div>

---

## 📑 Table of Contents

- [Hardware Requirements](#-hardware-requirements)
- [Software Requirements](#-software-requirements)
- [Installation](#-installation)
- [First Boot & Access](#-first-boot--access)
- [Web Interface Guide](#️-web-interface-guide)
- [Troubleshooting](#️-troubleshooting)
- [API Endpoints Reference](#-api-endpoints-reference)
- [Porting Notes](#-porting-notes-esp32-vs-esp8266)
- [Credits](#-credits)

---

## 🔧 Hardware Requirements

<details open>
<summary><b>ESP32 Version</b></summary>

| Spec | Detail |
|---|---|
| **Board** | ESP32 DevKit, NodeMCU-32S, WROOM-32, or similar |
| **RAM** | Standard built-in RAM is sufficient |
| **Features** | Dual-core processing → stable packet injection and sniffer operations simultaneously |

</details>

<details>
<summary><b>ESP8266 Version</b></summary>

| Spec | Detail |
|---|---|
| **Board** | NodeMCU 1.0 (ESP-12E), Wemos D1 Mini, or similar |
| **RAM** | Limited. High packet rates may cause watchdog resets |
| **Dependencies** | Requires `user_interface.h` for raw packet injection and promiscuous mode |
| **Limitations** | "Host Scan" relies on SoftAP station count — no client MAC display (SDK limitation) |

</details>

---

## 💻 Software Requirements

- **Arduino IDE:** Version 1.8.x or newer
- **Board Manager:**
  - ESP32 → install `esp32` by Espressif Systems
  - ESP8266 → install `esp8266` by Espressif Systems
- **Libraries** *(bundled with core install — no external downloads)*:
  - `WiFi.h` / `ESP8266WiFi.h`
  - `WebServer.h` / `ESP8266WebServer.h`
  - `DNSServer.h`

---

## 📥 Installation

```
1. Download the appropriate .ino file (ESP32_kill.ino or ESP8266_kill.ino)
2. Open the file in the Arduino IDE
3. Tools > Board > Generic ESP8266 Module  (or)  ESP32 Dev Module
4. Tools > Upload Speed > 115200
5. Click Upload
```

---

## 🚀 First Boot & Access

| Step | Action |
|:---:|---|
| 1 | Power on the microcontroller |
| 2 | Search for WiFi networks from a laptop or phone |
| 3 | Connect to **`TTAN_PenTest`** |
| 4 | Enter password **`pentester123`** |
| 5 | Browse to **`http://192.168.4.1`** |
| 6 | Dashboard loads |

> 🛠️ **Admin Panel** (captured credentials view) → `http://192.168.4.1:8080`

---

## 🖥️ Web Interface Guide

The dashboard has three sections: **System Status**, **Reconnaissance**, and **Attacks & Tools**.

### 🔍 1. Reconnaissance

<details open>
<summary><b>WiFi Scan</b></summary>

Scans for nearby Access Points. The ESP briefly disconnects from its own AP to scan — a "Scanning…" screen appears and reloads automatically. Don't change your device's WiFi connection mid-scan.

**Results:** SSID · Signal Strength · Channel · BSSID · Encryption type

</details>

<details>
<summary><b>Host Scan</b></summary>

Displays the number of clients connected to the ESP's AP.
> Note: ESP8266 does not expose individual client MAC addresses.

</details>

### ⚔️ 2. Attacks & Tools

Use the Channel dropdown (1–13) to select the target frequency.

| Tool | Function |
|---|---|
| **Monitor — Channel Analysis** | Locks to a channel, shows live packet stats (Management / Control / Data) |
| **Monitor — Channel Hopper** | Auto-cycles channels 1–13 for full-spectrum capture |
| **Deauth** *(from Scan Results)* | Sends forged 802.11 deauth frames — disconnects clients from the target AP |
| **Beacon Flood** | Broadcasts fake beacon frames under a chosen SSID |
| **Probe Flood** | Spams fake probe requests to surface hidden networks / generate noise |
| **PMKID Capture** | Passively captures RSN info frames — no client handshake required |
| **Handshake Capture** | Promiscuous-mode WPA/WPA2 4-way handshake logging; pair with Deauth to force a reconnect |
| **Evil Portal** | Clones an SSID, serves a fake login page, harvests submitted credentials |
| **Karma Attack** | Answers all nearby probe requests, tricking devices into auto-connecting |

> 📊 **Handshake logs:** "View Handshakes" in the dashboard
> 🔑 **Evil Portal captures:** Port 8080 → `/admin`

---

## 🛠️ Troubleshooting

<details>
<summary><b>Scan button fails / page unavailable</b></summary>

**Cause:** switching modes to scan drops the client connection.
**Fix:** wait 10–15s for the interstitial "Scanning…" page to resolve and auto-reload.

</details>

<details>
<summary><b>ESP8266 instability / Guru Meditation Error</b></summary>

**Cause:** limited RAM/CPU vs ESP32 — concurrent web traffic + packet injection can trip the Watchdog Timer.
**Fix:**
- Raise `WATCHDOG_TIMEOUT` in config (if defined)
- Reduce simultaneous active attacks
- Avoid a slow Serial Monitor baud rate during active attacks

</details>

<details>
<summary><b>Attacks not working</b></summary>

- **Channel mismatch** — confirm dropdown matches the target AP's channel
- **Signal strength** — ESP and target must be within range of each other
- **Router protections** — some modern routers block deauth / beacon floods

</details>

<details>
<summary><b>Admin panel / captured credentials</b></summary>

Open a separate tab to `http://192.168.4.1:8080/admin` to monitor captures live without disrupting the portal view.

</details>

---

## 🔌 API Endpoints Reference

**Main Server — Port 80**

| Endpoint | Description |
|---|---|
| `GET /` | Main Dashboard |
| `GET /s` | Start WiFi Scan |
| `GET /h` | Start Host Scan |
| `GET /d?m=...` | Start Deauth — args: `m=MAC`, `s=SSID`, `c=Channel` |
| `GET /stop` | Stop all active attacks |
| `GET /r` | Reboot the device |

**Admin Server — Port 8080**

| Endpoint | Description |
|---|---|
| `GET /admin` | View captured credentials table |
| `GET /admin/json` | Download credentials as JSON |
| `GET /admin/clear` | Wipe all captured data |

---

## 🔄 Porting Notes (ESP32 vs ESP8266)

| Feature | ESP32 | ESP8266 |
|---|---|---|
| Low-Level Access | `esp_wifi.h` (Official IDF) | `user_interface.h` (RTOS SDK) |
| Packet Injection | `esp_wifi_80211_tx` | `wifi_send_pkt_freedom` |
| Sniffer Callback | Struct w/ metadata (RSSI, rate) | Raw buffer (buf, len) only |
| Performance | High stability, dual-core | Moderate, single-core |

---

## 👤 Credits

<div align="center">

| | |
|---|---|
| **Version** | 2.4 |
| **Author** | Ak_45 |
| **License** | Educational Use Only |

### ⭐ If this project is useful, consider starring the repo

![Stars](https://img.shields.io/github/stars/Akshithsurya?style=social)

</div>

---

<div align="center">
<img src="https://capsule-render.vercel.app/api?type=waving&color=0:00979D,100:E7352C&height=100&section=footer"/>

**Always use responsibly and ethically — only test on networks you own or have explicit written permission to test.**

</div>
