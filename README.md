<div align="center">

# 📡 WiFi Audit Tool

**Professional WPA/WPA2 handshake capture & hc22000 hash extraction toolkit**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=flat-square&logo=linux)](https://kernel.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Aircrack-ng](https://img.shields.io/badge/Powered%20by-aircrack--ng-red?style=flat-square)](https://aircrack-ng.org)

*Designed exclusively for authorized security testing and network auditing.*

</div>

---

## 🔍 Overview

**WiFi Audit Tool** is a Python-based command-line toolkit that automates the full WPA/WPA2 handshake capture workflow — from putting your adapter into monitor mode to producing a ready-to-crack `hc22000` hash file compatible with **Hashcat**.

All steps are wrapped in a rich, color-coded terminal UI with animated progress bars and Russian-language prompts, making the process transparent and easy to follow for security professionals.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🔧 **Auto-dependency installer** | Detects `pacman` / `apt-get` / `dnf` and installs missing tools automatically |
| 📻 **Adapter discovery** | Lists all wireless interfaces with PHY, MAC address, and current mode |
| 🎛️ **Monitor mode management** | Enables monitor mode via `airmon-ng`, auto-detects the new interface name (`wlan0mon`, etc.) |
| 📶 **Network scanner** | Scans with `airodump-ng` and displays BSSID, ESSID, channel, signal strength (visual bar), and encryption type |
| 🎯 **Target selection** | Interactive numbered menu to select the target AP |
| 💥 **Deauthentication attack** | Sends deauth packets via `aireplay-ng` every 10 seconds to force client reconnection |
| 🤝 **Handshake capture** | Captures `.cap` file via `airodump-ng` with real-time detection loop |
| 🔄 **hc22000 conversion** | Converts `.cap` → `.hc22000` via `hcxpcapngtool` for direct use with Hashcat |
| 💾 **Hash export** | Displays captured hash in a panel and saves it as `handshake_<timestamp>.hc22000` |
| 🖥️ **Rich terminal UI** | Color-coded tables, animated spinners, progress bars, and panels via the `rich` library |
| 🔁 **Interface restoration** | Optionally restores the adapter to managed mode and restarts NetworkManager on exit |

---

## ⚙️ Requirements

### System

| Requirement | Version |
|---|---|
| Operating System | **Linux** (Arch, Debian/Ubuntu, Fedora, Kali, Parrot) |
| Python | **3.8+** |
| Privileges | **root** (`sudo`) |

### External Tools

All tools are installed automatically if missing. Manual install commands are shown below.

| Tool | Package (Arch) | Package (Debian/Ubuntu) | Purpose |
|---|---|---|---|
| `airmon-ng` | `aircrack-ng` | `aircrack-ng` | Monitor mode management |
| `airodump-ng` | `aircrack-ng` | `aircrack-ng` | Network scanning & packet capture |
| `aireplay-ng` | `aircrack-ng` | `aircrack-ng` | Deauthentication packets |
| `hcxpcapngtool` | `hcxtools` | `hcxtools` | Convert `.cap` → `hc22000` |
| `hcxdumptool` | `hcxdumptool` | `hcxdumptool` | Alternative capture backend |
| `iw` / `iwconfig` | `iw` | `iw` | Interface detection |

### Python Library

| Library | Install |
|---|---|
| `rich` | `sudo pacman -S python-rich` / `pip install rich` |

---

## 📦 Installation

### 1. Clone the repository

```bash
git clone https://github.com/TIMATONIK/wifi-audit-tool.git
cd wifi-audit-tool
```

### 2. Install system dependencies

**Arch Linux / CachyOS / Manjaro:**
```bash
sudo pacman -S aircrack-ng hcxtools hcxdumptool iw python-rich
```

**Debian / Ubuntu / Kali Linux:**
```bash
sudo apt-get update
sudo apt-get install aircrack-ng hcxtools hcxdumptool iw python3-rich
```

**Fedora / RHEL:**
```bash
sudo dnf install aircrack-ng hcxtools hcxdumptool iw python3-rich
```

> **Note:** If you skip this step, the script will attempt to install missing packages automatically on first run.

### 3. Make the script executable

```bash
chmod +x wifi_audit.py
```

---

## 🚀 Usage

Always run with root privileges:

```bash
sudo python3 wifi_audit.py
```

### Step-by-step workflow

```
1. Confirm you have authorization for the target network
2. Script checks and installs required tools
3. Select your wireless adapter from the list
4. Adapter is switched to monitor mode
5. Set scan duration (default: 15 seconds)
6. Select target network from the discovered list
7. Set capture duration (default: 60 seconds)
8. Deauth + capture runs automatically
9. .cap file is converted to .hc22000
10. Hash is displayed and saved to disk
```

### Cracking the hash with Hashcat

```bash
# Basic dictionary attack
hashcat -m 22000 handshake_20240101_120000.hc22000 wordlist.txt

# With rules (faster cracking)
hashcat -m 22000 handshake_20240101_120000.hc22000 wordlist.txt \
        -r /usr/share/hashcat/rules/best64.rule

# With rockyou wordlist
hashcat -m 22000 handshake_20240101_120000.hc22000 /usr/share/wordlists/rockyou.txt
```

---

## 🖥️ Example Output

```
 ██╗    ██╗██╗███████╗██╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗
 ██║    ██║██║██╔════╝██║     ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
 ██║ █╗ ██║██║█████╗  ██║     ███████║██║   ██║██║  ██║██║   ██║
 ██║███╗██║██║██╔══╝  ██║     ██╔══██║██║   ██║██║  ██║██║   ██║
 ╚███╔███╔╝██║██║     ██║     ██║  ██║╚██████╔╝██████╔╝██║   ██║
  ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝

  ██╗  ██╗ █████╗  ██████╗██╗  ██╗███████╗██████╗     ██╗   ██╗ ██╗
  ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗    ██║   ██║███║
  ███████║███████║██║     █████╔╝ █████╗  ██████╔╝    ██║   ██║╚██║
  ██╔══██║██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗    ╚██╗ ██╔╝ ██║
  ██║  ██║██║  ██║╚██████╗██║  ██╗███████╗██║  ██║     ╚████╔╝  ██║
  ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝      ╚═══╝   ╚═╝

╔─────────────────────────────────────────────────────────────────╗
│  ⚠  ОТКАЗ ОТ ОТВЕТСТВЕННОСТИ                                    │
│  Только для авторизованного тестирования безопасности.           │
╚─────────────────────────────────────────────────────────────────╝

──────────────────── Проверка инструментов ────────────────────────
  Пакет             Команды                   Статус
  aircrack-ng       aircrack-ng, airodump-ng  ✓ Установлен
  hcxtools          hcxpcapngtool             ✓ Установлен
  hcxdumptool       hcxdumptool               ✓ Установлен
  iw                iw, iwconfig              ✓ Установлен

──────────────────── Доступные WiFi адаптеры ──────────────────────
  #  Интерфейс   Режим       MAC адрес           PHY
  1  wlan0        managed     aa:bb:cc:dd:ee:ff   phy0
  2  wlan1        managed     11:22:33:44:55:66   phy1

Выберите номер адаптера [1]: 2

  ⠋ Перевод wlan1 в режим мониторинга...
  ✓ Режим мониторинга активен: wlan1mon

──────────────────── Обнаруженные сети ────────────────────────────
  #  BSSID              ESSID            Канал  Сигнал            Шифрование
  1  AA:BB:CC:DD:EE:FF  HomeNetwork      6      ████ -52 dBm      WPA2
  2  11:22:33:44:55:66  OfficeWiFi       11     ███░ -61 dBm      WPA2
  3  DE:AD:BE:EF:CA:FE  GuestNetwork     1      ██░░ -74 dBm      WPA
  4  CA:FE:BA:BE:00:01  <Скрытая>        36     █░░░ -81 dBm      WPA2

Выберите номер цели [1]: 1

╔─────────────────────────────────────────────────────────────────╗
│  Цель:   HomeNetwork                                             │
│  BSSID:  AA:BB:CC:DD:EE:FF                                      │
│  Канал:  6                                                       │
╚─────────────────────────────────────────────────────────────────╝

  ⠹ Деаутентификация клиентов...
  Ожидание хендшейка ━━━━━━━━━━━━━━━━━━━━ 100%  0:00:23
  ✓ Хендшейк захвачен!

  ⠸ Конвертация в hc22000... Готово

──────────────────── Результат — хэши hc22000 ─────────────────────
╔─────────────────────────────────────────────────────────────────╗
│  Хэш #1                                                         │
│  WPA*02*4a3f...8e1b*aabbccddeeff*...                            │
╚─────────────────────────────────────────────────────────────────╝

  Файл сохранён: /home/user/wifi-audit-tool/handshake_20240101_143022.hc22000

  Для подбора пароля:
  hashcat -m 22000 handshake_20240101_143022.hc22000 wordlist.txt
```

---

## 🗂️ Project Structure

```
wifi-audit-tool/
└── wifi_audit.py       # Main script — all-in-one, no extra modules required
```

---

## ⚠️ Legal Disclaimer

> **This tool is intended SOLELY for authorized security testing.**
>
> - Only use on networks you **own** or have **explicit written permission** to test.
> - Unauthorized interception of network traffic is **illegal** in most jurisdictions and may result in criminal prosecution.
> - The author assumes **no responsibility** for any misuse or damage caused by this tool.
>
> By running this script you confirm that you have the legal right to test the target network.

---

## 🛡️ Ethical Use Cases

- ✅ Testing your own home or lab network
- ✅ Authorized corporate penetration testing engagements
- ✅ Capture-the-Flag (CTF) competitions
- ✅ Security research in isolated environments
- ❌ Testing neighbors' or public networks without permission
- ❌ Any activity violating local laws or regulations

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<div align="center">

Made with ❤️ for the security community

</div>
