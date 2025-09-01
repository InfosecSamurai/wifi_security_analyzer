# 📡 WiFi Security Analyzer

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/InfosecSamurai/wifi_security_analyzer)](https://github.com/InfosecSamurai/wifi_security_analyzer/commits/main)
[![GitHub stars](https://img.shields.io/github/stars/InfosecSamurai/wifi_security_analyzer?style=social)](https://github.com/InfosecSamurai/wifi_security_analyzer/stargazers)

---

## 📖 Overview
The **WiFi Security Analyzer** is a tool for scanning and analyzing WiFi networks, helping identify security vulnerabilities like weak encryption and WPA handshake exposure.

It supports both **simulation mode (DRY-RUN)** for safe testing and **real packet capture** using monitor mode.

---

## 🚀 Features
- ✅ Scan nearby WiFi networks (beacon frames)  
- ✅ Capture WPA handshake packets (EAPOL)  
- ✅ Optional DRY-RUN mode for safe testing  
- ✅ User-defined capture duration  
- ✅ Fully automated monitor mode setup (Linux)  

---

## ⚙️ Installation

### Clone the repository:

```bash
git clone https://github.com/InfosecSamurai/wifi_security_analyzer.git
cd wifi_security_analyzer
```

---

### Install dependencies. You have multiple options depending on your environment:

## Option 1: Using a Virtual Environment (Recommended for Kali/WSL)

```bash
# Install venv if missing
sudo apt install python3-venv -y

# Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies inside the venv
pip install -r requirements.txt
```

## Option 2: System-Wide Install (Not recommended on Kali/WSL)

```bash
pip install --break-system-packages -r requirements.txt
```
#### ⚠️ Warning: This may overwrite system-managed packages. Use with caution.

---

## Option 3: Docker (Optional)

If you prefer running inside Docker:

```bash
docker build -t wifi-analyzer .
docker run -it --net=host --privileged wifi-analyzer
```

## ▶️ Running the Analyzer

```bash
sudo python analyzer.py
```

---

### The script will prompt you for:

- DRY-RUN mode – simulation without capturing real packets (recommended for testing).

- WiFi interface – e.g., wlan0 or external USB adapter in monitor mode.

- WPA handshake capture – optional, with user-defined duration.

### 💡 Using an external USB wireless adapter that supports monitor mode (like Realtek RTL8812AU) is highly recommended for reliable WPA handshake capture.

#### ⚠️ Notes
Requires root privileges (sudo) for packet capture.

- Monitor mode must be enabled for real packet capture; the script attempts to configure it automatically on Linux.

- Only use this tool on networks you own or have explicit permission to analyze.

## 📜 License
MIT License – feel free to modify and contribute!

🔹 Developed by InfosecSamurai
