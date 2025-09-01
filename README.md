# 📡 WiFi Security Analyzer

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

## ⚙️ Usage

### 📥 Installation
Clone the repository and install dependencies:

```bash
git clone https://github.com/InfosecSamurai/wifi_security_analyzer.git
cd wifi_security_analyzer
pip install scapy
````

⚠️ If using Kali or other externally-managed Python environments, create a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install scapy
```

---

### ▶️ Running the Analyzer

```bash
sudo python analyzer.py
```

The script will prompt you for:

* **DRY-RUN mode** – simulation without capturing real packets (recommended for testing).
* **WiFi interface** – e.g., `wlan0` or external USB adapter in monitor mode.
* **WPA handshake capture** – optional, with user-defined duration.

💡 Using an **external USB wireless adapter** that supports monitor mode (like Realtek RTL8812AU) is highly recommended for reliable WPA handshake capture.

---

## ⚠️ Notes

* Requires **root privileges** (`sudo`) for packet capture.
* Monitor mode must be enabled for real packet capture; the script attempts to configure it automatically on Linux.
* Only use this tool on networks you **own or have explicit permission to analyze**.

---

## 📜 License

MIT License – feel free to modify and contribute!
🔹 Developed by InfosecSamurai

```

---

Do you want me to also add **badges** (Python version, license, last commit) at the top so it looks more like a polished GitHub project?
```
