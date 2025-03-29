import os
import scapy.all as scapy

def scan_network(interface):
    """Scans for available WiFi networks."""
    print(f"[*] Scanning for networks on {interface}...\n")
    os.system(f"nmcli dev wifi list")

def check_wpa_handshake(interface):
    """Checks if WPA handshake packets can be captured (basic security check)."""
    print("[*] Sniffing for WPA handshake packets...")
    scapy.sniff(iface=interface, count=10, prn=lambda pkt: pkt.summary())

def main():
    interface = input("Enter your WiFi interface (e.g., wlan0): ").strip()
    scan_network(interface)
    handshake_check = input("\nDo you want to check for WPA handshakes? (y/n): ").strip().lower()
    
    if handshake_check == "y":
        check_wpa_handshake(interface)

if __name__ == "__main__":
    main()
