import os
import time
import logging
import scapy.all as scapy
import subprocess

# ==========================
# LOGGING CONFIG
# ==========================
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# ==========================
# CONFIGURATION
# ==========================
CAPTURE_DIR = "captures"  # Where to save captured packets


# ==========================
# FUNCTIONS
# ==========================
def validate_interface(interface):
    """Check if the interface exists on the system."""
    if interface not in scapy.get_if_list():
        logging.error(f"Interface '{interface}' not found! Use 'ip link show' or 'iw dev'.")
        return False
    return True


def check_interface_up(interface):
    """Check if the interface is up."""
    try:
        result = subprocess.run(f"ip link show {interface}", shell=True, capture_output=True, text=True)
        if "state UP" not in result.stdout:
            logging.error(f"Interface '{interface}' is down. Bring it up using 'sudo ip link set {interface} up'.")
            return False
    except Exception as e:
        logging.error(f"Error checking interface status: {e}")
        return False
    return True


def enable_monitor_mode(interface):
    """Enable monitor mode on the interface."""
    try:
        logging.info(f"[*] Putting {interface} into monitor mode...")
        subprocess.run(f"sudo ip link set {interface} down", shell=True, check=True)
        subprocess.run(f"sudo iw dev {interface} set type monitor", shell=True, check=True)
        subprocess.run(f"sudo ip link set {interface} up", shell=True, check=True)
        logging.info(f"[+] Monitor mode enabled on {interface}")
        # Confirm monitor mode
        result = subprocess.run(f"iwconfig {interface}", shell=True, capture_output=True, text=True)
        if "Mode:Monitor" not in result.stdout:
            logging.warning(f"Interface '{interface}' may not be in monitor mode. Check manually with 'iwconfig {interface}'.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error enabling monitor mode: {e}")
        return False
    return True


def scan_network(interface, timeout=10, dry_run=True):
    """Scan nearby WiFi networks using Scapy (beacon frames only)."""
    logging.info(f"[*] Scanning for networks on {interface} for {timeout} seconds...")
    if dry_run:
        logging.info("[DRY-RUN] Network scan simulated.")
        return
    try:
        scapy.sniff(iface=interface, timeout=timeout,
                    lfilter=lambda pkt: pkt.haslayer(scapy.Dot11Beacon),
                    prn=lambda pkt: pkt.summary())
    except (IOError, OSError) as e:
        logging.error(f"OS/IO error during network scan: {e}")
    except Exception as e:
        logging.error(f"Error during network scan: {e}")


def capture_packets(interface, timeout=60, dry_run=True):
    """Capture packets on the interface."""
    logging.info(f"[*] Capturing packets on {interface} for {timeout} seconds...")
    if dry_run:
        logging.info("[DRY-RUN] Packet capture simulated.")
        return []
    try:
        packets = scapy.sniff(iface=interface, timeout=timeout)
        return packets
    except (IOError, OSError) as e:
        logging.error(f"OS/IO error during packet capture: {e}")
        return []
    except Exception as e:
        logging.error(f"Error during packet capture: {e}")
        return []


def filter_eapol_packets(packets):
    """Filter EAPOL packets from the captured packets."""
    return [pkt for pkt in packets if pkt.haslayer(scapy.EAPOL)]


def save_packets_to_file(packets, filename):
    """Save packets to a file."""
    try:
        scapy.wrpcap(filename, packets)
        logging.info(f"[+] Packets saved to {filename}")
    except (IOError, OSError) as e:
        logging.error(f"OS/IO error saving packets to file: {e}")
    except Exception as e:
        logging.error(f"Error saving packets to file: {e}")


def check_wpa_handshake(interface, timeout=60, dry_run=True):
    """Sniff for WPA handshake packets (EAPOL)."""
    logging.info(f"[*] Sniffing for WPA handshake packets on {interface} for {timeout} seconds...")
    if dry_run:
        logging.info("[DRY-RUN] WPA handshake capture simulated.")
        return

    packets = capture_packets(interface, timeout, dry_run=False)
    if packets:
        eapol_packets = filter_eapol_packets(packets)
        if eapol_packets:
            logging.info(f"[+] Captured {len(eapol_packets)} WPA handshake packets!")
            if not os.path.exists(CAPTURE_DIR):
                os.makedirs(CAPTURE_DIR)
            filename = os.path.join(CAPTURE_DIR, f"handshake_{int(time.time())}.pcap")
            save_packets_to_file(eapol_packets, filename)
        else:
            logging.warning("[!] No WPA handshake packets captured.")
    else:
        logging.warning("[!] No packets captured.")


# ==========================
# MAIN
# ==========================
def main():
    print("=== WiFi Security Analyzer ===")
    dry_choice = input("Run in DRY-RUN mode? (y/n): ").strip().lower()
    dry_run = dry_choice == "y"

    interface = input("Enter your WiFi interface (e.g., wlan0): ").strip()

    if not validate_interface(interface):
        return

    if not check_interface_up(interface):
        return

    if not dry_run and not enable_monitor_mode(interface):
        return

    scan_network(interface, timeout=10, dry_run=dry_run)

    choice = input("\nDo you want to check for WPA handshakes? (y/n): ").strip().lower()
    if choice == "y":
        duration = input("Enter capture duration in seconds (default 60): ").strip()
        try:
            duration = int(duration)
        except ValueError:
            duration = 60
        check_wpa_handshake(interface, timeout=duration, dry_run=dry_run)


if __name__ == "__main__":
    main()
