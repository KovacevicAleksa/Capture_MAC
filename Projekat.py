from scapy.all import *
import time

mac_addresses = {}

def sniff_packet(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 4:  # Probe Request
            mac_address = packet[Dot11].addr2
            handle_probe_request(mac_address)

def handle_probe_request(mac_address):
    if mac_address == "00:00:00:00:00:00":
        return  # Ignore invalid MAC addresses

    current_time = time.strftime("%Y-%m-%d %H:%M:%S")

    if mac_address not in mac_addresses:
        # Prvi put viđena MAC adresa
        mac_addresses[mac_address] = {"first_seen": current_time, "last_seen": current_time}
    else:
        # Ažuriraj vreme poslednjeg viđenja
        mac_addresses[mac_address]["last_seen"] = current_time

    if entered_mac_address.lower() == mac_address.lower():
        print(f"\033[92mMAC Address: {mac_address}, First Seen: {mac_addresses[mac_address]['first_seen']}, Last Seen: {current_time}\033[0m")
    else:
        print(f"MAC Address: {mac_address}, First Seen: {mac_addresses[mac_address]['first_seen']}, Last Seen: {current_time}")

def main():
    global entered_mac_address
    interface = "wlan0"  # Set the appropriate network interface

    # Input MAC address from the user
    entered_mac_address = input("Enter the MAC address you want to track: ")

    try:
        print("Scanning for MAC addresses from Probe Requests. Press Ctrl+C to stop.")
        sniff(prn=sniff_packet, iface=interface, store=0)
    except KeyboardInterrupt:
        print("Scanning stopped.")

if __name__ == "__main__":
    main()
