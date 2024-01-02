from scapy.all import *

mac_addresses = set()

def sniff_packet(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 4:  # Probe Request
            mac_address = packet[Dot11].addr2
            handle_probe_request(mac_address)

def handle_probe_request(mac_address):
    if mac_address == "00:00:00:00:00:00":
        return  # Ignore invalid MAC addresses

    mac_addresses.add(mac_address)
    print(f"MAC Address: {mac_address}")

    # Check if the entered MAC address is in the set
    if entered_mac_address.lower() == mac_address.lower():
        print(f"Entered MAC Address {entered_mac_address} appeared!")

def main():
    global entered_mac_address
    interface = "wlan0"  # Postavite odgovarajući mrežni interfejs

    # Unos MAC adrese od strane korisnika
    entered_mac_address = input("Unesite MAC adresu koju želite pratiti: ")

    try:
        print("Scanning for MAC addresses from Probe Requests. Press Ctrl+C to stop.")
        sniff(prn=sniff_packet, iface=interface, store=0)
    except KeyboardInterrupt:
        print("Scanning stopped.")

if __name__ == "__main__":
    main()
