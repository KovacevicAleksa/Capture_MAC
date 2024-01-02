from scapy.all import *
import tkinter as tk
from datetime import datetime, timedelta

mac_addresses = set()
entered_mac_address = ""
last_display_time = datetime.now()

def sniff_packet():
    packet = sniff(prn=handle_probe_request, iface=interface_var.get(), store=0, count=1)
    root.after(100, sniff_packet)  # Ponovo pokrećemo sniff nakon 100 ms

def handle_probe_request(packet):
    global last_display_time

    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 4:  # Probe Request
            mac_address = packet[Dot11].addr2
            mac_addresses.add(mac_address)
            print(f"MAC Address: {mac_address}")

            # Check if the entered MAC address is in the set
            if entered_mac_address.lower() == mac_address.lower():
                current_time = datetime.now()
                time_difference = current_time - last_display_time

                # Ako je prošlo više od 5 sekundi, ispiši poruku
                if time_difference > timedelta(seconds=5):
                    last_display_time = current_time
                    display_info(f"Entered MAC Address {entered_mac_address} appeared at {current_time}")

def display_info(info):
    info_label.config(text=info)

def start_scanning():
    global entered_mac_address
    entered_mac_address = mac_entry.get()
    sniff_packet()  # Pokrećemo sniffing

def main():
    global interface_var
    global mac_entry
    global info_label
    global root

    root = tk.Tk()
    root.title("MAC Address Scanner")

    # Input for MAC address
    tk.Label(root, text="Unesite MAC adresu koju želite pratiti:").pack(pady=5)
    mac_entry = tk.Entry(root)
    mac_entry.pack(pady=10)

    # Input for network interface
    tk.Label(root, text="Unesite mrežni interfejs (npr. wlan0):").pack(pady=5)
    interface_var = tk.StringVar()
    interface_entry = tk.Entry(root, textvariable=interface_var)
    interface_entry.pack(pady=10)

    # Button to start scanning
    scan_button = tk.Button(root, text="Start Scanning", command=start_scanning)
    scan_button.pack(pady=10)

    # Label to display information
    info_label = tk.Label(root, text="")
    info_label.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
