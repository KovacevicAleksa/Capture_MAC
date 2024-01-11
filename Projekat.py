from scapy.all import *
import time
import tkinter as tk
from tkinter import ttk
import threading
import math

mac_addresses = {}

# Konstante za izračunavanje distance
MEASURED_POWER = -44  # RSSI na udaljenosti od 1 metra
N_FACTOR = 2.4  # Konstanta za okolinu (može biti između 2 i 4)

def sniff_packet(packet):
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 4:  # Probe Request
            mac_address = packet[Dot11].addr2
            rssi = -(256 - ord(packet.notdecoded[-4:-3]))  # Izdvajanje RSSI iz paketa

            handle_probe_request(mac_address, rssi)

def calculate_distance(rssi):
    # Formula za izračunavanje udaljenosti između uređaja i WiFi adaptera
    distance = 10 ** ((MEASURED_POWER - rssi) / (10 * N_FACTOR))
    return distance if distance <= 30 else 30  # Ako je udaljenost veća od 30m, postavi je na 30m

def handle_probe_request(mac_address, rssi):
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
        distance = calculate_distance(rssi)
        result_label.config(text=f"MAC Address: {mac_address}\nFirst Seen: {mac_addresses[mac_address]['first_seen']}\nLast Seen: {current_time}\nDistance: {distance:.2f} meters" if distance <= 30 else "Distance: 30m+", foreground="green")
        print(f"\033[92mMAC Address: {mac_address}, First Seen: {mac_addresses[mac_address]['first_seen']}, Last Seen: {current_time}, Distance: {distance:.2f} meters\033[0m")
    else:
        print(f"MAC Address: {mac_address}, First Seen: {mac_addresses[mac_address]['first_seen']}, Last Seen: {current_time}, Distance: {calculate_distance(rssi):.2f} meters")

def start_sniffing():
    global entered_mac_address
    entered_mac_address = mac_entry.get()
    interface = "wlan0"  # Set the appropriate network interface

    try:
        print("Scanning for MAC addresses from Probe Requests. Press Ctrl+C to stop.")
        sniff(prn=sniff_packet, iface=interface, store=0)
    except KeyboardInterrupt:
        print("Scanning stopped.")

def start_sniffing_thread():
    thread = threading.Thread(target=start_sniffing)
    thread.start()

# Tkinter GUI setup
root = tk.Tk()
root.title("MAC Address Tracker")
root.geometry("500x500")  # Postavljanje fiksne veličine prozora

mac_label = ttk.Label(root, text="Enter MAC address:")
mac_label.pack(pady=10)

mac_entry = ttk.Entry(root)
mac_entry.pack(pady=10)

start_button = ttk.Button(root, text="Start Tracking", command=start_sniffing_thread)
start_button.pack(pady=10)

result_label = ttk.Label(root, text="")
result_label.pack(pady=10)

root.mainloop()
