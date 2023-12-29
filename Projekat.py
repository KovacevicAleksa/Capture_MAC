import subprocess
import threading
import time

# Definisati funkciju koja izvršava komandu
def run_command(command):
    subprocess.run(command.split())

# Definisati funkciju koja pokreće airodump-ng za hvatanje klijenata
def capture_clients(interface, filename, bssid, channel):
    run_command(f"sudo airodump-ng -w {filename} -c {channel} --bssid {bssid} {interface}")

# Prikazati informacije o bežičnom interfejsu
run_command("iwconfig")

# Ubiti eventualne procese koji ometaju
run_command("sudo airmon-ng check kill")

# Zatražiti korisnički unos za ime interfejsa
interface = input("Unesite ime interfejsa: ")

# Zatražiti korisnički unos za lokaciju
location = input("Unesite naziv lokacije")

# Aktivirati monitor mod
run_command(f"sudo airmon-ng start {interface}")

# Zatražiti korisnički unos za naziv datoteke
filename = input("Unesite naziv datoteke: ")
filename_with_location = f"{location}_{filename}"


# Pokrenuti airodump-ng na određenom interfejsu
run_command(f"sudo airodump-ng {interface}")

# Zatražiti korisnički unos za željeni BSSID
bssid = input("Unesite BSSID: ")

# Zatražiti korisnički unos za željeni kanal
channel = input("Unesite kanal: ")

# Pokrenuti hvatanje klijenata u zasebnom thread-u
capture_thread = threading.Thread(target=capture_clients, args=(interface, filename_with_location, bssid, channel))
capture_thread.start()


# Čekati dok traje hvatanje klijenata
while capture_thread.is_alive():
    pass

# Sačekati korisnika da završi hvatanje handshake-a
input("Pritisnite Enter da biste zaustavili hvatanje...")

# Zaustaviti monitor mod na određenom interfejsu
run_command(f"sudo airmon-ng stop {interface}")

print("Monitor mod isključen.")
