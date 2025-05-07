import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import ipaddress
from mac_vendor_lookup import MacLookup
import threading

from netcut_core import (
    start_arp_spoof_thread,
    stop_arp_spoof,
    scan_network,
    block_all,
    unblock_all,
    get_mac_from_arp_cache
)

BG_DARK = "#232c33"
BG_PANEL = "#2e3942"
FG_TEXT = "#eaeaea"
FG_ACCENT = "#ffcc00"
FG_STATUS = "#ffb300"
FG_HEADER = "#3c4a53"
FG_ROW_HIGHLIGHT = "#39ff14"

attack_mode = "mitm"  # Default mode
last_devices = []     # Untuk block_all/unblock_all

def get_interfaces_and_ips():
    interfaces = []
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == 'AF_INET' and not addr.address.startswith('127.'):
                interfaces.append((name, addr.address, addr.netmask))
    return interfaces

def suggest_network(ip, netmask):
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return str(network)

def get_local_mac(interface):
    addrs = psutil.net_if_addrs().get(interface, [])
    for addr in addrs:
        if addr.family.name == 'AF_LINK':
            return addr.address.upper()
    return "00:00:00:00:00:00"

def get_default_gateway_ip(ip):
    net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
    return str(list(net.hosts())[0])

def fill_table(devices):
    for row in tree.get_children():
        tree.delete(row)
    for dev in devices:
        tags = ()
        if dev["type"].lower() == "router":
            tags = ("router",)
        elif dev["type"].lower() == "me":
            tags = ("me",)
        tree.insert("", "end", values=(dev["ip"], dev["mac"], dev["vendor"], dev["type"], dev["nickname"]), tags=tags)

def scan_devices_thread():
    global last_devices
    network_cidr = entry_network.get()
    interface = combo_interface.get()
    btn_scan.config(state=tk.DISABLED)
    btn_block_all.config(state=tk.DISABLED)
    btn_unblock_all.config(state=tk.DISABLED)
    progress.pack(side="left", padx=(10, 0))
    progress.start()
    lbl_status.config(text="Scanning...")
    root.update_idletasks()
    devices = scan_network(network_cidr, interface)
    mac_lookup = MacLookup()
    local_mac = get_local_mac(interface)
    gateway_ip = lbl_gateway_ip.cget("text")
    result = []
    for dev in devices:
        mac = dev['mac']
        try:
            vendor = mac_lookup.lookup(mac) if mac != "-" else "-"
        except Exception:
            vendor = "-"
        if dev['ip'] == gateway_ip:
            dtype = "Router"
        elif mac.upper() == local_mac:
            dtype = "Me"
        else:
            dtype = "User"
        result.append({
            "ip": dev['ip'],
            "mac": mac,
            "vendor": vendor,
            "type": dtype,
            "nickname": "-"
        })
    fill_table(result)
    last_devices = result
    lbl_status.config(text=f"Found {len(result)} devices.")
    lbl_count.config(text=f"{len(result)} devices (0 killed)")
    lbl_mac.config(text=local_mac)
    btn_scan.config(state=tk.NORMAL)
    btn_block_all.config(state=tk.NORMAL)
    btn_unblock_all.config(state=tk.NORMAL)
    progress.stop()
    progress.pack_forget()
    messagebox.showinfo("Info", f"Scan selesai. {len(result)} perangkat ditemukan.")

def scan_devices():
    threading.Thread(target=scan_devices_thread, daemon=True).start()

def on_select(event):
    selected = tree.focus()
    if selected:
        values = tree.item(selected, 'values')
        entry_target_ip.delete(0, tk.END)
        entry_target_ip.insert(0, values[0])
        entry_target_mac.delete(0, tk.END)
        entry_target_mac.insert(0, values[1])

def on_interface_change(event=None):
    selected_name = combo_interface.get()
    for iface in interfaces:
        if iface[0] == selected_name:
            ip, netmask = iface[1], iface[2]
            network = suggest_network(ip, netmask)
            entry_network.delete(0, tk.END)
            entry_network.insert(0, network)
            lbl_mac.config(text=get_local_mac(iface[0]))
            gateway_ip = get_default_gateway_ip(ip)
            lbl_gateway_ip.config(text=gateway_ip)
            break

def set_attack_mode(mode):
    global attack_mode
    attack_mode = mode
    btn_mitm.config(relief=tk.SUNKEN if mode=="mitm" else tk.RAISED)
    btn_block.config(relief=tk.SUNKEN if mode=="block" else tk.RAISED)

def start_attack():
    target_ip = entry_target_ip.get()
    target_mac = entry_target_mac.get()
    gateway_ip = lbl_gateway_ip.cget("text")
    interface = combo_interface.get()

    print (f"[INFO] Target IP {target_ip}...")
    print (f"[INFO] Target MAC {target_mac}...")
    print (f"[INFO] Target Gateway IP {gateway_ip}...")

    if not all([target_ip, target_mac, gateway_ip, interface]):
        messagebox.showerror("Error", "Semua field harus diisi!")
        return
    if target_mac == "-" or len(target_mac.split(":")) != 6:
        os.system(f"ping -n 1 -w 100 {target_ip} >nul")
        refreshed_mac = get_mac_from_arp_cache(target_ip)
        if refreshed_mac == "-" or len(refreshed_mac.split(":")) != 6:
            messagebox.showerror("Error", "MAC target tetap tidak ditemukan. Pastikan target aktif dan scan ulang.")
            return
        entry_target_mac.delete(0, tk.END)
        entry_target_mac.insert(0, refreshed_mac)
        target_mac = refreshed_mac
    btn_start.config(state=tk.DISABLED)
    btn_stop.config(state=tk.NORMAL)
    start_arp_spoof_thread(target_ip, gateway_ip, target_mac, interface, mode=attack_mode)
    messagebox.showinfo("Info", f"ARP spoofing ({attack_mode.upper()}) dimulai.")

def stop_attack():
    stop_arp_spoof()
    btn_start.config(state=tk.NORMAL)
    btn_stop.config(state=tk.DISABLED)
    messagebox.showinfo("Info", "Attack dihentikan.")

def block_all_thread():
    if not last_devices:
        messagebox.showerror("Error", "Silakan scan dulu sebelum Block All!")
        return
    interface = combo_interface.get()
    gateway_ip = lbl_gateway_ip.cget("text")
    gateway_mac = get_mac_from_arp_cache(gateway_ip)
    if gateway_mac == "-" or len(gateway_mac.split(":")) != 6:
        messagebox.showerror("Error", "MAC Gateway tidak valid. Scan ulang atau cek jaringan.")
        return
    btn_block_all.config(state=tk.DISABLED)
    btn_unblock_all.config(state=tk.NORMAL)
    lbl_status.config(text="Blocking all devices...")
    threading.Thread(target=block_all, args=(last_devices, gateway_ip, gateway_mac, interface), daemon=True).start()
    messagebox.showinfo("Info", "Block All dijalankan.")

def unblock_all_thread():
    if not last_devices:
        messagebox.showerror("Error", "Silakan scan dulu sebelum Unblock All!")
        return
    interface = combo_interface.get()
    gateway_ip = lbl_gateway_ip.cget("text")
    gateway_mac = get_mac_from_arp_cache(gateway_ip)
    btn_unblock_all.config(state=tk.DISABLED)
    lbl_status.config(text="Unblocking all devices...")
    threading.Thread(target=unblock_all, args=(last_devices, gateway_ip, gateway_mac, interface), daemon=True).start()
    messagebox.showinfo("Info", "Unblock All dijalankan.")

# ------------- Main Window -------------
root = tk.Tk()
root.title("NetCut-like Python GUI")
root.configure(bg=BG_DARK)

# --- Interface & Network selection ---
frame_net = tk.Frame(root, bg=BG_DARK)
frame_net.pack(fill="x", padx=8, pady=(8, 2))

interfaces = get_interfaces_and_ips()
interface_names = [i[0] for i in interfaces]

tk.Label(frame_net, text="Interface:", bg=BG_DARK, fg=FG_TEXT).pack(side="left", padx=(0, 4))
interface_var = tk.StringVar()
combo_interface = ttk.Combobox(frame_net, textvariable=interface_var, values=interface_names, state="readonly", width=12)
combo_interface.pack(side="left")
combo_interface.bind('<<ComboboxSelected>>', on_interface_change)
tk.Label(frame_net, text="Network:", bg=BG_DARK, fg=FG_TEXT).pack(side="left", padx=(12, 4))
entry_network = tk.Entry(frame_net, width=18)
entry_network.pack(side="left")
tk.Label(frame_net, text="Gateway IP:", bg=BG_DARK, fg=FG_TEXT).pack(side="left", padx=(12, 4))
lbl_gateway_ip = tk.Label(frame_net, text="", bg=BG_DARK, fg=FG_ACCENT, width=15, anchor="w")
lbl_gateway_ip.pack(side="left")
btn_scan = tk.Button(frame_net, text="Scan", command=scan_devices, bg=FG_ACCENT, fg="#222", font=("Segoe UI", 10, "bold"))
btn_scan.pack(side="left", padx=(12, 2))

btn_block_all = tk.Button(frame_net, text="Block All", command=block_all_thread, bg="#e74c3c", fg="white", font=("Segoe UI", 10, "bold"))
btn_block_all.pack(side="left", padx=(6,2))
btn_unblock_all = tk.Button(frame_net, text="Unblock All", command=unblock_all_thread, bg="#2ecc71", fg="white", font=("Segoe UI", 10, "bold"))
btn_unblock_all.pack(side="left", padx=(2,2))

# --- Progressbar ---
progress = ttk.Progressbar(frame_net, mode='indeterminate', length=120)
progress.pack(side="left", padx=(10, 0))
progress.pack_forget()  # Hide initially

# --- Table Device List ---
frame_table = tk.Frame(root, bg=BG_DARK)
frame_table.pack(fill="both", expand=True, padx=8, pady=(2, 2))

columns = ("IP Address", "MAC Address", "Vendor", "Type", "Nickname")
tree = ttk.Treeview(frame_table, columns=columns, show="headings", height=14)
for col, w in zip(columns, [120, 170, 100, 70, 90]):
    tree.heading(col, text=col)
    tree.column(col, width=w, anchor="center")
tree.pack(fill="both", expand=True, side="left")
tree.bind("<<TreeviewSelect>>", on_select)

# Scrollbar
scrollbar = ttk.Scrollbar(frame_table, orient="vertical", command=tree.yview)
tree.configure(yscroll=scrollbar.set)
scrollbar.pack(side="right", fill="y")

# Style for dark mode
style = ttk.Style()
style.theme_use("default")
style.configure("Treeview", background=BG_DARK, foreground=FG_TEXT, fieldbackground=BG_DARK, rowheight=24, font=("Consolas", 11))
style.configure("Treeview.Heading", background=FG_HEADER, foreground=FG_TEXT, font=("Segoe UI", 11, "bold"))
style.map("Treeview", background=[("selected", "#444")])
tree.tag_configure("router", background=FG_ROW_HIGHLIGHT, foreground="black")
tree.tag_configure("me", background=FG_ROW_HIGHLIGHT, foreground="black")

# --- Target, Start/Stop, Mode ---
frame_attack = tk.Frame(root, bg=BG_DARK)
frame_attack.pack(fill="x", padx=8, pady=(2, 2))

tk.Label(frame_attack, text="Target IP:", bg=BG_DARK, fg=FG_TEXT).pack(side="left", padx=(0, 4))
entry_target_ip = tk.Entry(frame_attack, width=14)
entry_target_ip.pack(side="left")
tk.Label(frame_attack, text="Target MAC:", bg=BG_DARK, fg=FG_TEXT).pack(side="left", padx=(8, 4))
entry_target_mac = tk.Entry(frame_attack, width=18)
entry_target_mac.pack(side="left")

btn_mitm = tk.Button(frame_attack, text="MitM", command=lambda: set_attack_mode("mitm"), bg="#444", fg="white", width=6)
btn_mitm.pack(side="left", padx=(12, 2))
btn_block = tk.Button(frame_attack, text="Block", command=lambda: set_attack_mode("block"), bg="#e74c3c", fg="white", width=6)
btn_block.pack(side="left", padx=(2, 2))

btn_start = tk.Button(frame_attack, text="Mulai", command=start_attack, bg=FG_ACCENT, fg="#222", font=("Segoe UI", 10, "bold"), width=8)
btn_start.pack(side="left", padx=(12, 2))
btn_stop = tk.Button(frame_attack, text="Stop", command=stop_attack, state=tk.DISABLED, bg="#e74c3c", fg="white", font=("Segoe UI", 10, "bold"), width=8)
btn_stop.pack(side="left", padx=(2, 2))

# --- Status Bar ---
frame_status = tk.Frame(root, bg=BG_PANEL)
frame_status.pack(fill="x", side="bottom", padx=0, pady=(0, 0))
lbl_status = tk.Label(frame_status, text="Found 0 devices.", bg=BG_PANEL, fg=FG_STATUS, font=("Segoe UI", 10))
lbl_status.pack(side="left", padx=8)
lbl_mac = tk.Label(frame_status, text="00:00:00:00:00:00", bg=BG_PANEL, fg="#aaa", font=("Consolas", 10))
lbl_mac.pack(side="right", padx=8)
lbl_count = tk.Label(frame_status, text="0 devices (0 killed)", bg=BG_PANEL, fg=FG_TEXT, font=("Segoe UI", 10))
lbl_count.pack(side="right", padx=8)
btn_coffee = tk.Button(frame_status, text="☕ Buy me a coffee", bg="#ffe066", fg="#222", font=("Segoe UI", 10, "bold"), bd=0)
btn_coffee.pack(side="right", padx=8)

if interface_names:
    combo_interface.current(0)
    on_interface_change()

set_attack_mode("mitm")

root.mainloop()
