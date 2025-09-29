import subprocess
import socket
import re
import time
import tkinter as tk
from tkinter import ttk, messagebox
import webbrowser
import os
from concurrent.futures import ThreadPoolExecutor, as_completed


# ---------- Core Network Scanner Functions ----------

def ping(ip):
    try:
        start = time.time()
        output = subprocess.check_output(
            ["ping", "-n", "1", "-w", "1000", ip],
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        end = time.time()
        elapsed = round((end - start) * 1000, 2)
        if "TTL=" in output:
            return elapsed
    except subprocess.CalledProcessError:
        return None
    return None


def get_mac(ip):
    try:
        subprocess.call(
            ["ping", "-n", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        output = subprocess.check_output(
            ["arp", "-a", ip],
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )
        match = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
        if match:
            return match.group(0)
    except Exception:
        pass
    return "Unknown"


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def scan_ip(ip):
    response_time = ping(ip)
    if response_time is not None:
        hostname = get_hostname(ip)
        mac = get_mac(ip)
        return (ip, hostname, mac, f"{response_time} ms")
    return None


def generate_ips(start_ip, end_ip):
    start_parts = list(map(int, start_ip.split(".")))
    end_parts = list(map(int, end_ip.split(".")))
    for third in range(start_parts[2], end_parts[2] + 1):
        for last in range(1, 256):
            yield f"{start_parts[0]}.{start_parts[1]}.{third}.{last}"


def scan_network(start_ip, end_ip, tree, max_threads=50):
    ips = list(generate_ips(start_ip, end_ip))

    with ThreadPoolExecutor(max_threads) as executor:
        futures = {executor.submit(scan_ip, ip): ip for ip in ips}
        for future in as_completed(futures):
            result = future.result()
            if result:
                tree.insert("", tk.END, values=result)


# ---------- GUI Actions ----------

def start_scan():
    start_ip = entry_start.get().strip()
    end_ip = entry_end.get().strip()

    if not start_ip or not end_ip:
        messagebox.showerror("Error", "Please enter both start and end IPs.")
        return

    # Clear old results
    for item in tree.get_children():
        tree.delete(item)

    tree.insert("", tk.END, values=(f"Scanning {start_ip} to {end_ip}...", "", "", ""))
    window.update()

    scan_network(start_ip, end_ip, tree)


def open_browser(ip):
    url = f"http://{ip}"
    webbrowser.open(url)


def open_explorer(ip):
    try:
        os.system(f'explorer \\\\{ip}\\')
    except Exception as e:
        messagebox.showerror("Error", f"Could not open shares: {e}")


def on_right_click(event):
    selected = tree.focus()
    if not selected:
        return
    values = tree.item(selected, "values")
    if not values or "Scanning" in values[0]:
        return

    ip = values[0]

    # Build context menu
    menu = tk.Menu(window, tearoff=0)
    menu.add_command(label="Open in Browser", command=lambda: open_browser(ip))
    menu.add_command(label="Open Shares", command=lambda: open_explorer(ip))
    menu.tk_popup(event.x_root, event.y_root)


# ---------- About Dialog ----------

def show_about():
    about_win = tk.Toplevel(window)
    about_win.title("About")
    about_win.geometry("750x800")  # much larger window
    about_win.resizable(False, False)

    def open_link(url):
        webbrowser.open(url)

    # Buy Me a Coffee link at top
    top_frame = tk.Frame(about_win)
    top_frame.pack(pady=10)

    coffee_label = tk.Label(
        top_frame,
        text="☕ Support me on Buy Me a Coffee",
        fg="blue",
        cursor="hand2",
        font=("Segoe UI", 11, "underline")
    )
    coffee_label.pack()
    coffee_label.bind("<Button-1>", lambda e: open_link("https://buymeacoffee.com/elysabionics"))

    # Main text area
    text = tk.Text(
        about_win,
        wrap="word",
        bg=window.cget("bg"),
        borderwidth=0,
        font=("Segoe UI", 10)
    )
    text.pack(padx=15, pady=15, fill="both", expand=True)

    content = (
        "Usage instructions:\n\n"
        "1) Enter a start and end IP range in the boxes above and click 'Start Scan'.\n"
        "   Examples:\n"
        "     • Home LAN (small range): 192.168.0.1 to 192.168.0.254\n"
        "     • Two-subnet scan: 192.168.0.1 to 192.168.1.254\n"
        "     • Typical office: 10.0.0.1 to 10.0.0.254\n\n"
        "2) Results appear in the table below with columns: IP, Hostname, MAC, Ping.\n"
        "   The scanner runs multiple checks in parallel for speed.\n\n"
        "3) Right-click any row to open the device in your web browser (http://<IP>)\n"
        "   or to open that host's shares in Windows Explorer (\\\\<IP>\\).\n\n"
        "Notes & tips:\n\n"
        "• If a host responds to ping it will be shown — unreachable hosts are omitted.\n"
        "• Use conservative ranges if you only need a quick scan; large ranges scan every\n"
        "  address in the specified subnets and will take longer.\n\n"
        "A word from the author:\n\n"
        "💡 I’m an engineer passionate about electronics, robotics, CAD, and embedded systems. "
        "I love turning ideas into working prototypes and exploring how technology can make life better.\n\n"
        "☕ It really grinds my gears how many network scanners and tools put basic features behind "
        "paywalls or cripple them with freemium limits. That’s why this program is entirely free —\n"
        "no nags, no hidden limits, no telemetry — just a simple, honest tool you can use and share.\n\n"
        "If you find it useful, donations are very appreciated (they help fuel more creative projects):\n"
        "https://buymeacoffee.com/elysabionics\n\n"
        "💻 Check out my GitHub and other projects:\n"
        "https://github.com/protocooper-sys\n\n"
        "Feel free to pass this program about — use it, fork it, improve it, and share it with others.\n"
    )

    text.insert(tk.END, content)
    text.config(state="disabled")

    # GitHub link button at bottom
    btn_frame = tk.Frame(about_win)
    btn_frame.pack(pady=5)

    tk.Button(
        btn_frame,
        text="💻 GitHub",
        command=lambda: open_link("https://github.com/protocooper-sys")
    ).pack(side=tk.LEFT, padx=10)


# ---------- GUI Setup ----------

window = tk.Tk()
window.title("Network Scanner")
window.geometry("850x500")

# Top frame
top_frame = tk.Frame(window)
top_frame.pack(fill=tk.X, pady=5, padx=5)

tk.Label(top_frame, text="Start IP:").pack(side=tk.LEFT, padx=5)
entry_start = tk.Entry(top_frame, width=20)
entry_start.pack(side=tk.LEFT, padx=5)

tk.Label(top_frame, text="End IP:").pack(side=tk.LEFT, padx=5)
entry_end = tk.Entry(top_frame, width=20)
entry_end.pack(side=tk.LEFT, padx=5)

btn_scan = tk.Button(top_frame, text="Start Scan", command=start_scan)
btn_scan.pack(side=tk.LEFT, padx=10)

# About and Buy Me a Coffee buttons on far right
btn_about = tk.Button(top_frame, text="ℹ About", command=show_about)
btn_about.pack(side=tk.RIGHT, padx=5)

btn_coffee = tk.Button(
    top_frame,
    text="☕ Buy Me a Coffee",
    command=lambda: webbrowser.open("https://buymeacoffee.com/elysabionics")
)
btn_coffee.pack(side=tk.RIGHT, padx=5)

# Results table
columns = ("IP", "Hostname", "MAC", "Ping")
tree = ttk.Treeview(window, columns=columns, show="headings", height=20)
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=150 if col != "Ping" else 80)
tree.pack(fill=tk.BOTH, expand=True, pady=10)

# Right-click binding
tree.bind("<Button-3>", on_right_click)

window.mainloop()
