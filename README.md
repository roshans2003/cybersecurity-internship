
1. **File Change Monitor (Hash-Based)**
2. **Web Vulnerability Scanner (SQLi & XSS)**
3. **Penetration Testing Toolkit (Port Scan, SSH/FTP Brute-force, Banner Grabbing)**
4. **AES-256 File Encryption Tool**


Cybersecurity Utility Suite - Python GUI Toolkit

This project is a collection of **four Python-based GUI security tools** built using `Tkinter` and `PyQt5`.
Each tool performs a specific task related to ethical hacking, file monitoring, vulnerability testing, and encryption.

---

## 1. File Change Monitor (Hash-Based)
Tech Stack: Python, PyQt5, SHA-256, JSON  
**Functionality:**
- Scans a selected folder and computes SHA-256 hash of all files.
- Detects **NEW**, **MODIFIED**, or **DELETED** files by comparing with the previous state.
- Stores the scan data in `file_hashes.json`.

**Usage:**
- Run `taskfour.py` (PyQt5-based GUI)
- Select a folder → Click "Scan & Compare"

> Ideal for monitoring integrity of sensitive project files or detecting unauthorized modifications.

---

## 2. Web Vulnerability Scanner
**Tech Stack:** Python, Tkinter, BeautifulSoup, requests  
**Features:**
- Scans a given website URL for:
  - **SQL Injection** vulnerabilities
  - **Cross-site Scripting (XSS)** vulnerabilities
- Recursively crawls all internal `<a>` links and scans them too.

**Usage:**
- Run the `web_vuln_scanner.py` script
- Enter target URL → Click "Scan"

> This is a basic demonstration tool for discovering form-based vulnerabilities.

---

## 3. Penetration Testing Toolkit
**Tech Stack:** Python, Tkinter, socket, Paramiko, ftplib  
**Features:**
- **Port Scanner:** Scans top 1024 ports on a given IP
- **SSH Brute-force:** Tries SSH login using a wordlist
- **FTP Brute-force:** Attempts FTP login using wordlist
- **Banner Grabbing:** Collects banners for common ports

**Usage:**
- Run `pentest_toolkit.py`
- Provide target IP, username, and password wordlist
- Click desired buttons for scanning

> Intended for ethical testing in lab environments only.

---

## 4. AES-256 File Encryption Tool
**Tech Stack:** Python, Tkinter, PyCryptodome  
**Features:**
- Encrypt any file using AES-256 (CBC mode)
- Secure password-based key derivation (PBKDF2 with salt)
- Decrypt `.enc` files back to original

**Usage:**
- Run `aes_tool.py`
- Select a file → Enter password → Encrypt or Decrypt

> Safeguard sensitive files with strong encryption.

---

## Requirements

Install dependencies using pip:

```bash
pip install pyqt5 requests beautifulsoup4 paramiko pycryptodome
````

---

## ⚠️ Disclaimer

This toolkit is for **educational and ethical testing purposes only**. Do not use against systems without **explicit permission**. Unauthorized scanning or brute-forcing is illegal and unethical.

---

## Author

Developed by **Muhammad Roshan**
🔗 [LinkedIn]([https://www.linkedin.com/](https://www.linkedin.com/in/muhammad-roshan-s/)) | 🛡️ MCA Cybersecurity Enthusiast

---

## Project Structure

```
.
├── file_monitor.py         # File Change Monitor (PyQt5)
├── web_vuln_scanner.py     # SQLi/XSS Scanner (Tkinter)
├── pentest_toolkit.py      # Port scan, SSH/FTP brute, banners
├── aes_tool.py             # AES-256 File Encryption
├── file_hashes.json        # Auto-generated on first run
└── README.md               # This file
```

---

## Future Improvements

* Add reporting/export feature (PDF/CSV logs)
* GUI integration for all tools into a single dashboard
* Add more vulnerability scanners (CSRF, Open Redirects)

---
