import os
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

# AES parameters
KEY_SIZE = 32  # 256 bits
SALT_SIZE = 16
IV_SIZE = 16
PBKDF2_ITERATIONS = 100000

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)

def pad(data):
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    return data[:-data[-1]]

def encrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    salt = get_random_bytes(SALT_SIZE)
    iv = get_random_bytes(IV_SIZE)
    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))

    encrypted_data = salt + iv + ciphertext
    output_path = file_path + '.enc'
    with open(output_path, 'wb') as f:
        f.write(encrypted_data)

    return output_path

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()

    salt = data[:SALT_SIZE]
    iv = data[SALT_SIZE:SALT_SIZE+IV_SIZE]
    ciphertext = data[SALT_SIZE+IV_SIZE:]

    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    output_path = file_path.replace('.enc', '.dec')
    with open(output_path, 'wb') as f:
        f.write(plaintext)

    return output_path

# GUI
def select_file():
    file_path.set(filedialog.askopenfilename())

def encrypt_action():
    if not file_path.get() or not password.get():
        messagebox.showerror("Error", "Please select a file and enter a password.")
        return
    try:
        output = encrypt_file(file_path.get(), password.get())
        messagebox.showinfo("Success", f"File encrypted:\n{output}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed:\n{e}")

def decrypt_action():
    if not file_path.get() or not password.get():
        messagebox.showerror("Error", "Please select a file and enter a password.")
        return
    try:
        output = decrypt_file(file_path.get(), password.get())
        messagebox.showinfo("Success", f"File decrypted:\n{output}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{e}")

# Build GUI
root = tk.Tk()
root.title("AES-256 File Encryption Tool")
root.geometry("500x250")

file_path = tk.StringVar()
password = tk.StringVar()

tk.Label(root, text="Select File:").pack(pady=5)
tk.Entry(root, textvariable=file_path, width=50).pack(pady=5)
tk.Button(root, text="Browse", command=select_file).pack(pady=5)

tk.Label(root, text="Enter Password:").pack(pady=5)
tk.Entry(root, textvariable=password, show='*', width=30).pack(pady=5)

tk.Button(root, text="Encrypt File", command=encrypt_action, bg="green", fg="white").pack(pady=10)
tk.Button(root, text="Decrypt File", command=decrypt_action, bg="blue", fg="white").pack(pady=5)

root.mainloop()
