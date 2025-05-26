import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import secrets

# Constants
SALT_SIZE = 16
KEY_SIZE = 32  # 256 bits for AES-256
ITERATIONS = 100_000
NONCE_SIZE = 12  # Recommended nonce size for AES-GCM

backend = default_backend()

def derive_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=backend
    )
    return kdf.derive(password_bytes)

def encrypt_file(password: str, input_file: str, output_file: str):
    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password, salt)
    nonce = secrets.token_bytes(NONCE_SIZE)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=backend)
    encryptor = cipher.encryptor()

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Store salt + nonce + tag + ciphertext in output file
    with open(output_file, 'wb') as f:
        f.write(salt + nonce + encryptor.tag + ciphertext)

def decrypt_file(password: str, input_file: str, output_file: str):
    with open(input_file, 'rb') as f:
        file_content = f.read()

    salt = file_content[:SALT_SIZE]
    nonce = file_content[SALT_SIZE:SALT_SIZE+NONCE_SIZE]
    tag = file_content[SALT_SIZE+NONCE_SIZE:SALT_SIZE+NONCE_SIZE+16]
    ciphertext = file_content[SALT_SIZE+NONCE_SIZE+16:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=backend)
    decryptor = cipher.decryptor()

    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise ValueError("Decryption failed. Incorrect password or corrupted file.")

    with open(output_file, 'wb') as f:
        f.write(plaintext)

# GUI
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced AES-256 File Encryption Tool")

        self.password_label = tk.Label(root, text="Password:")
        self.password_label.grid(row=0, column=0, padx=10, pady=10)

        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.grid(row=0, column=1, padx=10, pady=10)

        self.filepath_label = tk.Label(root, text="Select File:")
        self.filepath_label.grid(row=1, column=0, padx=10, pady=10)

        self.filepath_var = tk.StringVar()
        self.filepath_entry = tk.Entry(root, textvariable=self.filepath_var, width=40)
        self.filepath_entry.grid(row=1, column=1, padx=10, pady=10)

        self.browse_button = tk.Button(root, text="Browse", command=self.browse_file)
        self.browse_button.grid(row=1, column=2, padx=10, pady=10)

        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=2, column=0, padx=10, pady=10)

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=2, column=1, padx=10, pady=10)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.filepath_var.set(filename)

    def encrypt(self):
        password = self.password_entry.get()
        input_file = self.filepath_var.get()

        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return
        if not input_file or not os.path.isfile(input_file):
            messagebox.showerror("Error", "Please select a valid file to encrypt.")
            return

        output_file = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc")])
        if not output_file:
            return

        try:
            encrypt_file(password, input_file, output_file)
            messagebox.showinfo("Success", f"File encrypted successfully:\n{output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def decrypt(self):
        password = self.password_entry.get()
        input_file = self.filepath_var.get()

        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return
        if not input_file or not os.path.isfile(input_file):
            messagebox.showerror("Error", "Please select a valid file to decrypt.")
            return

        output_file = filedialog.asksaveasfilename(defaultextension=".dec", filetypes=[("Decrypted Files", "*.*")])
        if not output_file:
            return

        try:
            decrypt_file(password, input_file, output_file)
            messagebox.showinfo("Success", f"File decrypted successfully:\n{output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
