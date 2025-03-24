import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import requests
import socketio
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
import base64

def encrypt_message(message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_message(encrypted_message, aes_key):
    data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def generate_keys(username):
    # Generate RSA key pair
    key = RSA.generate(4096)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Save keys with unique filenames
    with open(f"private_key_{username}.pem", "wb") as f:
        f.write(private_key)

    with open(f"public_key_{username}.pem", "wb") as f:
        f.write(public_key)
        
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# SERVER_URL = "http://localhost:5000" # Local
SERVER_URL = "https://192.168.1.88:5001" # for wss implementation

sio = socketio.Client(ssl_verify=False)

class SecureChatLogin(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SecureChat - Login")
        self.geometry("400x300")

        self.label = ctk.CTkLabel(self, text="SecureChat Login", font=ctk.CTkFont(size=20, weight="bold"))
        self.label.pack(pady=20)

        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username")
        self.username_entry.pack(pady=10)

        self.password_entry = ctk.CTkEntry(self, placeholder_text="Password", show="*")
        self.password_entry.pack(pady=10)

        self.login_button = ctk.CTkButton(self, text="Login", command=self.login)
        self.login_button.pack(pady=5)

        self.register_button = ctk.CTkButton(self, text="Register", command=self.register)
        self.register_button.pack(pady=5)

        self.status_label = ctk.CTkLabel(self, text="")
        self.status_label.pack(pady=10)

        self.after_id = None

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        try:
            response = requests.post(f"{SERVER_URL}/login", json={"username": username, "password": password}, verify=False)
            if response.status_code == 200:
                self.after_cancel(self.after_id) if self.after_id else None
                self.destroy()
                app = SecureChatApp(username)
                app.mainloop()
            else:
                self.status_label.configure(text=f"Login failed. Try again. {response.text}")
        except Exception as e:
            self.status_label.configure(text=f"Error: {e}")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        try:
            generate_keys(username)
            
            with open(f"public_key_{username}.pem", "rb") as f:
                public_key = f.read()
            response = requests.post(f"{SERVER_URL}/register", json={"username": username, "password": password, "public_key": public_key.decode()}, verify=False)
            # print(f"Server response: {response.status_code}, {response.text}")  # Debugging log
            if response.status_code == 200:
                self.status_label.configure(text="Registration successful. You can now log in.")
                
            else:
                self.status_label.configure(text="Registration failed. Try another username.")
        except Exception as e:
            self.status_label.configure(text=f"Error: {e}")

class SecureChatApp(ctk.CTk):
    def __init__(self, username):
        super().__init__()
        self.title(f"SecureChat - {username}")
        self.geometry("900x600")
        self.username = username
        self.recipient = None

        self.user_menu = ctk.CTkOptionMenu(self, values=["Loading..."], command=self.change_recipient)
        self.user_menu.set("Loading...")
        self.user_menu.pack(pady=10)

        self.chat_box = ctk.CTkTextbox(self, height=400, width=800, state="disabled")
        self.chat_box.pack(pady=10)

        self.entry = ctk.CTkEntry(self, placeholder_text="Type your message...", width=600)
        self.entry.pack(pady=5)

        self.send_button = ctk.CTkButton(self, text="Send", command=self.send_message)
        self.send_button.pack(pady=5)

        self.file_button = ctk.CTkButton(self, text="Send File", command=self.send_file)
        self.file_button.pack(pady=5)

        self.after(100, self.load_users)
        self.connect_to_socket()

    def connect_to_socket(self):
        try:
            sio.connect("wss://192.168.1.88:5001")
            sio.emit("join", self.username)

            @sio.on("message")
            def on_message(data):
                try:
                    sender = data.get("sender", "Unknown")
                    encrypted_message = data.get("message", "")
                    encrypted_aes_key = base64.b64decode(data.get("aes_key", ""))
                    if sender == self.username:
                        return
                    
                    with open(f"private_key_{self.username}.pem", "rb") as f:
                        private_key = RSA.import_key(f.read())
                    cipher_rsa = PKCS1_OAEP.new(private_key)
                    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
                    
                    decrypted_message = decrypt_message(encrypted_message, aes_key)

                    #msg = data.get("message", "")
                    if self.recipient == sender or sender == self.username:
                        self.append_message(f"{sender}: {decrypted_message}")
                    # else:
                    #     self.append_message(f"You: {}")
                except Exception as e:
                    self.append_message(f"Error decrypting message: {e}")
                    print(f"error, recipient: {self.recipient}, sender: {sender}, message: {encrypted_message}")

            @sio.on("file")
            def on_file(data):
                try:
                    sender = data["sender"]
                    if sender == self.username:
                        return
                    filename = data["filename"]
                    ciphertext = base64.b64decode(data["data"])
                    nonce = base64.b64decode(data["nonce"])
                    tag = base64.b64decode(data["tag"])
                    encrypted_aes_key = base64.b64decode(data["aes_key"])

                    # Decrypting the session key using the recipient's private key
                    with open(f"private_key_{self.username}.pem", "rb") as f:
                        private_key = RSA.import_key(f.read())
                    cipher_rsa = PKCS1_OAEP.new(private_key)
                    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

                    # Decrypt w/AES
                    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
                    filedata = cipher_aes.decrypt_and_verify(ciphertext, tag)

                    if self.recipient == sender:
                        save_path = filedialog.asksaveasfilename(initialfile=filename)
                        if save_path:
                            with open(save_path, "wb") as f:
                                f.write(filedata)
                            self.append_message(f"{sender}: {filename} saved.")
                except Exception as e:
                    self.append_message(f"Error receiving or decrypting file: {e}")
                    print(f"Error: {e}")
        
        except Exception as e:
            self.append_message(f"[Connection error] {e}")

    def append_message(self, message):
        self.chat_box.configure(state="normal")
        self.chat_box.insert(tk.END, message + "\n")
        self.chat_box.configure(state="disabled")
        self.chat_box.see(tk.END)

    def change_recipient(self, value):
        self.recipient = value
        self.append_message(f"Switched chat to {value}")

    def send_message(self):
        msg = self.entry.get()
        
        if msg and self.recipient:
            aes_key = get_random_bytes(32)
            encrypted_message = encrypt_message(msg, aes_key)

            with open(f"public_key_{self.recipient}.pem", "rb") as f:
                recipient_public_key = RSA.import_key(f.read())
            cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            sio.emit("message", {
                "sender": self.username,
                "recipient": self.recipient,
                "message": encrypted_message,
                "aes_key": base64.b64encode(encrypted_aes_key).decode()
            })
            self.append_message(f"You: {msg}")

            self.entry.delete(0, tk.END)

    def send_file(self):
        if not self.recipient:
            self.append_message("No recipient selected.")
            return
        if not self.winfo_exists():
            self.append_message("Error: Parent window does not exist.")
            return
        try:
            print("Opening file dialog...")
            file_path = filedialog.askopenfilename()
            print(f"File selected: {file_path}")
            if not file_path:
                self.append_message("No file selected.")
                return
            with open(file_path, "rb") as f:
                filedata = f.read()
            aes_key = get_random_bytes(32)
            cipher_aes = AES.new(aes_key, AES.MODE_EAX)
            ciphertext, tag = cipher_aes.encrypt_and_digest(filedata)

            # Encrypt the AES key using the recipient's public key
            with open(f"public_key_{self.recipient}.pem", "rb") as f:
                recipient_public_key = RSA.import_key(f.read())
            cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)
            
            filename = os.path.basename(file_path)
            sio.emit("file", {
                "sender": self.username,
                "recipient": self.recipient,
                "filename": filename,
                "data": base64.b64encode(ciphertext).decode(),  # Encode ciphertext as base64
                "nonce": base64.b64encode(cipher_aes.nonce).decode(),  # Encode nonce as base64
                "tag": base64.b64encode(tag).decode(),  # Encode tag as base64
                "aes_key": base64.b64encode(encrypted_aes_key).decode()  # Encode encrypted AES key as base64
            })
            self.append_message(f"{self.username}: {filename}")

        except Exception as e:
            self.append_message(f"Error selecting file: {e}")
            print(f"Error: {e}")

    def load_users(self):
        try:
            response = requests.get(f"{SERVER_URL}/users", params={"exclude": self.username}, verify=False)
            if response.status_code == 200:
                users = response.json()
                if users:
                    self.recipient = users[0]
                    self.user_menu.configure(values=users)
                    self.user_menu.set(users[0])
        except Exception as e:
            self.append_message(f"Failed to load users: {e}")

if __name__ == "__main__":
    login_window = SecureChatLogin()
    login_window.after_id = login_window.after(100, lambda: None)
    login_window.mainloop()
