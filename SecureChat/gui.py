import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog
import requests
import socketio
import os

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

SERVER_URL = "http://localhost:5000"

sio = socketio.Client()

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
            response = requests.post(f"{SERVER_URL}/login", json={"username": username, "password": password})
            if response.status_code == 200:
                self.after_cancel(self.after_id) if self.after_id else None
                self.destroy()
                app = SecureChatApp(username)
                app.mainloop()
            else:
                self.status_label.configure(text="Login failed. Try again.")
        except Exception as e:
            self.status_label.configure(text=f"Error: {e}")

    def register(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        try:
            response = requests.post(f"{SERVER_URL}/register", json={"username": username, "password": password})
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
            sio.connect(SERVER_URL)
            sio.emit("join", self.username)

            @sio.on("message")
            def on_message(data):
                sender = data.get("sender", "Unknown")
                msg = data.get("message", "")
                if self.recipient == sender or sender == self.username:
                    self.append_message(f"{sender}: {msg}")

            @sio.on("file")
            def on_file(data):
                sender = data["sender"]
                filename = data["filename"]
                filedata = bytes.fromhex(data["data"])
                if self.recipient == sender:
                    save_path = filedialog.asksaveasfilename(initialfile=filename)
                    if save_path:
                        with open(save_path, "wb") as f:
                            f.write(filedata)
                        self.append_message(f"{sender}: {filename} saved.")
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
            sio.emit("message", {
                "sender": self.username,
                "recipient": self.recipient,
                "message": msg
            })
            self.entry.delete(0, tk.END)

    def send_file(self):
        if not self.recipient:
            return
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, "rb") as f:
                filedata = f.read()
            filename = os.path.basename(file_path)
            sio.emit("file", {
                "sender": self.username,
                "recipient": self.recipient,
                "filename": filename,
                "data": filedata.hex()
            })
            self.append_message(f"{self.username}: {filename}")

    def load_users(self):
        try:
            response = requests.get(f"{SERVER_URL}/users", params={"exclude": self.username})
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
