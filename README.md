# Secure Chat

## Connect as client
Simply download and launch gui.exe on a windows machine from the respective folder

## Set Up

### server.py 
1. **Create a Python Environment:**
   ```bash
   python3 -m venv venv
2. **Actiate then install the following dependencies with:**
    ```bash
    pip install customtkinter python-socketio pycryptodome requests flask-socketio

## Key Features
1. User Friendly interface
2. File sharing capabilities
3. Emoji and Rich Media Support
4. Security Hardening
5. User Authentication
6. Real Time Messaging 
7. Secure Connection
8. Rate limiting
9. Connection Handling

## File breakdown
### server.py
This is the main server-side script.It handles HTTP requests, manages user sessions, interactions with user data, and sets up WebSocket connections using Flask-SocketIO. 

For authentication it verifies login and handles registration on backend, verifies user credentials, and manages user sessions. Prevents bruteforce login attempts, broadcasts of message.
It also Manages WebSocket connections and events, such as user connections, disconnections, and message handling.

### gui.py
python file used to create executable
encrypts and decrypts messages using AES and session keys
generates RSA key pair for users upon registration
handles user interface with tkinter and customtkinter
handles frontend for login, registration, messaging, file sharing

### gui.exe
Client side executable

### Logs directory (server/logs)
Directory for chat message history

### users.json (server/users.json)
Information about registered users for logging in and encryption and stored here. The server has access to this and only knows the public key of the users. Only the clients have access to their private keys. 


