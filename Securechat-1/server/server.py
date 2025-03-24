from chat_logger import log_message
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import os
import json
import bcrypt
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

USER_FILE = "users.json"
if not os.path.exists(USER_FILE):
    with open(USER_FILE, "w") as f:
        json.dump({}, f)

connected_users = {}  # sid: username

# === Brute-force tracking ===
login_attempts = {}
MAX_ATTEMPTS = 5
BLOCK_DURATION = timedelta(minutes=5)

# === User handling ===
def load_users():
    with open(USER_FILE, "r") as f:
        return json.load(f)

def save_users(data):
    with open(USER_FILE, "w") as f:
        json.dump(data, f, indent=2)

# === Routes ===
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    public_key = data["public_key"] 

    users = load_users()
    if username in users:
        return "Username already exists", 400

    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[username] = {"password": hashed, "public_key": public_key}
    save_users(users)
    return "User registered", 200

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    now = datetime.now()
    attempts = login_attempts.get(username, {"count": 0, "last_attempt": now, "blocked_until": None})

    if attempts["blocked_until"] and now < attempts["blocked_until"]:
        return "Too many login attempts. Please try again later.", 403

    users = load_users()
    if username not in users:
        return "User not found", 400

    hashed = users[username]["password"].encode()
    if bcrypt.checkpw(password.encode(), hashed):
        login_attempts[username] = {"count": 0, "last_attempt": now, "blocked_until": None}
        return "Login successful", 200
    else:
        attempts["count"] += 1
        attempts["last_attempt"] = now
        if attempts["count"] >= MAX_ATTEMPTS:
            attempts["blocked_until"] = now + BLOCK_DURATION
        login_attempts[username] = attempts
        return "Incorrect password", 401

@app.route("/users", methods=["GET"])
def get_users():
    exclude = request.args.get("exclude")
    users = load_users()
    return jsonify([u for u in users if u != exclude])

# === SocketIO Events ===
@socketio.on("connect")
def handle_connect():
    print("Client connected.")

@socketio.on("join")
def handle_join(data):
    username = data
    connected_users[request.sid] = username
    print(f"[JOIN] {username}")
    send_user_list()

@socketio.on("disconnect")
def handle_disconnect():
    sid = request.sid
    if sid in connected_users:
        left_user = connected_users[sid]
        print(f"[DISCONNECT] {left_user}")
        del connected_users[sid]
        send_user_list()

@socketio.on("message")
def handle_message(data):
    sender = data.get("sender")
    recipient = data.get("recipient")
    message = data.get("message")

    log_message(sender, recipient, message)
    emit("message", data, broadcast=True)

@socketio.on("file")
def handle_file(data):
    emit("file", data, broadcast=True)

def send_user_list():
    usernames = list(set(connected_users.values()))
    socketio.emit("user_list", usernames)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5001, ssl_context=("cert.pem", "key.pem"), debug=True)
