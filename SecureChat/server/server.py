from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, send, emit, disconnect
from flask_session import Session
import json
import os
import time

app = Flask(__name__, template_folder="templates", static_folder="static")
app.debug = True
app.secret_key = "supersecretkey"
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.abspath("flask_session")
Session(app)

socketio = SocketIO(app, cors_allowed_origins="*")

USER_DB = "users.json"

# Ensure users.json exists
def load_users():
    if not os.path.exists(USER_DB):
        save_users({
            "admin": "password123", 
            "team_member": "securechat456"
        })
        return {"admin": "password123", "team_member": "securechat456"}

    try:
        with open(USER_DB, "r") as f:
            data = f.read()
            return json.loads(data) if data.strip() else {}
    except (FileNotFoundError, json.JSONDecodeError):
        print("Error: users.json is missing or corrupted. Resetting to default.")
        save_users({"admin": "password123", "team_member": "securechat456"})
        return {"admin": "password123", "team_member": "securechat456"}

def save_users(users):
    with open(USER_DB, "w") as f:
        json.dump(users, f)

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        username = data.get("username")
        password = data.get("password")

        users = load_users()

        if username in users and users[username] == password:
            session["user"] = username
            print(f"User {username} logged in successfully")
            return jsonify({"success": True, "message": "Login successful!"})

        print("Invalid login attempt")
        return jsonify({"success": False, "message": "Invalid credentials!"})

    except Exception as e:
        print("Error in login:", e)
        return jsonify({"success": False, "message": "Internal Server Error"}), 500

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("auth_page"))

@app.route("/")
def auth_page():
    return render_template("auth.html")

@app.route("/chat")
def chat_page():
    if "user" not in session:
        print("User not authenticated. Redirecting to login.")
        return redirect(url_for("auth_page"))
    return render_template("index.html")

user_last_message_time = {}
MESSAGE_RATE_LIMIT = 1.5  # Users must wait 1.5 seconds between messages

@socketio.on("connect")
def handle_connect():
    user = session.get("user", "Guest")
    print(f"User {user} has connected.")
    emit("user_connected", {"message": f"{user} has joined the chat."}, broadcast=True)

@socketio.on("disconnect")
def handle_disconnect():
    user = session.get("user", "Guest")
    print(f"User {user} has disconnected.")
    emit("user_disconnected", {"message": f"{user} has left the chat."}, broadcast=True)

@socketio.on("message")
def handle_message(msg):
    user = session.get("user", "guest")
    current_time = time.time()

    if user in user_last_message_time:
        time_since_last_message = current_time - user_last_message_time[user]
        if time_since_last_message < MESSAGE_RATE_LIMIT:
            print(f"{user} is sending messages too fast. Ignoring message.")
            return

    user_last_message_time[user] = current_time

    print(f"User {user} sent a message")
    send(f"{user}: {msg}", broadcast=True)

# Start Server
if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, ssl_context=('cert.pem', 'key.pem'))
