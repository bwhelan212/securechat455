Requirements:
- node
- npm
- python 
- flasksocket-io
- socket.io

Create a python environment
python3 -m venv .venv
source .venv/bin/activate
pip install Flask Flask-SocketIO Flask-Session

Generate self-signed certs in /SecureChat/server folder
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

To run the program:
go to location of /SecureChat/server and run:
python3 server.py

Naivgate to one of the following:
https://localhost:5001
https://127.0.0.1:5001
https://<your_ip>:5001

admin credentials:
admin/password123

### `server.py`
main server-side script. handles HTTP requests, manages user sessions, and sets up WebSocket connections using Flask-SocketIO.
- **User Authentication**: Handles login and logout requests, verifies user credentials, and manages user sessions.
- **WebSocket Events**: Manages WebSocket connections and events, such as user connections, disconnections, and message handling.
- **Session Management**: Uses Flask-Session to store session data on the filesystem, ensuring that session data is available across different requests and WebSocket connections.

### `auth.js`
client-side script handles the login form submission
- **Form Submission**: Prevents the default form submission behavior and sends an asynchronous request to the server.
- **User Feedback**: Displays messages to the user based on the server's response (e.g., login successful or invalid credentials).
- **Redirection**: Redirects the user to the chat page upon successful login.

### script.js
client-side script that manages the WebSocket connection and handles real-time events in the chat application.
- **WebSocket Connection**: Establishes a WebSocket connection to the server and handles reconnection attempts.
- **Event Handling**: Listens for various WebSocket events, such as user connections, disconnections, and incoming messages, and updates the chat interface accordingly.
- **Message Sending**: Provides a function to send messages to the server, ensuring that messages are sent at a controlled rate to prevent spamming.

### users.json
stores user credentials in JSON format. It is used by the server to verify user credentials during the login process. The file contains key-value pairs where the key is the username and the value is the password.
