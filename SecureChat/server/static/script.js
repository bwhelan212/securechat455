const socket = io("wss://localhost:5000", {
    reconnection: true, 
    reconnectionAttempts: 5, 
    reconnectionDelay: 2000 
});

let lastMessageTime = 0;
const MESSAGE_RATE_LIMIT = 1500; // 1.5 seconds in milliseconds

socket.on("connect", function () {
    console.log("Connected to WebSocket server.");
});

socket.on("disconnect", function () {
    console.log("Disconnected from server. Attempting to reconnect...");
});

socket.on("reconnect", function () {
    console.log("Reconnected to the server.");
});

socket.on("user_connected", function (data) {
    console.log(data.message);
    const chat = document.getElementById("chat");
    const newMessage = document.createElement("p");
    newMessage.style.fontStyle = "italic";
    newMessage.innerText = data.message;
    chat.appendChild(newMessage);
});

socket.on("user_disconnected", function (data) {
    console.log(data.message);
    const chat = document.getElementById("chat");
    const newMessage = document.createElement("p");
    newMessage.style.fontStyle = "italic";
    newMessage.innerText = data.message;
    chat.appendChild(newMessage);
});

socket.on("message", function (data) {
    console.log("Received:", data);
    const chat = document.getElementById("chat");
    const newMessage = document.createElement("p");
    newMessage.innerText = data;
    chat.appendChild(newMessage);
});

function sendMessage() {
    const input = document.getElementById("messageInput");
    const message = input.value.trim();
    
    if (message === "") return;

    let currentTime = Date.now();
    if (currentTime - lastMessageTime < MESSAGE_RATE_LIMIT) {
        console.log("Please wait before sending another message.");
        alert("You're sending messages too fast! Please wait.");
        return;
    }

    console.log("Sending:", message);
    socket.send(message);
    lastMessageTime = currentTime;
    input.value = "";
}

// Listen for "Enter" key press
document.getElementById("messageInput").addEventListener("keydown", function (event) {
    if (event.key === "Enter") {
        event.preventDefault();
        sendMessage();
    }
});

// Send a heartbeat every 10 seconds to keep connection active
setInterval(() => {
    socket.emit("heartbeat", { status: "alive" });
}, 10000);
