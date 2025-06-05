const backendURL = "https://your-backend.onrender.com"; // update after deployment

const validUsername = "admin";
const validPassword = "secret123";

function login() {
    const u = document.getElementById("username").value;
    const p = document.getElementById("password").value;

    if (u === validUsername && p === validPassword) {
        localStorage.setItem("loggedIn", "true");
        window.location.href = "index.html";
    } else {
        document.getElementById("error").textContent = "Invalid credentials";
    }
}

function checkAuth() {
    if (localStorage.getItem("loggedIn") !== "true") {
        window.location.href = "login.html";
    }
}

function logout() {
    localStorage.removeItem("loggedIn");
    window.location.href = "login.html";
}

async function encryptMessage() {
    const message = document.getElementById("message").value;
    const key = document.getElementById("key").value;
    const res = await fetch(`${backendURL}/encrypt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message, key })
    });
    const data = await res.json();
    document.getElementById("encrypted").textContent = data.encrypted || data.error;
}

async function decryptMessage() {
    const encrypted = document.getElementById("encryptedMsg").value;
    const key = document.getElementById("decryptKey").value;
    const res = await fetch(`${backendURL}/decrypt`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ encrypted, key })
    });
    const data = await res.json();
    document.getElementById("decrypted").textContent = data.message || data.error;
}
