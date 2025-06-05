from flask import Flask, request, jsonify, session
from flask_cors import CORS
from cryptography.fernet import Fernet
import base64
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Needed for session management
CORS(app, supports_credentials=True)

# In-memory store for messages: key_word -> encrypted_message
store = {}

# Fixed username/password (do NOT show in frontend)
FIXED_USERNAME = "admin"
FIXED_PASSWORD = "password"

def get_fernet(key_str):
    k = hashlib.sha256(key_str.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(k))

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username", "")
    password = data.get("password", "")
    if username == FIXED_USERNAME and password == FIXED_PASSWORD:
        session["logged_in"] = True
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True})

def is_logged_in():
    return session.get("logged_in", False)

@app.route("/save", methods=["POST"])
def save_message():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    key_word = data.get("key", "")
    message = data.get("message", "")
    if not key_word or not message:
        return jsonify({"error": "Missing key or message"}), 400

    f = get_fernet(key_word)
    encrypted = f.encrypt(message.encode()).decode()
    store[key_word] = encrypted
    return jsonify({"success": True})

@app.route("/get", methods=["POST"])
def get_message():
    if not is_logged_in():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    key_word = data.get("key", "")
    if not key_word:
        return jsonify({"error": "Missing key"}), 400
    encrypted = store.get(key_word)
    if not encrypted:
        return jsonify({"error": "No message found for this key"}), 404

    f = get_fernet(key_word)
    try:
        decrypted = f.decrypt(encrypted.encode()).decode()
    except:
        return jsonify({"error": "Decryption failed"}), 400

    return jsonify({"message": decrypted})

@app.route("/")
def home():
    return "Hello from backend!"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
