from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
import base64
import hashlib

app = Flask(__name__)

def generate_key(secret_key):
    return base64.urlsafe_b64encode(hashlib.sha256(secret_key.encode()).digest())

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.json
    key = generate_key(data["key"])
    f = Fernet(key)
    encrypted = f.encrypt(data["message"].encode()).decode()
    return jsonify({"encrypted": encrypted})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.json
    key = generate_key(data["key"])
    f = Fernet(key)
    try:
        decrypted = f.decrypt(data["encrypted"].encode()).decode()
        return jsonify({"message": decrypted})
    except:
        return jsonify({"error": "Invalid key or data"}), 400

@app.route("/")
def home():
    return "Encryption API is running."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
