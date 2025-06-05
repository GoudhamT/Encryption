import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet

app = Flask(__name__)
CORS(app)

# Generate key from user password (simple)
def get_fernet(key_str):
    # Ensure key is 32 url-safe base64 bytes: pad or hash accordingly
    # For simplicity, we hash the user key to 32 bytes base64
    import base64, hashlib
    k = hashlib.sha256(key_str.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(k))

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.json
    message = data.get("message", "")
    key = data.get("key", "")
    if not message or not key:
        return jsonify({"error": "Missing message or key"}), 400
    f = get_fernet(key)
    token = f.encrypt(message.encode()).decode()
    return jsonify({"encrypted": token})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.json
    encrypted = data.get("encrypted", "")
    key = data.get("key", "")
    if not encrypted or not key:
        return jsonify({"error": "Missing encrypted message or key"}), 400
    f = get_fernet(key)
    try:
        decrypted = f.decrypt(encrypted.encode()).decode()
    except Exception:
        return jsonify({"error": "Decryption failed. Wrong key or corrupted data."}), 400
    return jsonify({"message": decrypted})

@app.route("/")
def home():
    return "Hello from Render!"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
