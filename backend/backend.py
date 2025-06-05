from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os

app = Flask(__name__)
CORS(app)

# In-memory storage: password -> { encrypted message, salt }
storage = {}

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    data = request.get_json()
    password = data.get("password")
    message = data.get("message")

    if not password or not message:
        return jsonify({"error": "Password and message required"}), 400

    salt = os.urandom(16)
    key = derive_key(password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(message.encode())

    # Save encrypted message + salt
    storage[password] = {
        "encrypted": encrypted.decode(),
        "salt": base64.b64encode(salt).decode()
    }

    return jsonify({"message": "Message encrypted and saved"})

@app.route('/retrieve', methods=['POST'])
def retrieve_message():
    data = request.get_json()
    password = data.get("password")
    if not password or password not in storage:
        return jsonify({"error": "Invalid password or no message found"}), 400

    entry = storage[password]
    salt = base64.b64decode(entry["salt"])
    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted = fernet.decrypt(entry["encrypted"].encode()).decode()
    except Exception as e:
        return jsonify({"error": "Decryption failed. Wrong password?"}), 400

    return jsonify({"message": decrypted})

if __name__ == '__main__':
    app.run(debug=True)
