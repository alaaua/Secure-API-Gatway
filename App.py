from flask import Flask, request, jsonify
from auth_utils import generate_token, validate_token
from encryption_utils import encrypt_data, decrypt_data
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    filename="logs/api_requests.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# Dummy secret key for JWT token generation
SECRET_KEY = "mysecretkey"

# Endpoint: Generate JWT Token
@app.route('/generate-token', methods=['POST'])
def get_token():
    user_data = request.json.get("user")
    if not user_data:
        return jsonify({"error": "User data required"}), 400

    token = generate_token(user_data, SECRET_KEY)
    return jsonify({"token": token})

# Endpoint: Secure Data (AES Encryption)
@app.route('/secure-data', methods=['POST'])
def secure_data():
    try:
        # Log the request
        logging.info("Request received: /secure-data")

        # Validate JWT Token
        token = request.headers.get("Authorization")
        if not token or not validate_token(token, SECRET_KEY):
            return jsonify({"error": "Invalid or missing token"}), 401

        # Encrypt Data
        data = request.json.get("data")
        if not data:
            return jsonify({"error": "No data provided"}), 400

        encrypted_data = encrypt_data(data)
        return jsonify({"encrypted_data": encrypted_data})

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

# Endpoint: Decrypt Data (AES Decryption)
@app.route('/decrypt-data', methods=['POST'])
def decrypt_data_route():
    try:
        logging.info("Request received: /decrypt-data")

        # Validate JWT Token
        token = request.headers.get("Authorization")
        if not token or not validate_token(token, SECRET_KEY):
            return jsonify({"error": "Invalid or missing token"}), 401

        # Decrypt Data
        encrypted_data = request.json.get("encrypted_data")
        if not encrypted_data:
            return jsonify({"error": "No encrypted data provided"}), 400

        decrypted_data = decrypt_data(encrypted_data)
        return jsonify({"decrypted_data": decrypted_data})

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    app.run(debug=True)
