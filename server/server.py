from flask import Flask, request, jsonify, send_file
import os
import base64

app = Flask(__name__)

#Path to store encrypted files
RECEIVED_FOLDER = os.path.join(os.path.dirname(__file__), "received")
os.makedirs(RECEIVED_FOLDER, exist_ok=True)

#This server only stores and retrieves encrypted files.
#It does NOT perform any encryption, decryption, or signature verification.

@app.route("/upload", methods=["POST"])
def upload_file():
    try:
        #Get encrypted parts
        ciphertext = request.files['ciphertext'].read()
        iv = request.files['iv'].read()
        encrypted_key = request.files['encrypted_key'].read()
        signature = request.files['signature'].read()
        filename = request.form['filename']

        print(f"[+] Uploading encrypted file parts for: {filename}")

        #Save each component with unique suffix
        base = os.path.join(RECEIVED_FOLDER, filename)
        with open(f"{base}.cipher", "wb") as f:
            f.write(ciphertext)
        with open(f"{base}.iv", "wb") as f:
            f.write(iv)
        with open(f"{base}.key", "wb") as f:
            f.write(encrypted_key)
        with open(f"{base}.sig", "wb") as f:
            f.write(signature)

        return jsonify({"message": f"Encrypted file stored securely as '{filename}'"}), 200

    except Exception as e:
        print(f"[!] Error: {e}")
        return jsonify({"error": str(e)}), 500
    

@app.route("/download/<filename>", methods=["GET"])
def download_file(filename):
    try:
        base = os.path.join(RECEIVED_FOLDER, filename)

        files = {}
        for ext in ['.cipher', '.iv', '.key', '.sig']:
            path = f"{base}{ext}"
            if not os.path.exists(path):
                return jsonify({"error": f"Missing {ext} for {filename}"}), 404
            with open(path, "rb") as f:
                encoded = base64.b64encode(f.read()).decode('utf-8') #Binary data cannot be natively serialized into JSON.
                files[ext.strip('.')] = encoded                      #Converts binary data into a text-safe format (only ASCII characters).

        return jsonify(files), 200  #Flask will return as JSON with base64

    except Exception as e:
        print(f"[!] Download error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/list_files", methods=["GET"])
def list_files():
    try:
        files = set()
        for filename in os.listdir(RECEIVED_FOLDER):
            base, ext = os.path.splitext(filename)
            if ext in ['.cipher', '.iv', '.key', '.sig']:
                files.add(base)
        return jsonify(sorted(list(files))), 200
    except Exception as e:
        print(f"[!] Error listing files: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000) #Binding, listen on all available interfaces
