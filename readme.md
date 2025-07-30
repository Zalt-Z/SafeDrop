# SafeDrop – Secure File Transfer System

**SafeDrop** is a client-server Python application that securely encrypts, transmits, and stores files with **confidentiality**, **integrity**, and **non-repudiation** using AES, RSA, and digital signatures.

## Features

- **AES-256-CBC** encryption for file confidentiality.
- **RSA-OAEP** to securely encrypt AES keys.
- **RSA-PSS** digital signature for data integrity and sender verification.
- **Base64 encoding** for safe HTTP JSON transmission.
- **Tkinter GUI** for easy user interaction.
- **File dropdown** to select available encrypted files on the server.

## File Structure
```
SafeDrop/
├── certs/ # Generated RSA key pairs
├── client/
│ └── gui.py # Main GUI application
│ └── crypto.py # Cryptographic logic (encrypt, sign, decrypt, verify)
├── server/
│ └── server.py # Flask server to store and serve encrypted files
│ └── received/ # Folder to store received files
├── generate_keys.py # Script to generate RSA key pairs
├── readme.md
```

## Setup Instructions

### How to run the server
Perform the following steps on another machine such as a Ubuntu Virtual Machine.

**Install required Python libraries:**
```
pip install flask
```

**Start the Server:**
```
python ./server/server.py
```
Server listens on ```http://0.0.0.0:5000``` and stores encrypted files in ```received/```.


### How to run the client
Perform the following steps on your host machine.

**Install required Python libraries:**
```
pip install cryptography requests
```

**Generate RSA key pairs:**
```
python generate_keys.py
```
This creates 4 files in ```certs/```:
```
sender_private.pem
sender_public.pem
receiver_private.pem
receiver_public.pem
```

**Run the Client GUI**
```
python ./client/gui.py
```
*Important: Make sure to update the ```server_ip``` variable in gui.py to match your VM's IP address.*
```
server_ip = "192.168.19.XXX"  # Update this!
```

## Functionality

### Upload Flow
1. User selects a file.
2. File is AES-256 encrypted.
3. AES key is encrypted with receiver's RSA public key.
4. Ciphertext is signed using sender's private RSA key.
5. Four components (cipher, iv, key, sig) are uploaded to the server.

### Download & Verify Flow
1. User selects a filename from dropdown.
2. The four file components are downloaded from the server.
3. Signature is verified with sender's public key.
4. AES key is decrypted using receiver's private key.
5. File is decrypted and saved locally.

## Testing Tips
* Create a text file (ie. secret.txt) with text like "This is my secret"
* Use two machines: one for running the server, another for the client GUI.
* Try corrupting one file component on the server to observe signature failure.
* Use a unique file name when uploading to avoid overwriting.