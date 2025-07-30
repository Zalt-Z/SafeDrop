import os
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils

import secrets  #For secure AES key/IV generation

#Load RSA Public Key (for encrypting AES key)
def load_rsa_public_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

#Load RSA Private Key (for signing)
def load_rsa_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

#AES encryption + RSA signature
def encrypt_and_sign(filepath, sender_private_path, receiver_public_path):
    #Load file to encrypt
    with open(filepath, "rb") as f:
        plaintext = f.read()

    #Generate AES key and IV
    aes_key = secrets.token_bytes(32)  #256-bit AES
    iv = secrets.token_bytes(16)       #128-bit IV

    #Padding manually to block size (16 bytes)
    #Common padding scheme used here: PKCS#7-like
    padding_len = 16 - len(plaintext) % 16 #16 - (200 bytes) % 16 = 8
    plaintext += bytes([padding_len] * padding_len) #[8]*8 = [8, 8, 8, 8, 8, 8, 8, 8] = b'\x08\x08\x08\x08\x08\x08\x08\x08'

    #AES-CBC encryption
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend()) #Setup AES in CBC mode
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize() #Performs actual encryption

    #Load RSA keys
    sender_private_key = load_rsa_private_key(sender_private_path)
    receiver_public_key = load_rsa_public_key(receiver_public_path)

    #Sign ciphertext with sender's private key
    signature = sender_private_key.sign( #Generate Digital Signature
        ciphertext,
        asym_padding.PSS(mgf=asym_padding.MGF1(hashes.SHA256()), salt_length=asym_padding.PSS.MAX_LENGTH),
        hashes.SHA256() 
    )#Sign data with RSASSA-PSS (probabilistic signature scheme), SHA-256 hash of the data, Adds randomness (PSS salt) to prevent signature reuse

    #Encrypt AES key with receiver’s public key
    encrypted_key = receiver_public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )#Using OAEP for added security, makes RSA probabilistic (randomised)
     #Encrypting the same message twice gives different ciphertexts

    #Return everything for transmission
    return {
        "ciphertext": ciphertext,
        "iv": iv,
        "encrypted_key": encrypted_key,
        "signature": signature
    }


def verify_and_decrypt(ciphertext, iv, encrypted_key, signature, receiver_private_path, sender_public_path):
    #Load keys
    receiver_private_key = load_rsa_private_key(receiver_private_path)
    sender_public_key = load_rsa_public_key(sender_public_path)

    #Verify signature BEFORE decryption
    #If even 1 bit of the file is changed during transit or on disk, it will be detected (Integrity)
    try:
        sender_public_key.verify(   
            signature,
            ciphertext,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verified = True
    except Exception as e:
        print(f"[!] Signature verification failed: {e}") #No decryption is attempted if signature fails
        return None, False  #Stop here if not verified
    
    # ^^ If this check succeeds, it proves:
    #The sender must have signed the ciphertext using their private key
    #Only the sender possesses this private key, so the signature proves authorship.
    #Therefore, the sender cannot deny having sent the file. (Non-repudiation)

    #Decrypt AES key using receiver's private key
    #Without access to the receiver's private key, nobody else can decrypt the AES key or file (Confidentiality)
    aes_key = receiver_private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    #Decrypt AES ciphertext
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    #Remove padding
    padding_len = padded_plaintext[-1]
    plaintext = padded_plaintext[:-padding_len] #Slicing

    return plaintext, verified