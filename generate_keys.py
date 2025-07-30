#This file was coded by Lin Tze Jay Gregory

#Only need to run the key generation once, so treat this script as a setup tool
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

#Generates an RSA private key, and Extracts the public key from it
def generate_rsa_keys(name):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048) #2048-bit RSA private key

    #Save Private Key to PEM File
    with open(f"certs/{name}_private.pem", "wb") as file_handle: #wb(write, binary)
        file_handle.write(
            private_key.private_bytes( #Returns the key serialized as bytes
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption() #The private key is saved unencrypted (no password)
            )
        )
    
    #Save Public Key to PEM File
    with open(f"certs/{name}_public.pem", "wb") as file_handle:
        file_handle.write(  
            private_key.public_key().public_bytes( #The RSAPublicKey associated with this private key
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo 
            )
        )
    
#Run once to generate keys
if __name__ == "__main__": #Run only if being run directly, not imported by another file
    os.makedirs("certs", exist_ok=True)
    generate_rsa_keys("sender")
    generate_rsa_keys("receiver")
    print("RSA key pairs generated in certs/ (sender & receiver)")

#certs/
#├── sender_private.pem   (Sender’s private key — signing)
#├── sender_public.pem    (Sender’s public key — verification)
#├── receiver_private.pem (Receiver’s private key — decrypt AES key)
#├── receiver_public.pem  (Receiver’s public key — encrypt AES key)