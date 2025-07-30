import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox
import requests
import os
import base64

from crypto import encrypt_and_sign, verify_and_decrypt

#Set paths to RSA key files
SENDER_PRIVATE_KEY = "certs/sender_private.pem"
RECEIVER_PUBLIC_KEY = "certs/receiver_public.pem"

RECEIVER_PRIVATE_KEY = "certs/receiver_private.pem"
SENDER_PUBLIC_KEY = "certs/sender_public.pem"

server_ip = "192.168.19.156" #Update server IP to VM IP

#Upload logic
def upload_file():
    filepath = filedialog.askopenfilename()
    if not filepath:
        return

    try:
        print(f"[+] Encrypting and signing {filepath}")
        result = encrypt_and_sign(filepath, SENDER_PRIVATE_KEY, RECEIVER_PUBLIC_KEY)

        files = {
            "ciphertext": ("file.bin", result["ciphertext"]),
            "encrypted_key": ("key.bin", result["encrypted_key"]),
            "iv": ("iv.bin", result["iv"]),
            "signature": ("sig.bin", result["signature"])
        }

        data = {
            "filename": os.path.basename(filepath)
        }

        #Following flask format:
        #files= is for uploading binary content with an associated file-like structure.
        #data= is for sending additional form values or metadata, like a filename string.
        upload_url = f"http://{server_ip}:5000/upload"
        response = requests.post(upload_url, files=files, data=data)
        
        try:
            server_msg = response.json().get("message") or response.json().get("error")
        except:
            server_msg = response.text  #fallback if not JSON

        if response.status_code == 200:
            messagebox.showinfo("Success", f"Success:\n{server_msg}")
        else:
            messagebox.showerror("Upload Failed", f"Server rejected upload:\n{server_msg}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred:\n{str(e)}")

#Download logic
def download_and_verify():
    try:
        #Fetch available files from server
        file_list_url = f"http://{server_ip}:5000/list_files"
        response = requests.get(file_list_url)
        if response.status_code != 200:
            messagebox.showerror("Error", f"Could not fetch file list: {response.text}")
            return

        file_list = response.json()
        if not file_list:
            messagebox.showinfo("No Files", "No files available on the server.")
            return

        #Ask user to select a file
        filename = ask_file_selection(file_list)

        download_url = f"http://{server_ip}:5000/download/{filename}"
        response = requests.get(download_url)
        if response.status_code != 200:
            messagebox.showerror("Error", f"Download failed: {response.text}")
            return
        
        files = response.json()
        for k in ['cipher', 'iv', 'key', 'sig']:
            if k not in files:
                messagebox.showerror("Error", f"Missing {k} component in server response")
                return

        #Decode base64 fields
        decoded_parts = {
            k: base64.b64decode(files[k]) for k in files
        }

        #Call decryption & verification function
        plaintext, verified = verify_and_decrypt(
            decoded_parts['cipher'],
            decoded_parts['iv'],
            decoded_parts['key'],
            decoded_parts['sig'],
            RECEIVER_PRIVATE_KEY,  #For decryption
            SENDER_PUBLIC_KEY      #For signature verification
        )

        if verified:
            save_path = filedialog.asksaveasfilename(defaultextension=".txt", title="Save decrypted file")
            if save_path:
                with open(save_path, "wb") as f:
                    f.write(plaintext)
                messagebox.showinfo("Success", f"File decrypted and verified successfully.\nSaved to:\n{save_path}")
        else:
            messagebox.showerror("Verification Failed", "Signature verification failed.\nFile integrity compromised.")
    
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred:\n{str(e)}")

#Dropdown
def ask_file_selection(file_list):
    popup = tk.Toplevel()
    popup.title("Select File to Download")

    tk.Label(popup, text="Select a file to download:", font=("Segoe UI", 11)).pack(padx=15, pady=10)

    selected_file = tk.StringVar()
    combobox = ttk.Combobox(popup, textvariable=selected_file, values=file_list, state="readonly", width=40)
    combobox.current(0)
    combobox.pack(pady=10)

    def confirm():
        popup.destroy()

    ttk.Button(popup, text="Confirm", command=confirm).pack(pady=10)
    popup.grab_set()
    popup.wait_window()
    return selected_file.get()

#Tkinter GUI
root = tk.Tk()
root.title("SafeDrop - Secure File Uploader")
root.geometry("320x220")
root.resizable(False, False)

frame = tk.LabelFrame(root, text="Secure File Actions", padx=15, pady=15, font=("Segoe UI", 11))
frame.pack(padx=20, pady=20, fill="both", expand=True)

upload_btn = ttk.Button(frame, text="Select & Send File Securely", command=upload_file)
upload_btn.pack(pady=8, fill="x")

download_btn = ttk.Button(frame, text="Download & Verify File", command=download_and_verify)
download_btn.pack(pady=8, fill="x")

root.mainloop()


