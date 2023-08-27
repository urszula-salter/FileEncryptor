import os.path

import os
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from tkinter import Button, Frame
from tkinter import font
from tkinter import PhotoImage, Label
from tkinter import Label
from tkinter import messagebox

KEY_FILE_PATH = "private_key.pem"


def save_private_key_to_file(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as f:
        f.write(pem)

def load_private_key_from_file(filename):
    with open(filename, 'rb') as f:
        pem = f.read()
    private_key = serialization.load_pem_private_key(
        pem,
        password=None,
        backend=default_backend()
    )
    return private_key

def generate_rsa_key_pair():
    if os.path.exists(KEY_FILE_PATH):
        private_key = load_private_key_from_file(KEY_FILE_PATH)
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        save_private_key_to_file(private_key, KEY_FILE_PATH)

    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_rsa(plaintext, public_key):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def generate_aes_key():
    return os.urandom(32)

def encrypt_aes(plaintext, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, encryptor.tag, ciphertext

def decrypt_aes(ciphertext, key, iv, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def encrypt_file(file_path):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    aes_key = generate_aes_key()
    nonce, tag, ciphertext = encrypt_aes(plaintext, aes_key)

    encrypted_aes_key = encrypt_rsa(aes_key, public_key)

    with open(file_path, 'wb') as f:
        f.write(encrypted_aes_key + nonce + tag + ciphertext)

    print(f"Encrypted file saved at: {file_path}")

def decrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted_aes_key = data[:256]
    nonce = data[256:268]
    tag = data[268:284]
    ciphertext = data[284:]

    aes_key = decrypt_rsa(encrypted_aes_key, private_key)
    plaintext = decrypt_aes(ciphertext, aes_key, nonce, tag)

    with open(file_path, 'wb') as f:
        f.write(plaintext)

    print(f"Decrypted file saved at: {file_path}")

def open_encrypt_file_dialog():
    Tk().withdraw()
    file_path = askopenfilename(title='Select a file to encrypt')
    if file_path:
        encrypt_file(file_path)

def open_decrypt_file_dialog():
    Tk().withdraw()
    file_path = askopenfilename(title='Select an encrypted file to decrypt')
    if file_path:
        decrypt_file(file_path)


def encrypt_rsa(plaintext, public_key):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def generate_aes_key():
    return os.urandom(32)

def encrypt_aes(plaintext, key):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, encryptor.tag, ciphertext

def decrypt_aes(ciphertext, key, iv, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def show_success_message(operation):
    messagebox.showinfo("Success", f"File {operation} successfully!")

def encrypt_file(file_path):
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    aes_key = generate_aes_key()
    nonce, tag, ciphertext = encrypt_aes(plaintext, aes_key)

    encrypted_aes_key = encrypt_rsa(aes_key, public_key)

    with open(file_path, 'wb') as f:
        f.write(encrypted_aes_key + nonce + tag + ciphertext)

    print(f"Encrypted file saved at: {file_path}")
    show_success_message("encrypted")

def decrypt_file(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted_aes_key = data[:256]
    nonce = data[256:268]
    tag = data[268:284]
    ciphertext = data[284:]

    aes_key = decrypt_rsa(encrypted_aes_key, private_key)
    plaintext = decrypt_aes(ciphertext, aes_key, nonce, tag)

    with open(file_path, 'wb') as f:
        f.write(plaintext)

    print(f"Decrypted file saved at: {file_path}")
    show_success_message("decrypted")

def open_encrypt_file_dialog(encrypt_button, decrypt_button):
    Tk().withdraw()
    file_path = askopenfilename(title='Select a file to encrypt')
    if file_path:
        encrypt_button.config(state="disabled")  # Disable the button during processing
        decrypt_button.config(state="disabled")  # Disable the button during processing
        encrypt_file(file_path)
        encrypt_button.config(state="normal")  # Enable the button after processing
        decrypt_button.config(state="normal")  # Enable the button after processing

def open_decrypt_file_dialog(encrypt_button, decrypt_button):
    Tk().withdraw()
    file_path = askopenfilename(title='Select an encrypted file to decrypt')
    if file_path:
        encrypt_button.config(state="disabled")  # Disable the button during processing
        decrypt_button.config(state="disabled")  # Disable the button during processing
        decrypt_file(file_path)
        encrypt_button.config(state="normal")  # Enable the button after processing
        decrypt_button.config(state="normal")  # Enable the button after processing


def main():
    window = Tk()
    window.title("CSCI400 Simple File Encryption Program")
    window.geometry("800x600")
    # Set custom window icon
    window.iconbitmap('icon.ico')

    # Load the background image
    bg_image = PhotoImage(file="Untitled.png")
    bg_label = Label(window, image=bg_image)
    bg_label.place(x=0, y=0, relwidth=1, relheight=1)

    # Set custom font
    custom_font = font.nametofont("TkDefaultFont")
    custom_font.actual()
    custom_font.config(size=14)
    window.option_add("*Font", custom_font)

    # Load the button images
    encrypt_button_image = PhotoImage(file="encButton.png")
    decrypt_button_image = PhotoImage(file="decButton1.png")

    # Adjust the image size using subsample or zoom
    encrypt_button_image = encrypt_button_image.subsample(2, 2)  # Reduce the size by a factor of 2
    decrypt_button_image = decrypt_button_image.subsample(2, 2)  # Reduce the size by a factor of 2

    # Create the buttons with text, images, and 3D effect
    encrypt_button = Button(window, text="Encrypt a file", image=encrypt_button_image, compound='top',
                            command=lambda: open_encrypt_file_dialog(encrypt_button, decrypt_button),
                            borderwidth=6, relief="raised", pady=10)
    decrypt_button = Button(window, text="Decrypt a file", image=decrypt_button_image, compound='top',
                            command=lambda: open_decrypt_file_dialog(encrypt_button, decrypt_button),
                            borderwidth=6, relief="raised", pady=10)


    # Set the button positions
    encrypt_button.place(x=210, y=250)
    decrypt_button.place(x=410, y=250)

    # Place the buttons on the window
    encrypt_button.place(x=180, y=180)  # Decrease the y value to move the button higher
    decrypt_button.place(x=405, y=180)  # Decrease the y value to move the button higher

    # Add a label with the desired text
    label_text = "CSCI 400 Project\nSimple File Encryptor"
    label = Label(window, text=label_text, bg="white", font=("Arial", 24), relief="raised", borderwidth=6)
    label.place(x=247, y=60)  # Adjust the x and y values to position the label as needed

    window.mainloop()

if __name__ == "__main__":
    private_key, public_key = generate_rsa_key_pair()
    main()