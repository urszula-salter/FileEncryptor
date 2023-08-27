Simple File Encryption Program

Introduction

This is a simple file encryption program written in Python. It makes use of the cryptography library for encryption and decryption. It features a graphical user interface (GUI) built with Tkinter, allowing you to easily encrypt and decrypt files. The program uses both RSA and AES algorithms for secure file encryption and decryption.

Requirements

    Python 3.x
    cryptography library
    Tkinter (usually comes with Python)

You can install the cryptography library using pip:
pip install cryptography

Usage

    Run the program by executing the Python file.
    A window with an Encrypt and Decrypt button will appear.
    To encrypt a file, click the 'Encrypt a file' button and choose the file you wish to encrypt.
    To decrypt a file, click the 'Decrypt a file' button and choose the file you wish to decrypt.

RSA Key Pair

    An RSA key pair is automatically generated upon the first run.
    The private key is saved to "private_key.pem".

Features

    RSA (2048-bit) encryption for securing the AES key
    AES-GCM encryption for file data
    User-friendly GUI
    Private key stored securely in a PEM file

Functions

    generate_rsa_key_pair: Generates an RSA key pair.
    encrypt_rsa: Encrypts plaintext using RSA.
    decrypt_rsa: Decrypts ciphertext using RSA.
    generate_aes_key: Generates a random AES key.
    encrypt_aes: Encrypts plaintext using AES.
    decrypt_aes: Decrypts ciphertext using AES.
    encrypt_file: Encrypts a selected file.
    decrypt_file: Decrypts a selected file.

Limitations

    This program is intended for educational purposes and not recommended for use in a production environment.
