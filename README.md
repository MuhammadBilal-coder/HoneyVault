⭐ HoneyVault — Secure File Encryption & Management System

HoneyVault is a secure file protection system designed to safeguard sensitive data using modern cryptographic techniques.
It combines AES-256 encryption, key splitting, honey (decoy) files, and a time-lock mechanism within a Flask-based web application.

🚀 Key Features

🔐 AES-256 file encryption

🧩 Shamir’s Secret Sharing for encryption key splitting

🍯 Honey (fake) files for attacker detection

⏳ Time-lock security for controlled decryption

🌐 Flask web interface for file upload and management

📁 Secure encryption and decryption workflow

🧠 How the System Works

The user uploads a file through the web interface

The file is encrypted using AES-256

The encryption key is split into multiple parts using Shamir’s Secret Sharing

Key fragments can be stored separately (server, local machine, external storage)

The system generates honey files to detect unauthorized access

If a honey file is accessed, an alert with a timestamp is logged

A time-lock ensures the file can only be decrypted after a specified time

When all key parts and time conditions are satisfied, the file is successfully decrypted

⚡ 5-Second Summary

Upload → Encrypt → Split Key → Honey Files → Time-Lock → Decrypt

🛠️ Technologies Used

Python

Flask

HTML / Jinja Templates

AES Cryptography

Shamir’s Secret Sharing

Local Flask Server

📂 Project Structure
HoneyVault/
│── app/
│   ├── main.py
│   └── templates/
│       ├── dashboard.html
│       ├── upload.html
│       ├── encrypt_result.html
│       └── decrypt.html
│
│── core/
│   ├── aes_encrypt.py
│   ├── aes_decrypt.py
│   ├── combine_key.py
│   ├── split_key.py
│   ├── timelock.py
│   ├── honey_files.py
│   └── db_functions.py
│
│── uploads/
│── run.py
│── requirements.txt

▶️ How to Run the Project
pip install -r requirements.txt
python run.py


Open in browser:

http://127.0.0.1:5000

🎯 Project Purpose

This project was developed for educational and academic purposes to demonstrate:

Secure file encryption techniques

Key management using secret sharing

Practical application of cybersecurity concepts

A portfolio-ready Flask web application

👤 Author

Muhammad Bilal
Computer Science Student
Aspiring Web / Software Development Intern
