# 🛡️ SecureDoc: Encrypted Sharing & Verification System
> A robust platform for confidential document exchange using RSA encryption and DSA digital signatures.

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)
![SQLite](https://img.shields.io/badge/sqlite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white)
![Cryptography](https://img.shields.io/badge/Security-RSA%20%26%20DSA-red?style=for-the-badge)

---

### 🌟 Project Overview
SecureDoc addresses the critical need for authenticity in digital document sharing. Unlike standard cloud storage, every document in this system is cryptographically signed and encrypted, ensuring that only the intended recipient can access it and verify its integrity.



### ✨ Core Security Features

* **Asymmetric Encryption (RSA-2048):** Documents are encrypted using the recipient's public key, ensuring true end-to-end privacy.
* **Digital Signatures (DSA):** Every upload is signed with the sender's private key. Recipients use the sender's public key to verify that the file hasn't been tampered with.
* **Secure Authentication:** Passwords are never stored in plain text; they are hashed using **PBKDF2-HMAC-SHA256**.
* **AJAX-Driven UI:** Dynamic interactions (Upload/Share/Verify) without page reloads for a modern user experience.
* **Integrity Checks:** 100% detection rate for tampered or altered files during the verification process.

---

### 🛠️ Technical Stack

* **Backend:** Flask (Python)
* **Frontend:** HTML5, CSS3 (Flexbox/Animations), Vanilla JavaScript (Fetch API/AJAX)
* **Database:** SQLite3
* **Security Library:** `cryptography` (hazmat primitives)
* **Hashing:** Werkzeug Security

---

### 📂 System Architecture

1. **Client:** Dynamic frontend sends asynchronous requests via AJAX.
2. **Server:** Flask handles routing, session management, and cryptographic heavy lifting.
3. **Storage:** Metadata and keys are stored in SQLite; encrypted files are managed in a secure file-system structure.

---

### 🚀 Getting Started

#### 1. Installation
```bash
# Clone the repository
git clone [https://github.com/Alisha418/SecureDoc-Flask.git](https://github.com/Alisha418/SecureDoc-Flask.git)
cd Digital_Signature_System

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install flask cryptography

2. Running the App
#Bash
python app.py

🛡️ Threat Model Mitigations
Threat,Mitigation Strategy
Eavesdropping,RSA Asymmetric Encryption
File Tampering,DSA Digital Signatures (SHA-256)
Weak Passwords,PBKDF2 Hashing with Salts
Unauthorized Access,Strict Flask Session Management
