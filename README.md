# 🔐 CipherVault

CipherVault is a secure command-line password vault written in Python. It allows users to store, retrieve, list, and delete credentials encrypted with a single master password using modern cryptographic best practices.

## ✨ Features
- Encrypted password storage using Fernet symmetric encryption
- Strong key derivation with PBKDF2 (SHA-256)
- Cryptographically secure random salt
- Tamper detection and safe failure on incorrect passwords
- Simple and intuitive CLI interface
- No plaintext secrets stored on disk
- Cross-platform (Windows, macOS, Linux)
  
## 🔐 Security Design
- The master password is never stored
- Encryption keys are derived using PBKDF2 with 200,000 iterations
- All vault data is encrypted at rest and authenticated to detect tampering
- Password input is hidden using secure terminal prompts
  
## 🛠️ Requirements
- Python 3.9+
- `cryptography` library

Install dependencies:
```bash
pip install cryptography
```
## 🚀 Usage
```bash
Create a new vault
python CipherVault.py init

Add an entry
python CipherVault.py add -n github

Add an entry with username and password
python CipherVault.py add -n hotmail -u you@hotmail.com -p MySecret

List all entries
python CipherVault.py list

Retrieve an entry
python CipherVault.py get -n gmail

Delete an entry
python CipherVault.py delete -n gmail
```
