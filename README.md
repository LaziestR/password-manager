# 🔐 Password Manager – Group 7 (CSC154)
A CLI-based password manager with user authentication and vault storage.
A simple and secure command-line password manager built in Python. It allows multiple users to manage login credentials for various services. Passwords are encrypted using symmetric key cryptography and stored securely on the local machine.

---

## 📌 Features

- ✅ Account creation with hashed passwords using bcrypt
- ✅ User login with secure password verification
- ✅ Encrypted storage of service credentials using `cryptography.fernet`
- ✅ Secure CLI input using `getpass` (passwords not shown when typed)
- ✅ Add, view, and delete credentials in a user-friendly interface
- ✅ Data saved locally in a JSON vault unique to each user

---

## 🚀 How to Run

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
```

### 2. Install dependencies
```bash 
pip install bcrypt cryptography
```

### 2.1 Optionally install GUI interface 
```bash 
pip install PyQt6 cryptography bcrypt
```

### 3. Run the program
```bash
python PassManager.py
```

