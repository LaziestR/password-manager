import sys
import os
import json
import bcrypt
import base64
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                            QStackedWidget, QTableWidget, QTableWidgetItem,
                            QMessageBox, QInputDialog, QHeaderView, QDialog,
                            QDialogButtonBox, QFormLayout)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QPalette, QColor
from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self):
        self.VAULT_DIR = "vault"
        self.USER_FILE = "users.json"
        self.ensure_vault_dir()
    
    def ensure_vault_dir(self):
        if not os.path.exists(self.VAULT_DIR):
            os.makedirs(self.VAULT_DIR)
    
    def get_vault_path(self, username):
        return os.path.join(self.VAULT_DIR, f"{username}.json")
    
    def load_vault(self, username):
        path = self.get_vault_path(username)
        if not os.path.exists(path):
            return []
        with open(path, "r") as f:
            return json.load(f)
    
    def save_vault(self, username, entries):
        path = self.get_vault_path(username)
        with open(path, "w") as f:
            json.dump(entries, f, indent=4)
    
    def load_users(self):
        if not os.path.exists(self.USER_FILE):
            return []
        with open(self.USER_FILE, "r") as f:
            return json.load(f)
    
    def save_users(self, users):
        with open(self.USER_FILE, "w") as f:
            json.dump(users, f, indent=4)
    
    def hash_password(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    def verify_password(self, password, hashed):
        return bcrypt.checkpw(password.encode(), hashed.encode())
    
    def create_account(self, username, password):
        users = self.load_users()
        
        if any(u["username"] == username for u in users):
            return False, "Username already exists."
        
        hashed = self.hash_password(password)
        key = Fernet.generate_key().decode()
        users.append({"username": username, "hashed_password": hashed, "vault_key": key})
        self.save_users(users)
        return True, "Account created successfully!"
    
    def login(self, username, password):
        users = self.load_users()
        
        for user in users:
            if user["username"] == username:
                if self.verify_password(password, user["hashed_password"]):
                    return True, user
                else:
                    return False, "Incorrect password."
        return False, "User not found."
    
    def add_vault_entry(self, username, vault_key, service, entry_username, password):
        f = Fernet(vault_key.encode())
        encrypted_pwd = f.encrypt(password.encode()).decode()
        
        entries = self.load_vault(username)
        entries.append({
            "service": service, 
            "username": entry_username, 
            "password": encrypted_pwd
        })
        self.save_vault(username, entries)
        return True
    
    def decrypt_password(self, vault_key, encrypted_password):
        try:
            f = Fernet(vault_key.encode())
            return f.decrypt(encrypted_password.encode()).decode()
        except Exception as e:
            return None
    
    def delete_vault_entry(self, username, index):
        entries = self.load_vault(username)
        if 0 <= index < len(entries):
            removed = entries.pop(index)
            self.save_vault(username, entries)
            return True, f"Deleted entry for {removed['service']}"
        return False, "Invalid entry index"

class AddEntryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Add New Entry")
        self.setModal(True)
        self.setFixedSize(400, 200)
        
        layout = QFormLayout()
        
        self.service_input = QLineEdit()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        layout.addRow("Service:", self.service_input)
        layout.addRow("Username:", self.username_input)
        layout.addRow("Password:", self.password_input)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | 
                                 QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)
        
        self.setLayout(layout)
    
    def get_data(self):
        return (self.service_input.text(), 
                self.username_input.text(), 
                self.password_input.text())

class LoginWindow(QWidget):
    def __init__(self, password_manager, main_window):
        super().__init__()
        self.password_manager = password_manager
        self.main_window = main_window
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(50, 50, 50, 50)
        
        # Title
        title = QLabel("Password Manager")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 24, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Login section
        login_layout = QVBoxLayout()
        login_layout.setSpacing(10)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.username_input.setMinimumHeight(40)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(40)
        self.password_input.returnPressed.connect(self.login)
        
        login_btn = QPushButton("Login")
        login_btn.setMinimumHeight(40)
        login_btn.clicked.connect(self.login)
        
        create_btn = QPushButton("Create Account")
        create_btn.setMinimumHeight(40)
        create_btn.clicked.connect(self.show_create_account)
        
        login_layout.addWidget(QLabel("Username:"))
        login_layout.addWidget(self.username_input)
        login_layout.addWidget(QLabel("Password:"))
        login_layout.addWidget(self.password_input)
        login_layout.addWidget(login_btn)
        login_layout.addWidget(create_btn)
        
        layout.addLayout(login_layout)
        layout.addStretch()
        self.setLayout(layout)
    
    def login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Warning", "Please enter both username and password.")
            return
        
        success, result = self.password_manager.login(username, password)
        
        if success:
            self.main_window.user_data = result
            self.main_window.switch_to_vault()
            self.username_input.clear()
            self.password_input.clear()
        else:
            QMessageBox.warning(self, "Login Failed", result)
    
    def show_create_account(self):
        self.main_window.switch_to_create_account()

class CreateAccountWindow(QWidget):
    def __init__(self, password_manager, main_window):
        super().__init__()
        self.password_manager = password_manager
        self.main_window = main_window
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(50, 50, 50, 50)
        
        # Title
        title = QLabel("Create New Account")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        layout.addWidget(title)
        
        # Create account section
        create_layout = QVBoxLayout()
        create_layout.setSpacing(10)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Choose a username")
        self.username_input.setMinimumHeight(40)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Create a password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setMinimumHeight(40)
        
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText("Confirm password")
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_input.setMinimumHeight(40)
        self.confirm_password_input.returnPressed.connect(self.create_account)
        
        create_btn = QPushButton("Create Account")
        create_btn.setMinimumHeight(40)
        create_btn.clicked.connect(self.create_account)
        
        back_btn = QPushButton("Back to Login")
        back_btn.setMinimumHeight(40)
        back_btn.clicked.connect(self.back_to_login)
        
        create_layout.addWidget(QLabel("Username:"))
        create_layout.addWidget(self.username_input)
        create_layout.addWidget(QLabel("Password:"))
        create_layout.addWidget(self.password_input)
        create_layout.addWidget(QLabel("Confirm Password:"))
        create_layout.addWidget(self.confirm_password_input)
        create_layout.addWidget(create_btn)
        create_layout.addWidget(back_btn)
        
        layout.addLayout(create_layout)
        layout.addStretch()
        self.setLayout(layout)
    
    def create_account(self):
        username = self.username_input.text().strip()
        password = self.password_input.text()
        confirm_password = self.confirm_password_input.text()
        
        if not username or not password:
            QMessageBox.warning(self, "Warning", "Please fill in all fields.")
            return
        
        if password != confirm_password:
            QMessageBox.warning(self, "Warning", "Passwords do not match.")
            return
        
        if len(password) < 6:
            QMessageBox.warning(self, "Warning", "Password must be at least 6 characters long.")
            return
        
        success, message = self.password_manager.create_account(username, password)
        
        if success:
            QMessageBox.information(self, "Success", message)
            self.clear_fields()
            self.main_window.switch_to_login()
        else:
            QMessageBox.warning(self, "Error", message)
    
    def clear_fields(self):
        self.username_input.clear()
        self.password_input.clear()
        self.confirm_password_input.clear()
    
    def back_to_login(self):
        self.clear_fields()
        self.main_window.switch_to_login()

class VaultWindow(QWidget):
    def __init__(self, password_manager, main_window):
        super().__init__()
        self.password_manager = password_manager
        self.main_window = main_window
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        header_layout = QHBoxLayout()
        self.title = QLabel()  # Will be set when user logs in
        self.title.setFont(QFont("Arial", 18, QFont.Weight.Bold))
        
        logout_btn = QPushButton("Logout")
        logout_btn.setMaximumWidth(100)
        logout_btn.clicked.connect(self.logout)
        
        header_layout.addWidget(self.title)
        header_layout.addStretch()
        header_layout.addWidget(logout_btn)
        layout.addLayout(header_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        add_btn = QPushButton("Add Entry")
        add_btn.clicked.connect(self.add_entry)
        
        delete_btn = QPushButton("Delete Entry")
        delete_btn.clicked.connect(self.delete_entry)
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.load_entries)
        
        button_layout.addWidget(add_btn)
        button_layout.addWidget(delete_btn)
        button_layout.addWidget(refresh_btn)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Service", "Username", "Password", "Action"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        
        layout.addWidget(self.table)
        self.setLayout(layout)
    
    def set_user(self, user_data):
        self.user_data = user_data
        self.title.setText(f"{user_data['username']}'s Vault")
        self.load_entries()
    
    def load_entries(self):
        entries = self.password_manager.load_vault(self.user_data['username'])
        self.table.setRowCount(len(entries))
        
        for i, entry in enumerate(entries):
            self.table.setItem(i, 0, QTableWidgetItem(entry['service']))
            self.table.setItem(i, 1, QTableWidgetItem(entry['username']))
            self.table.setItem(i, 2, QTableWidgetItem("••••••••"))
            
            # View password button
            view_btn = QPushButton("View")
            view_btn.clicked.connect(lambda checked, row=i: self.view_password(row))
            self.table.setCellWidget(i, 3, view_btn)
    
    def add_entry(self):
        dialog = AddEntryDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            service, username, password = dialog.get_data()
            
            if not service or not username or not password:
                QMessageBox.warning(self, "Warning", "Please fill in all fields.")
                return
            
            success = self.password_manager.add_vault_entry(
                self.user_data['username'],
                self.user_data['vault_key'],
                service, username, password
            )
            
            if success:
                QMessageBox.information(self, "Success", "Entry added successfully!")
                self.load_entries()
            else:
                QMessageBox.warning(self, "Error", "Failed to add entry.")
    
    def view_password(self, row):
        # Ask for master password
        password, ok = QInputDialog.getText(
            self, "Master Password", 
            "Enter your master password to view the password:",
            QLineEdit.EchoMode.Password
        )
        
        if not ok or not password:
            return
        
        # Verify master password
        if not self.password_manager.verify_password(password, self.user_data['hashed_password']):
            QMessageBox.warning(self, "Error", "Incorrect master password.")
            return
        
        # Get encrypted password
        entries = self.password_manager.load_vault(self.user_data['username'])
        if row < len(entries):
            encrypted_password = entries[row]['password']
            decrypted_password = self.password_manager.decrypt_password(
                self.user_data['vault_key'], encrypted_password
            )
            
            if decrypted_password:
                QMessageBox.information(
                    self, "Password", 
                    f"Password for {entries[row]['service']}:\n{decrypted_password}"
                )
            else:
                QMessageBox.warning(self, "Error", "Failed to decrypt password.")
    
    def delete_entry(self):
        current_row = self.table.currentRow()
        if current_row < 0:
            QMessageBox.warning(self, "Warning", "Please select an entry to delete.")
            return
        
        entries = self.password_manager.load_vault(self.user_data['username'])
        service_name = entries[current_row]['service']
        
        reply = QMessageBox.question(
            self, "Confirm Delete",
            f"Are you sure you want to delete the entry for '{service_name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            success, message = self.password_manager.delete_vault_entry(
                self.user_data['username'], current_row
            )
            
            if success:
                QMessageBox.information(self, "Success", message)
                self.load_entries()
            else:
                QMessageBox.warning(self, "Error", message)
    
    def logout(self):
        reply = QMessageBox.question(
            self, "Logout",
            "Are you sure you want to logout?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.main_window.switch_to_login()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.password_manager = PasswordManager()
        self.user_data = None
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 800, 600)
        
        # Create stacked widget to switch between windows
        self.stacked_widget = QStackedWidget()
        self.setCentralWidget(self.stacked_widget)
        
        # Create windows
        self.login_window = LoginWindow(self.password_manager, self)
        self.create_account_window = CreateAccountWindow(self.password_manager, self)
        self.vault_window = VaultWindow(self.password_manager, self)
        
        # Add windows to stack
        self.stacked_widget.addWidget(self.login_window)      # Index 0
        self.stacked_widget.addWidget(self.create_account_window)  # Index 1
        self.stacked_widget.addWidget(self.vault_window)      # Index 2
        
        # Start with login window
        self.stacked_widget.setCurrentIndex(0)
    
    def switch_to_login(self):
        self.stacked_widget.setCurrentIndex(0)
    
    def switch_to_create_account(self):
        self.stacked_widget.setCurrentIndex(1)
    
    def switch_to_vault(self):
        self.vault_window.set_user(self.user_data)
        self.stacked_widget.setCurrentIndex(2)

def main():
    app = QApplication(sys.argv)
    
    # Set application style
    app.setStyle('Fusion')
    
    # Create and show main window
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()