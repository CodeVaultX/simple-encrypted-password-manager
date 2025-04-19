from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QLineEdit, QLabel, 
                           QTableWidget, QTableWidgetItem, QMessageBox, QMenu,
                           QInputDialog, QDialog, QFileDialog)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QAction
from cryptography.fernet import Fernet
import json
import os
import sys
import pyperclip

class MasterPasswordDialog(QDialog):
    def __init__(self, new_password=False):
        super().__init__()
        self.setWindowTitle("Master Password" if not new_password else "Create New Master Password")
        self.setFixedWidth(300)
        layout = QVBoxLayout()

        # Password field
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter Master Password")
        layout.addWidget(self.password_input)

        # If creating new password, ask for confirmation
        if new_password:
            self.password_confirm_input = QLineEdit()
            self.password_confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_confirm_input.setPlaceholderText("Confirm Master Password")
            layout.addWidget(self.password_confirm_input)

        # Login button
        self.login_btn = QPushButton("OK")
        self.login_btn.clicked.connect(self.accept)
        layout.addWidget(self.login_btn)

        self.setLayout(layout)

    def get_password(self):
        return self.password_input.text()

    def get_password_confirm(self):
        if hasattr(self, 'password_confirm_input'):
            return self.password_confirm_input.text()
        return None

class PasswordManagerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        
        # Master password check
        if not self.master_password_check():
            sys.exit()
            
        self.setWindowTitle("Password Manager")
        self.setMinimumSize(600, 400)
        
        # Initialize password manager logic
        self.key_file = "key.key"
        self.passwords_file = "passwords.enc"
        self.key = self._get_or_create_key()
        self.fernet = Fernet(self.key)
        self.passwords = self._load_passwords()
        
        # Create main widget and layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        
        # Create search field
        self.create_search_field()
        
        # Create input fields
        self.create_input_fields()
        
        # Create table
        self.create_table()
        
        # Update table
        self.update_table()

    def create_search_field(self):
        search_layout = QHBoxLayout()
        
        # Search box
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by site name or username...")
        self.search_input.textChanged.connect(self.search)
        
        # Clear button
        self.clear_btn = QPushButton("Clear Search")
        self.clear_btn.clicked.connect(self.clear_search)
        
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.clear_btn)
        
        self.layout.addLayout(search_layout)

    def search(self, search_text):
        search_text = search_text.lower()
        self.table.setRowCount(0)
        row = 0
        
        # Collect search results in a temporary list and sort
        matching_records = []
        for site, details in self.passwords.items():
            if (search_text in site.lower() or 
                search_text in details["username"].lower()):
                matching_records.append((site, details))
        
        # Sort matching records alphabetically
        sorted_records = sorted(matching_records, key=lambda x: x[0].lower())
        
        # Add sorted results to the table
        for site, details in sorted_records:
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(site))
            self.table.setItem(row, 1, QTableWidgetItem(details["username"]))
            self.table.setItem(row, 2, QTableWidgetItem("********"))
            row += 1

    def clear_search(self):
        self.search_input.clear()
        self.update_table()

    def master_password_check(self):
        # Master password file check
        self.master_password_file = "master_password.key"
        
        if not os.path.exists(self.master_password_file):
            # First use - create new password
            while True:
                dialog = MasterPasswordDialog(new_password=True)
                if dialog.exec() == QDialog.DialogCode.Accepted:
                    password = dialog.get_password()
                    password_confirm = dialog.get_password_confirm()
                    
                    if password == password_confirm and password.strip():
                        # Hash password and save
                        password_hash = Fernet.generate_key()
                        f = Fernet(password_hash)
                        encrypted_password = f.encrypt(password.encode())
                        
                        with open(self.master_password_file, 'wb') as file:
                            file.write(password_hash + b'\n' + encrypted_password)
                        return True
                    else:
                        QMessageBox.warning(self, "Error", "Passwords don't match or are empty!")
                else:
                    return False
        else:
            # Existing password check
            try:
                with open(self.master_password_file, 'rb') as file:
                    password_hash = file.readline().strip()
                    encrypted_password = file.readline().strip()
                
                for _ in range(3):  # 3 attempts
                    dialog = MasterPasswordDialog()
                    if dialog.exec() == QDialog.DialogCode.Accepted:
                        password = dialog.get_password()
                        f = Fernet(password_hash)
                        try:
                            decrypted_password = f.decrypt(encrypted_password).decode()
                            if password == decrypted_password:
                                return True
                            else:
                                QMessageBox.warning(self, "Error", "Wrong password!")
                        except:
                            QMessageBox.warning(self, "Error", "Wrong password!")
                    else:
                        return False
                
                QMessageBox.critical(self, "Error", "Too many failed attempts!")
                return False
                
            except Exception as e:
                QMessageBox.critical(self, "Error", "Master password file is corrupted!")
                return False

    def _get_or_create_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            return key

    def _load_passwords(self):
        if os.path.exists(self.passwords_file):
            with open(self.passwords_file, "rb") as f:
                encrypted_data = f.read()
                try:
                    decrypted_data = self.fernet.decrypt(encrypted_data)
                    return json.loads(decrypted_data)
                except:
                    return {}
        return {}

    def _save_passwords(self):
        encrypted_data = self.fernet.encrypt(json.dumps(self.passwords).encode())
        with open(self.passwords_file, "wb") as f:
            f.write(encrypted_data)

    def create_input_fields(self):
        input_layout = QHBoxLayout()
        
        self.site_input = QLineEdit()
        self.site_input.setPlaceholderText("Site Name")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        input_layout.addWidget(self.site_input)
        input_layout.addWidget(self.username_input)
        input_layout.addWidget(self.password_input)
        
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.add_password)
        input_layout.addWidget(self.save_btn)
        
        # Change master password button
        self.change_password_btn = QPushButton("Change Master Password")
        self.change_password_btn.clicked.connect(self.change_master_password)
        input_layout.addWidget(self.change_password_btn)

        # Save to TXT button
        self.save_txt_btn = QPushButton("Save to TXT")
        self.save_txt_btn.clicked.connect(self.save_to_txt)
        input_layout.addWidget(self.save_txt_btn)

        # Load from TXT button
        self.load_txt_btn = QPushButton("Load from TXT")
        self.load_txt_btn.clicked.connect(self.load_from_txt)
        input_layout.addWidget(self.load_txt_btn)
        
        self.layout.addLayout(input_layout)

    def create_table(self):
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Site", "Username", "Password"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.right_click_menu)
        self.layout.addWidget(self.table)

    def change_master_password(self):
        dialog = MasterPasswordDialog(new_password=True)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            password = dialog.get_password()
            password_confirm = dialog.get_password_confirm()
            
            if password == password_confirm and password.strip():
                password_hash = Fernet.generate_key()
                f = Fernet(password_hash)
                encrypted_password = f.encrypt(password.encode())
                
                with open(self.master_password_file, 'wb') as file:
                    file.write(password_hash + b'\n' + encrypted_password)
                
                QMessageBox.information(self, "Success", "Master password changed successfully!")
            else:
                QMessageBox.warning(self, "Error", "Passwords don't match or are empty!")

    def add_password(self):
        site = self.site_input.text()
        username = self.username_input.text()
        password = self.password_input.text()
        
        if not all([site, username, password]):
            QMessageBox.warning(self, "Error", "Please fill in all fields!")
            return
        
        self.passwords[site] = {
            "username": username,
            "password": password
        }
        self._save_passwords()
        
        # Clear form
        self.site_input.clear()
        self.username_input.clear()
        self.password_input.clear()
        
        # Update table
        self.update_table()
        QMessageBox.information(self, "Success", "Password saved successfully!")

    def update_table(self):
        # If there's text in the search box, use search
        if hasattr(self, 'search_input') and self.search_input.text():
            self.search(self.search_input.text())
            return
            
        # Otherwise do normal update
        self.table.setRowCount(0)
        
        # Sort sites alphabetically
        sorted_sites = sorted(self.passwords.items(), key=lambda x: x[0].lower())
        
        for row, (site, details) in enumerate(sorted_sites):
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(site))
            self.table.setItem(row, 1, QTableWidgetItem(details["username"]))
            self.table.setItem(row, 2, QTableWidgetItem("********"))

    def right_click_menu(self, position):
        menu = QMenu()
        row = self.table.rowAt(position.y())
        col = self.table.columnAt(position.x())
        
        if row >= 0 and col >= 0:
            # Copy option
            copy_action = QAction("Copy", self)
            copy_action.triggered.connect(lambda: self.copy_data(row, col))
            menu.addAction(copy_action)
            
            # Edit option
            edit_action = QAction("Edit", self)
            edit_action.triggered.connect(lambda: self.edit_data(row, col))
            menu.addAction(edit_action)
            
            # Show password option (only for password column)
            if col == 2:
                show_action = QAction("Show Password", self)
                show_action.triggered.connect(lambda: self.show_password(row))
                menu.addAction(show_action)
            
            # Delete row option
            delete_action = QAction("Delete", self)
            delete_action.triggered.connect(lambda: self.delete_record(row))
            menu.addAction(delete_action)
            
            menu.exec(self.table.viewport().mapToGlobal(position))

    def copy_data(self, row, col):
        site = self.table.item(row, 0).text()
        if col == 0:
            pyperclip.copy(site)
        elif col == 1:
            pyperclip.copy(self.passwords[site]["username"])
        elif col == 2:
            pyperclip.copy(self.passwords[site]["password"])
        QMessageBox.information(self, "Success", "Data copied to clipboard!")

    def edit_data(self, row, col):
        site = self.table.item(row, 0).text()
        old_value = ""
        
        if col == 0:
            old_value = site
            new_value, ok = self._input_dialog("Edit Site Name", "New site name:", old_value)
            if ok and new_value:
                self.passwords[new_value] = self.passwords.pop(site)
        elif col == 1:
            old_value = self.passwords[site]["username"]
            new_value, ok = self._input_dialog("Edit Username", "New username:", old_value)
            if ok and new_value:
                self.passwords[site]["username"] = new_value
        elif col == 2:
            old_value = self.passwords[site]["password"]
            new_value, ok = self._input_dialog("Edit Password", "New password:", old_value)
            if ok and new_value:
                self.passwords[site]["password"] = new_value
        
        self._save_passwords()
        self.update_table()

    def _input_dialog(self, title, message, default):
        value, ok = QInputDialog.getText(self, title, message, QLineEdit.EchoMode.Normal, default)
        return value, ok

    def delete_record(self, row):
        site = self.table.item(row, 0).text()
        response = QMessageBox.question(self, "Delete Confirmation", 
                                   f"Are you sure you want to delete the record for {site}?",
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if response == QMessageBox.StandardButton.Yes:
            del self.passwords[site]
            self._save_passwords()
            self.update_table()
            QMessageBox.information(self, "Success", "Record deleted successfully!")

    def show_password(self, row):
        site = self.table.item(row, 0).text()
        password = self.passwords[site]["password"]
        QMessageBox.information(self, "Password", f"Password: {password}")

    def save_to_txt(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Save TXT File", "", "Text Files (*.txt)")
        if file_name:
            try:
                with open(file_name, 'w', encoding='utf-8') as f:
                    for site, details in self.passwords.items():
                        f.write(f"{site},{details['username']},{details['password']}\n")
                QMessageBox.information(self, "Success", "Passwords saved to TXT file!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error saving file: {str(e)}")

    def load_from_txt(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Select TXT File", "", "Text Files (*.txt)")
        if file_name:
            try:
                with open(file_name, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:  # Skip empty lines
                            continue
                        try:
                            site, username, password = line.split(',')
                            self.passwords[site] = {
                                'username': username,
                                'password': password
                            }
                        except ValueError:
                            QMessageBox.warning(self, "Warning", f"Invalid line format: {line}")
                            continue
                
                self._save_passwords()
                self.update_table()
                QMessageBox.information(self, "Success", "Passwords loaded from TXT file!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error loading file: {str(e)}")

def main():
    app = QApplication(sys.argv)
    window = PasswordManagerGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()