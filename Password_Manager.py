from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLineEdit, QLabel, QTableWidget, QTableWidgetItem, 
    QMessageBox, QMenu, QInputDialog, QDialog, QFileDialog, QComboBox, QSpinBox, QHeaderView
)
from PyQt6.QtCore import Qt, QUrl
from PyQt6.QtGui import QAction
from cryptography.fernet import Fernet
import json, os, sys, pyperclip, random, string, webbrowser
import winreg

# =================== Themes ===================
themes = {
    "Light": """
        QWidget { background-color: #F5F5F5; color: #000; font-size:14px; }
        QLineEdit, QTableWidget, QTableView { background-color: #FFF; border:1px solid #AAA; border-radius:6px; padding:6px; selection-background-color:#3399FF; }
        QPushButton { background-color:#DDD; border:1px solid #AAA; border-radius:6px; padding:6px; }
        QPushButton:hover { background-color:#CCC; }
        QPushButton:pressed { background-color:#BBB; }
        QHeaderView::section { background-color:#DDD; border:1px solid #AAA; padding:6px; }
        QTableWidget::item:selected { background-color:#3399FF; color:white; }
    """,
    "Dark": """
        QWidget { background-color:#1E1E1E; color:#E5E5E5; font-size:14px; }
        QLineEdit, QTableWidget, QTableView { background-color:#2B2B2B; border:1px solid #444; border-radius:6px; padding:6px; selection-background-color:#007ACC; }
        QPushButton { background-color:#3A3A3A; border:1px solid #555; border-radius:6px; padding:6px; }
        QPushButton:hover { background-color:#505050; }
        QPushButton:pressed { background-color:#3D3D3D; }
        QHeaderView::section { background-color:#3A3A3A; border:1px solid #555; padding:6px; }
        QTableWidget::item:selected { background-color:#007ACC; color:white; }
    """,
    "MacOS Sierra Dark": """
        QWidget { background-color:#2C2C2E; color:#FFFFFF; font-size:14px; }
        QLineEdit, QTableWidget { background-color:#3A3A3C; border:1px solid #555; border-radius:6px; padding:6px; selection-background-color:#0A84FF; }
        QPushButton { background-color:#444444; border-radius:6px; padding:6px; }
        QTableWidget::item:selected { background-color:#0A84FF; color:white; }
    """,
    "Windows 11 Fluent Dark": """
        QWidget { background-color:#1E1E2F; color:#FFFFFF; font-size:14px; }
        QLineEdit, QTableWidget { background-color:#252535; border:1px solid #3A3A4A; border-radius:6px; padding:6px; selection-background-color:#0078D4; }
        QPushButton { background-color:#3A3A4A; border-radius:6px; padding:6px; }
        QTableWidget::item:selected { background-color:#0078D4; color:white; }
    """,
    "Material UI Dark": """
        QWidget { background-color:#263238; color:#ECEFF1; font-size:14px; }
        QLineEdit, QTableWidget { background-color:#37474F; border-radius:6px; padding:6px; selection-background-color:#80CBC4; }
        QPushButton { background-color:#455A64; border-radius:6px; padding:6px; }
        QTableWidget::item:selected { background-color:#80CBC4; color:#263238; }
    """,
    "Nord": """
        QWidget { background-color:#2E3440; color:#D8DEE9; font-size:14px; }
        QLineEdit, QTableWidget { background-color:#3B4252; border-radius:6px; padding:6px; selection-background-color:#88C0D0; }
        QPushButton { background-color:#4C566A; border-radius:6px; padding:6px; }
        QTableWidget::item:selected { background-color:#88C0D0; color:#2E3440; }
    """,
    "Dracula": """
        QWidget { background-color:#282A36; color:#F8F8F2; font-size:14px; }
        QLineEdit, QTableWidget { background-color:#44475A; border-radius:6px; padding:6px; selection-background-color:#6272A4; }
        QPushButton { background-color:#6272A4; border-radius:6px; padding:6px; }
        QTableWidget::item:selected { background-color:#6272A4; color:#F8F8F2; }
    """
}

# =================== Master Password Dialog ===================
class MasterPasswordDialog(QDialog):
    def __init__(self, new_password=False):
        super().__init__()
        self.setWindowTitle("Master Password" if not new_password else "Create New Master Password")
        self.setFixedWidth(300)
        layout = QVBoxLayout()
        self.pw_input = QLineEdit()
        self.pw_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pw_input.setPlaceholderText("Enter Master Password")
        layout.addWidget(self.pw_input)
        if new_password:
            self.pw_confirm_input = QLineEdit()
            self.pw_confirm_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.pw_confirm_input.setPlaceholderText("Confirm Master Password")
            layout.addWidget(self.pw_confirm_input)
        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.accept)
        layout.addWidget(ok_btn)
        self.setLayout(layout)

    def get_password(self): return self.pw_input.text()
    def get_password_confirm(self): 
        return getattr(self, 'pw_confirm_input', None) and self.pw_confirm_input.text() or None

# =================== Main GUI ===================
class PasswordManagerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.app = QApplication.instance()
        if not self.check_master_password():
            sys.exit()
        self.setWindowTitle("Password Manager")
        self.setMinimumSize(700,500)
        # Files
        self.key_file="key.key"
        self.passwords_file="passwords.enc"
        self.key=self.get_or_create_key()
        self.fernet=Fernet(self.key)
        self.passwords=self.load_passwords()
        self.central_widget=QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout=QVBoxLayout(self.central_widget)
        # Top buttons
        self.create_top_buttons()
        # Search
        self.create_search_field()
        # Input fields
        self.create_input_fields()
        # Table
        self.create_table()
        self.update_table()
        # Load theme from registry
        self.load_theme_from_registry()

    # ---------- Master Password ----------
    def check_master_password(self):
        self.master_file="master.key"
        if not os.path.exists(self.master_file):
            dialog=MasterPasswordDialog(new_password=True)
            if dialog.exec()==QDialog.DialogCode.Accepted:
                pw=dialog.get_password()
                pw_confirm=dialog.get_password_confirm()
                if pw==pw_confirm and pw.strip():
                    key=Fernet.generate_key()
                    f=Fernet(key)
                    encrypted_pw=f.encrypt(pw.encode())
                    with open(self.master_file,'wb') as file:
                        file.write(key+b'\n'+encrypted_pw)
                    return True
                else:
                    QMessageBox.warning(self,"Error","Passwords do not match or empty!")
                    return False
            else:
                return False
        else:
            with open(self.master_file,'rb') as file:
                key=file.readline().strip()
                encrypted_pw=file.readline().strip()
            for _ in range(3):
                dialog=MasterPasswordDialog()
                if dialog.exec()==QDialog.DialogCode.Accepted:
                    pw=dialog.get_password()
                    f=Fernet(key)
                    try:
                        dec_pw=f.decrypt(encrypted_pw).decode()
                        if pw==dec_pw: return True
                        else: QMessageBox.warning(self,"Error","Wrong password!")
                    except: QMessageBox.warning(self,"Error","Wrong password!")
                else: return False
            QMessageBox.critical(self,"Error","Too many failed attempts!")
            return False

    def change_master_password(self):
        dialog=MasterPasswordDialog(new_password=True)
        if dialog.exec()==QDialog.DialogCode.Accepted:
            pw=dialog.get_password()
            pw_confirm=dialog.get_password_confirm()
            if pw==pw_confirm and pw.strip():
                key=Fernet.generate_key()
                f=Fernet(key)
                encrypted_pw=f.encrypt(pw.encode())
                with open(self.master_file,'wb') as file:
                    file.write(key+b'\n'+encrypted_pw)
                QMessageBox.information(self,"Success","Master password changed successfully!")
            else: QMessageBox.warning(self,"Error","Passwords do not match or empty!")

    # ---------- Top Buttons ----------
    def create_top_buttons(self):
        top_layout=QHBoxLayout()
        self.change_master_btn=QPushButton("Change Master Password")
        self.change_master_btn.clicked.connect(self.change_master_password)
        top_layout.addWidget(self.change_master_btn)
        self.save_txt_btn=QPushButton("Save to TXT")
        self.save_txt_btn.clicked.connect(self.save_to_txt)
        top_layout.addWidget(self.save_txt_btn)
        self.load_txt_btn=QPushButton("Load from TXT")
        self.load_txt_btn.clicked.connect(self.load_from_txt)
        top_layout.addWidget(self.load_txt_btn)
        self.theme_combo=QComboBox()
        self.theme_combo.addItems(list(themes.keys()))
        self.theme_combo.currentIndexChanged.connect(self.change_theme)
        top_layout.addWidget(self.theme_combo)
        self.layout.addLayout(top_layout)

    def change_theme(self, index):
        theme_name=self.theme_combo.currentText()
        self.app.setStyleSheet(themes[theme_name])
        self.save_theme_to_registry(theme_name)

    def save_theme_to_registry(self, theme_name):
        try:
            key=winreg.CreateKey(winreg.HKEY_CURRENT_USER,r"Software\PasswordManager")
            winreg.SetValueEx(key,"Theme",0,winreg.REG_SZ,theme_name)
            winreg.CloseKey(key)
        except: pass

    def load_theme_from_registry(self):
        try:
            key=winreg.OpenKey(winreg.HKEY_CURRENT_USER,r"Software\PasswordManager")
            theme_name,_=winreg.QueryValueEx(key,"Theme")
            winreg.CloseKey(key)
            if theme_name in themes:
                self.theme_combo.setCurrentText(theme_name)
                self.app.setStyleSheet(themes[theme_name])
            else:
                self.theme_combo.setCurrentText("Light")
                self.app.setStyleSheet(themes["Light"])
        except:
            self.theme_combo.setCurrentText("Light")
            self.app.setStyleSheet(themes["Light"])

    # ---------- Search ----------
    def create_search_field(self):
        search_layout=QHBoxLayout()
        self.search_input=QLineEdit()
        self.search_input.setPlaceholderText("Search by site or username...")
        self.search_input.textChanged.connect(self.search)
        self.clear_search_btn=QPushButton("Clear Search")
        self.clear_search_btn.clicked.connect(self.clear_search)
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(self.clear_search_btn)
        self.layout.addLayout(search_layout)

    def search(self,text):
        text=text.lower()
        self.table.setRowCount(0)
        row=0
        results=[]
        for site,info in self.passwords.items():
            if text in site.lower() or text in info["username"].lower():
                results.append((site,info))
        results=sorted(results,key=lambda x:x[0].lower())
        for site,info in results:
            self.table.insertRow(row)
            self.table.setItem(row,0,QTableWidgetItem(site))
            self.table.setItem(row,1,QTableWidgetItem(info["username"]))
            self.table.setItem(row,2,QTableWidgetItem("********"))
            row+=1

    def clear_search(self):
        self.search_input.clear()
        self.update_table()

    # ---------- Input Fields ----------
    def create_input_fields(self):
        input_layout=QHBoxLayout()
        self.site_input=QLineEdit(); self.site_input.setPlaceholderText("Site")
        self.username_input=QLineEdit(); self.username_input.setPlaceholderText("Username")
        self.pass_input=QLineEdit(); self.pass_input.setPlaceholderText("Password (visible)")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Normal)
        self.length_spin=QSpinBox(); self.length_spin.setRange(6,32); self.length_spin.setValue(12); self.length_spin.setPrefix("Len: ")
        self.generate_btn=QPushButton("Generate Password"); self.generate_btn.clicked.connect(self.generate_password)
        self.add_btn=QPushButton("Add Password"); self.add_btn.clicked.connect(self.add_password)
        input_layout.addWidget(self.site_input)
        input_layout.addWidget(self.username_input)
        input_layout.addWidget(self.pass_input)
        input_layout.addWidget(self.length_spin)
        input_layout.addWidget(self.generate_btn)
        input_layout.addWidget(self.add_btn)
        self.layout.addLayout(input_layout)

    def generate_password(self):
        length=self.length_spin.value()
        chars=string.ascii_letters+string.digits+string.punctuation
        self.pass_input.setText("".join(random.choice(chars) for _ in range(length)))

    def add_password(self):
        site=self.site_input.text().strip()
        username=self.username_input.text().strip()
        password=self.pass_input.text().strip()
        if not all([site,username,password]):
            QMessageBox.warning(self,"Error","Please fill all fields!")
            return
        self.passwords[site]={"username":username,"password":password}
        self.save_passwords()
        self.site_input.clear(); self.username_input.clear(); self.pass_input.clear()
        self.update_table()
        QMessageBox.information(self,"Success","Password added successfully!")

    # ---------- Table ----------
    def create_table(self):
        self.table=QTableWidget(); self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Site","Username","Password"])
        self.table.setShowGrid(True)
        self.table.setStyleSheet("""
            QTableWidget::item { border:1px solid #555; }
            QHeaderView::section { border:1px solid #555; padding:4px; }
        """)
        header=self.table.horizontalHeader()
        header.setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2,QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.context_menu)
        self.layout.addWidget(self.table)

    def update_table(self):
        self.table.setRowCount(0)
        for row,(site,info) in enumerate(sorted(self.passwords.items(),key=lambda x:x[0].lower())):
            self.table.insertRow(row)
            self.table.setItem(row,0,QTableWidgetItem(site))
            self.table.setItem(row,1,QTableWidgetItem(info["username"]))
            self.table.setItem(row,2,QTableWidgetItem("********"))

    # ---------- Context Menu ----------
    def context_menu(self,pos):
        menu=QMenu()
        row=self.table.rowAt(pos.y())
        col=self.table.columnAt(pos.x())
        if row<0 or col<0: return
        site=self.table.item(row,0).text()
        copy_action=QAction("Copy",self); copy_action.triggered.connect(lambda: self.copy_cell(row,col)); menu.addAction(copy_action)
        edit_action=QAction("Edit",self); edit_action.triggered.connect(lambda: self.edit_cell(row,col)); menu.addAction(edit_action)
        if col==2: show_action=QAction("Show Password",self); show_action.triggered.connect(lambda: self.show_password_popup(row)); menu.addAction(show_action)
        delete_action=QAction("Delete",self); delete_action.triggered.connect(lambda: self.delete_row(row)); menu.addAction(delete_action)
        if col==0: open_action=QAction("Open Site",self); open_action.triggered.connect(lambda: self.open_site(row)); menu.addAction(open_action)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def copy_cell(self,row,col):
        site=self.table.item(row,0).text()
        if col==0: pyperclip.copy(site)
        elif col==1: pyperclip.copy(self.passwords[site]["username"])
        elif col==2: pyperclip.copy(self.passwords[site]["password"])
        QMessageBox.information(self,"Copied","Copied to clipboard!")

    def edit_cell(self,row,col):
        site=self.table.item(row,0).text()
        if col==0:
            old=site
            new,ok=QInputDialog.getText(self,"Edit Site","New site:",QLineEdit.EchoMode.Normal,old)
            if ok and new: self.passwords[new]=self.passwords.pop(site)
        elif col==1:
            old=self.passwords[site]["username"]
            new,ok=QInputDialog.getText(self,"Edit Username","New username:",QLineEdit.EchoMode.Normal,old)
            if ok and new: self.passwords[site]["username"]=new
        elif col==2:
            old=self.passwords[site]["password"]
            new,ok=QInputDialog.getText(self,"Edit Password","New password:",QLineEdit.EchoMode.Normal,old)
            if ok and new: self.passwords[site]["password"]=new
        self.save_passwords(); self.update_table()

    def show_password_popup(self,row):
        site=self.table.item(row,0).text()
        password=self.passwords[site]["password"]
        QMessageBox.information(self,"Password",f"Password: {password}")

    def delete_row(self,row):
        site=self.table.item(row,0).text()
        if QMessageBox.question(self,"Delete",f"Delete {site}?")==QMessageBox.StandardButton.Yes:
            del self.passwords[site]
            self.save_passwords()
            self.update_table()

    def open_site(self,row):
        site=self.table.item(row,0).text().strip()
        if site:  # kullanıcı ne yazdıysa o açılsın
            webbrowser.open(site)

    # ---------- Load / Save Passwords ----------
    def get_or_create_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file,"rb") as f:
                return f.read()
        else:
            key=Fernet.generate_key()
            with open(self.key_file,"wb") as f:
                f.write(key)
            return key

    def load_passwords(self):
        if os.path.exists(self.passwords_file):
            with open(self.passwords_file,"rb") as f:
                encrypted=f.read()
            try:
                decrypted=self.fernet.decrypt(encrypted)
                return json.loads(decrypted)
            except:
                return {}
        return {}

    def save_passwords(self):
        encrypted=self.fernet.encrypt(json.dumps(self.passwords).encode())
        with open(self.passwords_file,"wb") as f:
            f.write(encrypted)

    # ---------- TXT ----------
    def save_to_txt(self):
        file_name,_=QFileDialog.getSaveFileName(self,"Save Passwords","","Text Files (*.txt)")
        if file_name:
            try:
                with open(file_name,"w",encoding="utf-8") as f:
                    for site,info in self.passwords.items():
                        f.write(f"{site},{info['username']},{info['password']}\n")
                QMessageBox.information(self,"Saved","Passwords saved to TXT successfully!")
            except Exception as e:
                QMessageBox.critical(self,"Error",f"Failed to save: {str(e)}")

    def load_from_txt(self):
        file_name,_=QFileDialog.getOpenFileName(self,"Load Passwords","","Text Files (*.txt)")
        if file_name:
            try:
                with open(file_name,"r",encoding="utf-8") as f:
                    for line in f:
                        parts=line.strip().split(",")
                        if len(parts)==3:
                            site=username=password=None
                            site,username,password=[p.strip() for p in parts]
                            self.passwords[site]={"username":username,"password":password}
                self.save_passwords()
                self.update_table()
                QMessageBox.information(self,"Loaded","Passwords loaded from TXT successfully!")
            except Exception as e:
                QMessageBox.critical(self,"Error",f"Failed to load: {str(e)}")

# =================== Main ===================
def main():
    app=QApplication(sys.argv)
    window=PasswordManagerGUI()
    window.show()
    sys.exit(app.exec())

if __name__=="__main__":
    main()
