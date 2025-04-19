# Password Manager

A simple desktop application to store, manage, and generate passwords securely. Built with Python and PyQt6, and backed by a local SQLite database.

## 🚀 Features

- Save passwords with associated website and username
- View all saved entries in a table
- Delete individual entries
- Generate secure random passwords
- Simple and clean graphical interface

## 🖥️ Screenshot

![Screenshot](1.png)  
![Screenshot](2.png)  
![Screenshot](3.png)  
![Screenshot](4.png)  
*The main interface of the Password Manager.*

## ⚙️ Installation

> **Requirements:**  
> - Python 3.10+  
> - pip  

1. Clone this repository or download the source files.

2. Install dependencies:
   ```bash
   pip install PyQt6 cryptography pyperclip
   ```

3. Run the application:
   ```bash
   python Password_Manager.py
   ```

## 🛠️ Build Executable (.exe)

To create a standalone Windows executable of the application:

1. Install `pyinstaller` if you haven't:
   ```bash
   pip install pyinstaller
   ```

2. Run the following command to generate the `.exe`:
   ```bash
   pyinstaller --onefile --windowed  --icon=pass.ico Password_Manager.py
   ```

3. After building, the executable file will be located in the `dist` folder as `main.exe`.

> **Note:**  
> - Use `--windowed` to hide the terminal window (recommended for GUI apps).  
> - If your script depends on other files (like icons or `.ui` files), you may need to bundle them manually or adjust the `pyinstaller` command.


---

## 🔐 How It Works

- Stores passwords in a local SQLite database (`passwords.enc`).
- Each entry includes a website, username, and password.
- The password generator creates a secure password using letters, digits, and symbols.

## 📁 Files

- `Password_Manager.py`: Main application file (PyQt6 UI + database logic)
- `passwords.enc`: Created automatically to store saved data
- `README.md`: Project description and usage guide

> 💡 **Tip:**  
> It is recommended to create a folder named `Password Manager` and place the `Password_Manager.py` file inside it.  
> This way, any files created by the program (like `passwords.enc`) will stay organized within that folder.


## 🛡️ Security Note

This is a simple desktop password manager for local use only. **Passwords are stored unencrypted in the database.** For production-grade usage, consider implementing encryption and user authentication.

## 📄 License

This project is licensed under the MIT License.
