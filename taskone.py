# Import required modules
import sys
import os
import hashlib
import json
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QFileDialog, QLabel,
    QVBoxLayout, QTableWidget, QTableWidgetItem, QMessageBox
)

# File where we store the hash values of previously scanned files
HASH_FILE = "file_hashes.json"

# Function to calculate the SHA-256 hash of a file
def calculate_hash(filepath):
    sha256 = hashlib.sha256()
    # Open file in binary mode and read it in chunks
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()

# Function to scan all files in a folder and generate their hashes
def scan_files(folder):
    file_hashes = {}
    # Walk through all directories and files inside the selected folder
    for root, _, files in os.walk(folder):
        for file in files:
            path = os.path.join(root, file)
            try:
                file_hashes[path] = calculate_hash(path)  # Store file hash
            except Exception as e:
                print(f"Error reading {path}: {e}")  # Skip unreadable files
    return file_hashes

# Main GUI application class
class FileMonitorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("File Change Monitor (Hash Based)")
        self.resize(700, 500)  # Set window size

        # Set up layout and widgets
        self.layout = QVBoxLayout()

        self.label = QLabel("Selected folder: None")  # Show selected folder path
        self.btn_select = QPushButton("Select Folder")  # Button to choose folder
        self.btn_monitor = QPushButton("Scan & Compare")  # Button to scan & compare

        # Table to show file status (NEW / MODIFIED / DELETED)
        self.table = QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Status", "File Path"])
        self.table.setColumnWidth(0, 100)
        self.table.setColumnWidth(1, 550)

        # Connect button actions to functions
        self.btn_select.clicked.connect(self.select_folder)
        self.btn_monitor.clicked.connect(self.monitor_files)

        # Add all widgets to the layout
        self.layout.addWidget(self.label)
        self.layout.addWidget(self.btn_select)
        self.layout.addWidget(self.btn_monitor)
        self.layout.addWidget(self.table)
        self.setLayout(self.layout)

        self.folder_path = None  # Variable to hold selected folder path

    # Function to open folder selection dialog
    def select_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if path:
            self.folder_path = path
            self.label.setText(f"Selected folder: {path}")  # Update label

    # Function to scan files and compare them with old hashes
    def monitor_files(self):
        if not self.folder_path:
            QMessageBox.warning(self, "Warning", "Please select a folder first.")
            return

        # Get the latest hashes of all files in the selected folder
        current_hashes = scan_files(self.folder_path)

        # Try to load previously saved hashes, or start fresh
        try:
            with open(HASH_FILE, "r") as f:
                old_hashes = json.load(f)
        except FileNotFoundError:
            old_hashes = {}

        self.table.setRowCount(0)  # Clear previous scan results from table

        # Compare current hashes with old hashes
        for path, hash in current_hashes.items():
            status = ""
            if path not in old_hashes:
                status = "NEW"  # File is new
            elif old_hashes[path] != hash:
                status = "MODIFIED"  # File has changed
            if status:
                self.add_table_row(status, path)  # Show in table

        # Find deleted files (present in old but not in current)
        for path in old_hashes:
            if path not in current_hashes:
                self.add_table_row("DELETED", path)

        # Save the current state of file hashes to disk
        with open(HASH_FILE, "w") as f:
            json.dump(current_hashes, f, indent=4)

    # Helper method to add a row in the result table
    def add_table_row(self, status, path):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(status))
        self.table.setItem(row, 1, QTableWidgetItem(path))

# Standard entry point for a PyQt5 application
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileMonitorApp()
    window.show()
    sys.exit(app.exec_())
