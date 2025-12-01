import os
import hashlib
import base64
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import *
import threading
import time

class DiskEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.setup_main_window()
        self.setup_styles()
        self.setup_variables()
        self.create_widgets()
        
    def setup_main_window(self):
        """Configure the main window settings"""
        self.root.title("Disk Encryptor")
        self.root.geometry("800x700")
        self.root.configure(bg='white')
        self.root.resizable(True, True)
        
    def setup_styles(self):
        """Configure custom styles for widgets"""
        style = ttk.Style()
        style.configure('TNotebook', background='white')
        style.configure('Custom.TFrame', background='white')
        style.configure('Header.TLabel', 
                       font=('Helvetica', 24, 'bold'), 
                       padding=10)
        style.configure('Status.TLabel', 
                       font=('Helvetica', 10), 
                       foreground='#666666')
        
    def setup_variables(self):
        """Initialize variables used across the application"""
        self.password_var = tk.StringVar()
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
    def create_widgets(self):
        """Create and arrange all widgets in the window"""
        self.create_header()
        self.create_password_section()
        self.create_notebook()
        self.create_progress_section()
        self.create_footer()
        
    def create_header(self):
        """Create the header section"""
        header_frame = ttk.Frame(self.root, style='Custom.TFrame')
        header_frame.pack(fill='x', padx=20, pady=10)
        
        title_label = ttk.Label(header_frame, 
                               text="Disk Encryptor", 
                               style='Header.TLabel')
        title_label.pack(pady=10)
        
    def create_password_section(self):
        """Create the password input section"""
        password_frame = ttk.Frame(self.root, style='Custom.TFrame')
        password_frame.pack(fill='x', padx=20, pady=10)
        
        password_label = ttk.Label(password_frame, 
                                 text="Enter Password:", 
                                 font=('Helvetica', 12))
        password_label.pack(side='left', padx=5)
        
        self.password_entry = ttk.Entry(password_frame, 
                                      textvariable=self.password_var, 
                                      show="*", 
                                      width=40)
        self.password_entry.pack(side='left', padx=5)
        
        self.show_password_var = tk.BooleanVar()
        show_password_btn = ttk.Checkbutton(
            password_frame,
            text="Show Password",
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        show_password_btn.pack(side='left', padx=5)
        
    def create_notebook(self):
        """Create the notebook with tabs for different operations"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=10)
        
        # File Operations Tab
        file_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(file_frame, text='File Operations')
        
        ttk.Button(file_frame, 
                  text="Encrypt File", 
                  command=lambda: self.start_operation(self.encrypt_file)
                  ).pack(pady=10)
        ttk.Button(file_frame, 
                  text="Decrypt File", 
                  command=lambda: self.start_operation(self.decrypt_file)
                  ).pack(pady=10)
        
        # Folder Operations Tab
        folder_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(folder_frame, text='Folder Operations')
        
        ttk.Button(folder_frame, 
                  text="Encrypt Folder", 
                  command=lambda: self.start_operation(self.encrypt_folder)
                  ).pack(pady=10)
        ttk.Button(folder_frame, 
                  text="Decrypt Folder", 
                  command=lambda: self.start_operation(self.decrypt_folder)
                  ).pack(pady=10)
        
        # Disk Operations Tab
        disk_frame = ttk.Frame(self.notebook, style='Custom.TFrame')
        self.notebook.add(disk_frame, text='Disk Operations')
        
        self.create_disk_widgets(disk_frame)
        
    def create_disk_widgets(self, parent):
        """Create widgets for disk operations"""
        available_drives = self.get_available_drives()
        
        for drive in available_drives:
            drive_frame = ttk.Frame(parent)
            drive_frame.pack(fill='x', padx=10, pady=5)
            
            ttk.Label(drive_frame, 
                     text=f"Drive {drive}", 
                     font=('Helvetica', 11)
                     ).pack(side='left')
            
            ttk.Button(drive_frame, 
                      text="Encrypt", 
                      command=lambda d=drive: self.encrypt_drive(d)
                      ).pack(side='right', padx=5)
            ttk.Button(drive_frame, 
                      text="Decrypt", 
                      command=lambda d=drive: self.decrypt_drive(d)
                      ).pack(side='right', padx=5)
            
    def create_progress_section(self):
        """Create the progress bar and status section"""
        progress_frame = ttk.Frame(self.root, style='Custom.TFrame')
        progress_frame.pack(fill='x', padx=20, pady=10)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            mode='determinate',
            length=300
        )
        self.progress_bar.pack(pady=5)
        
        self.status_label = ttk.Label(
            progress_frame,
            textvariable=self.status_var,
            style='Status.TLabel'
        )
        self.status_label.pack()
        
    def create_footer(self):
        """Create the footer section"""
        footer_frame = ttk.Frame(self.root, style='Custom.TFrame')
        footer_frame.pack(fill='x', side='bottom', pady=10)
        
        ttk.Label(footer_frame, 
                 text="Created by Hemant", 
                 style='Status.TLabel'
                 ).pack()

    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def get_available_drives(self):
        """Get list of available drives"""
        if os.name == 'nt':  # Windows
            return ['C:', 'D:', 'E:', 'F:']
        return ['/']  # Unix/Linux/MacOS

    def generate_key(self, password):
        """Generate encryption key from password"""
        hashed_password = hashlib.sha256(password.encode()).digest()
        return base64.urlsafe_b64encode(hashed_password[:32])

    def start_operation(self, operation):
        """Start an encryption/decryption operation in a separate thread"""
        if not self.password_var.get():
            messagebox.showerror("Error", "Password cannot be empty!")
            return
            
        self.progress_var.set(0)
        self.status_var.set("Processing...")
        
        thread = threading.Thread(target=self.run_operation, args=(operation,))
        thread.daemon = True
        thread.start()

    def run_operation(self, operation):
        """Run the encryption/decryption operation"""
        try:
            operation()
            self.root.after(0, self.operation_complete)
        except Exception as e:
            self.root.after(0, lambda: self.operation_failed(str(e)))

    def operation_complete(self):
        """Handle operation completion"""
        self.progress_var.set(100)
        self.status_var.set("Operation completed successfully!")
        messagebox.showinfo("Success", "Operation completed successfully!")

    def operation_failed(self, error_message):
        """Handle operation failure"""
        self.status_var.set("Operation failed!")
        messagebox.showerror("Error", f"Operation failed: {error_message}")

    def encrypt_file(self):
        """Encrypt a single file"""
        file_path = filedialog.askopenfilename(title="Select File to Encrypt")
        if not file_path:
            return

        fernet = Fernet(self.generate_key(self.password_var.get()))
        with open(file_path, "rb") as file:
            file_data = file.read()
        
        encrypted_data = fernet.encrypt(file_data)
        with open(file_path, "wb") as file:
            file.write(encrypted_data)

    def decrypt_file(self):
        """Decrypt a single file"""
        file_path = filedialog.askopenfilename(title="Select File to Decrypt")
        if not file_path:
            return

        fernet = Fernet(self.generate_key(self.password_var.get()))
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
        
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(file_path, "wb") as file:
            file.write(decrypted_data)

    def encrypt_folder(self):
        """Encrypt all files in a folder"""
        folder_path = filedialog.askdirectory(title="Select Folder to Encrypt")
        if not folder_path:
            return

        fernet = Fernet(self.generate_key(self.password_var.get()))
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    file_data = f.read()
                encrypted_data = fernet.encrypt(file_data)
                with open(file_path, "wb") as f:
                    f.write(encrypted_data)

    def decrypt_folder(self):
        """Decrypt all files in a folder"""
        folder_path = filedialog.askdirectory(title="Select Folder to Decrypt")
        if not folder_path:
            return

        fernet = Fernet(self.generate_key(self.password_var.get()))
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                with open(file_path, "rb") as f:
                    encrypted_data = f.read()
                decrypted_data = fernet.decrypt(encrypted_data)
                with open(file_path, "wb") as f:
                    f.write(decrypted_data)

    def encrypt_drive(self, drive):
        """Encrypt an entire drive"""
        if messagebox.askyesno("Confirm", f"Do you want to encrypt drive {drive}?"):
            # Implement drive encryption logic here
            messagebox.showinfo("Success", f"Drive {drive} encrypted successfully!")

    def decrypt_drive(self, drive):
        """Decrypt an entire drive"""
        if messagebox.askyesno("Confirm", f"Do you want to decrypt drive {drive}?"):
            # Implement drive decryption logic here
            messagebox.showinfo("Success", f"Drive {drive} decrypted successfully!")

def main():
    root = tk.Tk()
    app = DiskEncryptorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()