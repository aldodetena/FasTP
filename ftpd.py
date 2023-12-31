# ftpd_server.py
import tkinter as tk
import ftpHandler as ftpH
from tkinter import messagebox
from threading import Thread
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.servers import FTPServer
from osDetector import firewallConf

class FTPServerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Servidor FTP")

        tk.Label(root, text="Usuario:").pack()
        self.username_entry = tk.Entry(root)
        self.username_entry.pack()

        tk.Label(root, text="Contraseña:").pack()
        self.password_entry = tk.Entry(root, show="*")
        self.password_entry.pack()

        tk.Label(root, text="Directorio:").pack()
        self.directory_entry = tk.Entry(root)
        self.directory_entry.pack()

        self.user_count = 0
        self.user_count_label = tk.Label(root, text="Usuarios conectados: 0")
        self.user_count_label.pack()

        self.log_text = tk.Text(root, height=10, state='disabled')
        self.log_text.pack()

        self.status_label = tk.Label(root, text="Estado: Detenido")
        self.status_label.pack()

        self.start_button = tk.Button(root, text="Iniciar Servidor", command=self.start_server)
        self.start_button.pack()

        self.stop_button = tk.Button(root, text="Detener Servidor", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.pack()

        self.server = None
        self.server_thread = None

    def log_event(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state='disabled')
        self.log_text.yview(tk.END)

    def update_user_count(self, change):
        self.user_count += change
        self.user_count_label.config(text=f"Usuarios conectados: {self.user_count}")

    def start_server(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        directory = self.directory_entry.get()

        if not (username and password and directory):
            messagebox.showerror("Error", "Todos los campos son obligatorios")
            return

        authorizer = DummyAuthorizer()
        authorizer.add_user(username, password, directory, perm="elradfmw")

        ftpH.CustomFTPHandler.gui = self  # Establece la referencia a la GUI
        self.server = FTPServer(("0.0.0.0", 45000), ftpH.CustomFTPHandler)
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Estado: En ejecución")

    def stop_server(self):
        if self.server:
            self.server.close_all()
        
        if self.server_thread:
            self.server_thread.join()

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL)

        self.status_label.config(text="Estado: Detenido")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    gui = FTPServerGUI(root)
    root.mainloop()
