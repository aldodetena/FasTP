# ftpd_server.py
import tkinter as tk
import ftpHandler as ftpH
import ipFilter
from tkinter import messagebox
from tkinter import filedialog
from threading import Thread
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.servers import FTPServer
from osDetector import firewallConf

class FTPServerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Servidor FTP")
        self.ip_filter = ipFilter.IPFilter('blocked_ips')  # 'blocked_ips.ipf' será el archivo utilizado

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

        self.tls_var = tk.BooleanVar()
        self.tls_checkbox = tk.Checkbutton(root, text="Activar TLS", variable=self.tls_var, command=self.on_tls_checkbox)
        self.tls_checkbox.pack()

        self.ip_manage_button = tk.Button(root, text="Gestionar IPs", command=self.open_ip_manage_popup)
        self.ip_manage_button.pack()

        # Campo para la ruta del certificado
        self.cert_file_entry = tk.Entry(root)
        self.cert_file_entry.pack()
        self.cert_file_button = tk.Button(root, text="Seleccionar Certificado", command=lambda: self.on_select_file('cert'))
        self.cert_file_button.pack()

        # Campo para la ruta de la clave privada
        self.key_file_entry = tk.Entry(root)
        self.key_file_entry.pack()
        self.key_file_button = tk.Button(root, text="Seleccionar Clave Privada", command=lambda: self.on_select_file('key'))
        self.key_file_button.pack()

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
    
    def on_tls_checkbox(self):
        if self.tls_var.get():
            # Activar TLS
            self.cert_file_entry.config(state='normal')
            self.cert_file_button.config(state='normal')
        else:
            # Desactivar TLS
            self.cert_file_entry.config(state='disabled')
            self.cert_file_button.config(state='disabled')
    
    def on_select_file(self, file_type):
        file_path = filedialog.askopenfilename(
            title=f"Seleccionar {'Certificado' if file_type == 'cert' else 'Clave Privada'}",
            filetypes=(("Archivos PEM", "*.pem"), ("Archivos KEY", "*.key"), ("Todos los archivos", "*.*"))
        )
        if file_path:
            if file_type == 'cert':
                self.cert_file_entry.delete(0, tk.END)
                self.cert_file_entry.insert(0, file_path)
            elif file_type == 'key':
                self.key_file_entry.delete(0, tk.END)
                self.key_file_entry.insert(0, file_path)

    def open_ip_manage_popup(self):
        self.popup = tk.Toplevel(self.root)
        self.popup.title("Gestión de IPs")

        # Sección para añadir IP
        tk.Label(self.popup, text="Añadir IP:").pack()
        self.add_ip_entry = tk.Entry(self.popup)
        self.add_ip_entry.pack()
        add_ip_button = tk.Button(self.popup, text="Añadir", command=self.add_ip_to_filter)
        add_ip_button.pack()

        # Sección para mostrar y eliminar IPs bloqueadas
        tk.Label(self.popup, text="IPs Bloqueadas:").pack()
        self.blocked_ips_listbox = tk.Listbox(self.popup)
        self.blocked_ips_listbox.pack()
        self.update_blocked_ips_listbox()

        remove_ip_button = tk.Button(self.popup, text="Eliminar IP Seleccionada", command=self.remove_selected_ip)
        remove_ip_button.pack()

    def add_ip_to_filter(self):
        ip_to_add = self.add_ip_entry.get()
        if self.ip_filter.add_ip(ip_to_add):
            self.update_blocked_ips_listbox()
        else:
            messagebox.showerror("Error", "Dirección IP no válida o ya añadida.")

    def remove_selected_ip(self):
        selected_indices = self.blocked_ips_listbox.curselection()
        if selected_indices:
            selected_ip = self.blocked_ips_listbox.get(selected_indices[0])
            if self.ip_filter.remove_ip(selected_ip):
                self.update_blocked_ips_listbox()
            else:
                messagebox.showerror("Error", "La dirección IP no se encuentra en la lista.")

    def update_blocked_ips_listbox(self):
        self.blocked_ips_listbox.delete(0, tk.END)  # Limpiar lista actual
        for ip in self.ip_filter.blocked_ips:
            self.blocked_ips_listbox.insert(tk.END, ip)  # Añadir IPs a la lista

    def start_server(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        directory = self.directory_entry.get()

        if not (username and password and directory):
            messagebox.showerror("Error", "Todos los campos son obligatorios")
            return

        authorizer = DummyAuthorizer()
        authorizer.add_user(username, password, directory, perm="elradfmw")

        # Comprobar si TLS está activado
        if self.tls_var.get():
            cert_file = self.cert_file_entry.get()
            key_file = self.key_file_entry.get()
            if cert_file and key_file:
                ftpH.CustomFTPHandler.certfile = cert_file
                ftpH.CustomFTPHandler.keyfile = key_file
                ftpH.CustomFTPHandler.tls_control_required = True
                ftpH.CustomFTPHandler.tls_data_required = True
            else:
                messagebox.showerror("Error", "Certificado o clave privada no especificados")
                return
        else:
            # Configurar el handler para no usar TLS
            ftpH.CustomFTPHandler.certfile = None
            ftpH.CustomFTPHandler.tls_control_required = False
            ftpH.CustomFTPHandler.tls_data_required = False

        ftpH.CustomFTPHandler.gui = self
        self.server = FTPServer(("0.0.0.0", 45000), ftpH.CustomFTPHandler)
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Estado: En ejecución")

    def stop_server(self):
        if self.server:
            self.server.close_all()  # Cierra todas las conexiones del servidor
            self.server = None

        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(1)  # Espera un tiempo limitado para que el hilo termine
            if self.server_thread.is_alive():
                # Si el hilo todavía está activo, forzar su terminación
                import ctypes
                ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(self.server_thread.ident), ctypes.py_object(SystemExit))

            self.server_thread = None

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Estado: Detenido")

if __name__ == "__main__":
    root = tk.Tk()
    gui = FTPServerGUI(root)
    root.mainloop()
