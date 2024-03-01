# ftpd_server.py
import threading
import time
import tkinter as tk
import ftpHandler as ftpH
import ipFilter
from optionsFrame import OptionsFrame
from tkinter import messagebox
from tkinter import filedialog
from threading import Thread
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.servers import FTPServer

class FTPServerGUI:
    def __init__(self, root):
        self.root = root
        root.title("Servidor FTP")
        # Inicializa IPFilter
        self.ip_filter = ipFilter.IPFilter('blocked_ips')

        # Marco para la configuración general del servidor
        self.server_frame = tk.Frame(root)
        self.server_frame.pack(fill=tk.BOTH, expand=True)

        self.port = 45000 # Puerto predeterminado
        self.user_count = 0
        self.user_count_label = tk.Label(self.server_frame, text="Usuarios conectados: 0")
        self.user_count_label.pack()

        self.log_text = tk.Text(self.server_frame, height=10, state='disabled')
        self.log_text.pack()

        self.status_label = tk.Label(self.server_frame, text="Estado: Detenido")
        self.status_label.pack()

        self.start_button = tk.Button(self.server_frame, text="Iniciar Servidor", bg="green", command=self.start_server, width=15)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(self.server_frame, text="Detener Servidor", bg="red", command=self.stop_server, state=tk.DISABLED , width=15)
        self.stop_button.pack(pady=5)

        threading.Thread(target=self.reload_ips_periodically, daemon=True).start()

        # Marco para las opciones avanzadas
        self.options_frame = OptionsFrame(root, parent=self, ip_filter=self.ip_filter, show_server_callback=self.show_server)

        # Menú de opciones
        self.menu_frame = tk.Frame(self.server_frame)
        self.menu_frame.pack(side=tk.TOP, fill=tk.X)

        # Botón de opciones
        self.options_button = tk.Button(self.menu_frame, text="Opciones", command=self.show_options)
        self.options_button.pack(side=tk.BOTTOM)

        self.server = None
        self.server_thread = None

    def show_options(self):
        # Lógica para mostrar el marco de opciones
        self.server_frame.pack_forget()
        self.options_frame.pack(fill=tk.BOTH, expand=True)

    def show_server(self):
        # Lógica para mostrar el marco del servidor
        self.options_frame.pack_forget()
        self.server_frame.pack(fill=tk.BOTH, expand=True)

    def log_event(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state='disabled')
        self.log_text.yview(tk.END)
    
    def select_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.directory_entry.delete(0, tk.END)
            self.directory_entry.insert(0, directory)

    def update_user_count(self, change):
        """Función para manejar la reinicialización a 0 de los usuarios conectados"""
        self.user_count += change
        # Asegurarse de que el contador no sea menor que cero
        if self.user_count < 0:
            self.user_count = 0
        self.user_count_label.config(text=f"Usuarios conectados: {self.user_count}")

    # Función para limpiar el área de texto del log
    def clear_log(self):
        self.log_text.config(state='normal')
        self.log_text.delete('1.0', tk.END)  # Eliminar todo el texto desde el principio hasta el final
        self.log_text.config(state='disabled')

    def reload_ips_periodically(self):
        while True:
            try:
                self.ip_filter.reload_blocked_ips()
                self.log_event("Lista de IPs actualizada correctamente")
            except Exception as e:
                self.log_event(f"Error al recargar las IPs: {e}")
            time.sleep(60)

    def change_port(self, new_port):
        self.port = new_port

    def start_server(self):
        username = self.options_frame.get_username()
        password = self.options_frame.get_password()
        directory = self.options_frame.get_directory()

        self.user_count = 0
        self.update_user_count(0)
        self.clear_log()

        if not (username and password and directory):
            messagebox.showerror("Error", "Todos los campos son obligatorios")
            return

        authorizer = DummyAuthorizer()
        authorizer.add_user(username, password, directory, perm="elradfmw")
        handler = None

        if self.options_frame.is_tls_enabled():
            cert_file = self.options_frame.get_tls_cert_file()
            key_file = self.options_frame.get_tls_key_file()

            if cert_file and key_file:
                handler = ftpH.CustomTLSFTPHandler
                # Asignar el cert y la key al handler
                handler.certfile = cert_file
                handler.keyfile = key_file
            else:
                messagebox.showerror("Error", "Certificado o clave privada no especificados")
                return
        else:
            handler = ftpH.CustomFTPHandler
            handler.certfile = None
            handler.keyfile = None
            handler.tls_control_required = False
            handler.tls_data_required = False

        handler.authorizer = authorizer
        handler.gui = self
        handler.ip_filter = self.ip_filter

        print(f"Iniciando el servidor en el puerto {self.port}")

        self.server = FTPServer(('0.0.0.0', self.port), handler)
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
