# ftpd_server.py
import threading
import time
import tkinter as tk
import ftpHandler as ftpH
import tlsFtpHandler as sftpH
import ipFilter
from optionsFrame import OptionsFrame
from tkinter import messagebox
from tkinter import filedialog
from threading import Thread
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.servers import FTPServer

class FTPServerGUI:
    """
    Representa la interfaz gráfica de usuario (GUI) para un servidor FTP, permitiendo controlar
    el inicio y detención del servidor, así como la configuración de diversas opciones.

    Attributes:
        root (tk.Tk): La ventana principal de la aplicación.
        ip_filter (IPFilter): Instancia de IPFilter para el manejo del bloqueo de IPs.
        server_frame (tk.Frame): El marco principal que contiene los controles del servidor.
        port (int): El puerto en el que el servidor escucha.
        user_count (int): Contador de usuarios conectados actualmente.
        log_text (tk.Text): Área de texto para mostrar los registros de eventos.
        server (FTPServer): La instancia del servidor FTP en ejecución.
        server_thread (Thread): El hilo en el que se ejecuta el servidor FTP.
    """
    def __init__(self, root):
        """
        Inicializa la GUI del servidor FTP, configurando la ventana principal y los elementos de la GUI.

        Args:
            root (tk.Tk): La ventana principal de la aplicación.
        """
        self.root = root
        root.title("FasTP")
        # Inicializa IPFilter
        self.ip_filter = ipFilter.IPFilter('blocked_ips')

        # Marco para la configuración general del servidor
        self.server_frame = tk.Frame(root)
        self.server_frame.pack(fill=tk.BOTH, expand=True)

        self.port = 45000 # Puerto Predeterminado
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
        self.menu_frame.pack(side=tk.TOP, fill=tk.X, pady=5)

        # Botón de opciones
        self.options_button = tk.Button(self.menu_frame, text="Opciones", command=self.show_options, width=15)
        self.options_button.pack(side=tk.BOTTOM)

        self.server = None
        self.server_thread = None

    def show_options(self):
        """Muestra el marco de opciones para la configuración avanzada del servidor."""
        self.server_frame.pack_forget()
        self.options_frame.pack(fill=tk.BOTH, expand=True)

    def show_server(self):
        """Vuelve a mostrar el marco del servidor, ocultando las opciones avanzadas."""
        self.options_frame.pack_forget()
        self.server_frame.pack(fill=tk.BOTH, expand=True)

    def log_event(self, message):
        """Registra un mensaje en el área de texto de registro de la GUI.

        Args:
            message (str): El mensaje a registrar.
        """
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state='disabled')
        self.log_text.yview(tk.END)
    
    def select_directory(self):
        """Abre un diálogo para que el usuario seleccione el directorio raíz del servidor FTP."""
        directory = filedialog.askdirectory()
        if directory:
            self.directory_entry.delete(0, tk.END)
            self.directory_entry.insert(0, directory)

    def update_user_count(self, change):
        """
        Actualiza el contador de usuarios conectados.

        Args:
            change (int): El cambio en el número de usuarios (positivo para incrementar, negativo para decrementar).
        """
        self.user_count += change
        # Asegurarse de que el contador no sea menor que cero
        if self.user_count < 0:
            self.user_count = 0
        self.user_count_label.config(text=f"Usuarios conectados: {self.user_count}")

    def clear_log(self):
        """Limpia el área de texto que muestra los registros de eventos."""
        self.log_text.config(state='normal')
        self.log_text.delete('1.0', tk.END)  # Eliminar todo el texto desde el principio hasta el final
        self.log_text.config(state='disabled')

    def reload_ips_periodically(self):
        """Recarga periódicamente la lista de IPs bloqueadas desde el archivo."""
        while True:
            try:
                self.ip_filter.reload_blocked_ips()
                self.log_event("Lista de IPs actualizada correctamente")
            except Exception as e:
                self.log_event(f"Error al recargar las IPs: {e}")
            time.sleep(60)

    def change_port(self, new_port):
        """
        Cambia el puerto en el que el servidor debe escuchar.

        Args:
            new_port (int): El nuevo puerto para el servidor.
        """
        self.port = new_port

    def start_server(self):
        """Inicia el servidor FTP en un hilo separado."""
        username = self.options_frame.get_username()
        password = self.options_frame.get_password()
        directory = self.options_frame.get_directory()
        port_str = self.options_frame.port_entry.get()

        self.user_count = 0
        self.update_user_count(0)
        self.clear_log()

        if not (username and password and directory):
            messagebox.showerror("Error", "Todos los campos son obligatorios")
            return
        
        if port_str:  # Si el usuario ha ingresado algo...
            try:
                port = int(port_str)
                if 1 <= port <= 65535:
                    self.port = port
                else:
                    messagebox.showerror("Error", "El número de puerto debe estar entre 1 y 65535.")
                    return
            except ValueError:
                messagebox.showerror("Error", f"Entrada no válida para el puerto: '{port_str}'. Por favor, introduce un número entre 1 y 65535.")
                return

        authorizer = DummyAuthorizer()
        authorizer.add_user(username, password, directory, perm="elradfmw")
        handler = None

        if self.options_frame.is_tls_enabled():
            cert_file = self.options_frame.get_tls_cert_file()
            key_file = self.options_frame.get_tls_key_file()
            self.ip_filter.set_login_attempts(sftpH.CustomTLSFTPHandler.login_attempts)

            if cert_file and key_file:
                handler = sftpH.CustomTLSFTPHandler
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
            self.ip_filter.set_login_attempts(ftpH.CustomFTPHandler.login_attempts)

        handler.authorizer = authorizer
        handler.gui = self
        handler.ip_filter = self.ip_filter

        self.log_event(f"Iniciando el servidor en el puerto {self.port}")

        self.server = FTPServer(('0.0.0.0', self.port), handler)
        self.server_thread = Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True
        self.server_thread.start()

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Estado: En ejecución")
        
    def stop_server(self):
        """Detiene el servidor FTP y limpia los recursos."""
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
