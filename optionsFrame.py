import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog

class OptionsFrame(tk.Frame):
    """
    Un marco de Tkinter que proporciona una interfaz para configurar las opciones del servidor FTP.

    Permite al usuario ingresar credenciales de usuario, seleccionar directorios, gestionar IPs bloqueadas,
    configurar TLS y elegir archivos de certificado y clave privada.

    Attributes:
        show_server_callback (function): Función para volver a la vista del servidor principal.
        ip_filter (IPFilter): Instancia para gestionar el filtrado de IPs.
        parent: El contenedor padre para este frame.
    """
    def __init__(self, master, parent, ip_filter, **kwargs):
        """
        Inicializa la instancia de OptionsFrame.

        Args:
            master: Widget padre.
            parent: Contenedor padre para este frame.
            ip_filter (IPFilter): Instancia de IPFilter para gestionar IPs bloqueadas.
            **kwargs: Argumentos de palabra clave adicionales.
        """
        # Extrae 'show_server_callback' de kwargs
        self.show_server_callback = kwargs.pop('show_server_callback', None)
        self.ip_filter = ip_filter
        self.parent = parent
        super().__init__(master, **kwargs)

        # Crea el Notebook (contenedor de pestañas)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill="both")

        # Crea el Frame para opciones básicas
        self.basic_options_frame = tk.Frame(self.notebook)
        self.notebook.add(self.basic_options_frame, text='Opciones Básicas')

        tk.Label(self.basic_options_frame, text="Usuario:").pack()
        self.username_entry = tk.Entry(self.basic_options_frame)
        self.username_entry.pack()

        tk.Label(self.basic_options_frame, text="Contraseña:").pack()
        self.password_entry = tk.Entry(self.basic_options_frame, show="*")
        self.password_entry.pack()

        # Opción para cambiar el puerto
        tk.Label(self.basic_options_frame, text="Puerto:").pack()
        self.port_entry = tk.Entry(self.basic_options_frame)
        self.port_entry.pack(pady=5)

        tk.Label(self.basic_options_frame, text="Directorio:").pack()
        self.directory_entry = tk.Entry(self.basic_options_frame)
        self.directory_entry.pack(pady=5)

        self.directory_button = tk.Button(self.basic_options_frame, text="Seleccionar Directorio", command=self.select_directory, width=20)
        self.directory_button.pack(pady=5)

        # Crea el Frame para opciones avanzadas
        self.advanced_options_frame = tk.Frame(self.notebook)
        self.notebook.add(self.advanced_options_frame, text='Opciones Avanzadas')

        # Botón para gestionar IPs
        self.ip_manage_button = tk.Button(self.advanced_options_frame, text="Gestionar IPs", command=self.open_ip_manage_popup, width=20)
        self.ip_manage_button.pack(pady=5)

        # Campo para la ruta del certificado
        self.cert_file_entry = tk.Entry(self.advanced_options_frame)
        self.cert_file_entry.pack()
        self.cert_file_button = tk.Button(self.advanced_options_frame, text="Seleccionar Certificado", command=lambda: self.on_select_file('cert'), width=20)
        self.cert_file_button.pack(pady=5)

        # Campo para la ruta de la clave privada
        self.key_file_entry = tk.Entry(self.advanced_options_frame)
        self.key_file_entry.pack()
        self.key_file_button = tk.Button(self.advanced_options_frame, text="Seleccionar Clave Privada", command=lambda: self.on_select_file('key'), width=20)
        self.key_file_button.pack(pady=5)

        self.tls_var = tk.BooleanVar()
        self.tls_checkbox = tk.Checkbutton(self.advanced_options_frame, text="Activar TLS", variable=self.tls_var, command=self.on_tls_checkbox)
        self.tls_checkbox.pack(pady=5)

        # Botón para volver al frame principal
        if self.show_server_callback:
            self.back_button = tk.Button(self, text="Volver al Servidor", command=self.show_server_callback)
            self.back_button.pack()
    
    def select_directory(self):
        """
        Abre un diálogo para que el usuario seleccione un directorio.
        Actualiza la entrada del directorio con el directorio seleccionado.
        """
        directory = filedialog.askdirectory()
        if directory:
            self.directory_entry.delete(0, tk.END)
            self.directory_entry.insert(0, directory)

    def on_tls_checkbox(self):
        """
        Habilita o deshabilita la entrada de archivos de certificado y clave privada
        basado en el estado del checkbox de TLS.
        """
        if self.tls_var.get():
            # Activar TLS
            self.cert_file_entry.config(state='normal')
            self.cert_file_button.config(state='normal')
            self.key_file_entry.config(state='normal')
            self.key_file_button.config(state='normal')
        else:
            # Desactivar TLS
            self.cert_file_entry.config(state='disabled')
            self.cert_file_button.config(state='disabled')
            self.key_file_entry.config(state='disabled')
            self.key_file_button.config(state='disabled')

    def on_select_file(self, file_type):
        """
        Abre un diálogo para que el usuario seleccione un archivo de certificado o clave privada.

        Args:
            file_type (str): 'cert' para certificado, 'key' para clave privada.
        """
        file_path = filedialog.askopenfilename(
            title=f"Seleccionar {'Certificado' if file_type == 'cert' else 'Clave Privada'}",
            filetypes=[("Certificados y Clave Privada", ".crt .key"), ("Todos los archivos", "*.*")]
        )
        if file_path:
            if file_type == 'cert':
                self.cert_file_entry.delete(0, tk.END)
                self.cert_file_entry.insert(0, file_path)
            elif file_type == 'key':
                self.key_file_entry.delete(0, tk.END)
                self.key_file_entry.insert(0, file_path)

    def open_ip_manage_popup(self):
        """
        Abre una ventana emergente para gestionar las IPs bloqueadas.
        Permite al usuario añadir o eliminar IPs de la lista de bloqueo.
        """
        self.popup = tk.Toplevel(self)
        self.popup.title("Gestión de IPs")

        # Sección para añadir IP
        tk.Label(self.popup, text="Añadir IP:").pack()
        self.add_ip_entry = tk.Entry(self.popup)
        self.add_ip_entry.pack(pady=5)
        add_ip_button = tk.Button(self.popup, text="Añadir", command=self.add_ip_to_filter)
        add_ip_button.pack(pady=5)

        # Sección para mostrar y eliminar IPs bloqueadas
        tk.Label(self.popup, text="IPs Bloqueadas:").pack()
        self.blocked_ips_listbox = tk.Listbox(self.popup)
        self.blocked_ips_listbox.pack(pady=5)
        self.update_blocked_ips_listbox()

        remove_ip_button = tk.Button(self.popup, text="Eliminar IP Seleccionada", command=self.remove_selected_ip)
        remove_ip_button.pack()

    def add_ip_to_filter(self):
        """
        Añade la IP introducida por el usuario a la lista de IPs bloqueadas.
        """
        ip_to_add = self.add_ip_entry.get()
        if self.ip_filter.add_ip(ip_to_add):
            self.update_blocked_ips_listbox()
        else:
            messagebox.showerror("Error", "Dirección IP no válida o ya añadida.")

    def remove_selected_ip(self):
        """
        Elimina la IP seleccionada por el usuario de la lista de IPs bloqueadas.
        """
        selected_indices = self.blocked_ips_listbox.curselection()
        if selected_indices:
            selected_ip = self.blocked_ips_listbox.get(selected_indices[0])
            if self.ip_filter.remove_ip(selected_ip):
                self.update_blocked_ips_listbox()
            else:
                messagebox.showerror("Error", "La dirección IP no se encuentra en la lista.")

    def update_blocked_ips_listbox(self):
        """
        Actualiza la lista de IPs bloqueadas mostrada en la interfaz de usuario.
        """
        self.blocked_ips_listbox.delete(0, tk.END)  # Limpiar lista actual
        for ip in self.ip_filter.blocked_ips:
            self.blocked_ips_listbox.insert(tk.END, ip)  # Añadir IPs a la lista

    def is_tls_enabled(self):
        """
        Devuelve el estado actual del checkbox de TLS.

        Returns:
            bool: True si TLS está habilitado, False en caso contrario.
        """
        return self.tls_var.get()

    def get_tls_cert_file(self):
        """
        Devuelve la ruta del archivo de certificado seleccionado.

        Returns:
            str: Ruta del archivo de certificado.
        """
        return self.cert_file_entry.get()

    def get_tls_key_file(self):
        """
        Devuelve la ruta del archivo de clave privada seleccionado.

        Returns:
            str: Ruta del archivo de clave privada.
        """
        return self.key_file_entry.get()

    def get_username(self):
        """
        Obtiene el nombre de usuario introducido por el usuario.

        Returns:
            str: El nombre de usuario introducido.
        """
        return self.username_entry.get()

    def get_password(self):
        """
        Obtiene la contraseña introducida por el usuario.

        Returns:
            str: La contraseña introducida.
        """
        return self.password_entry.get()

    def get_directory(self):
        """
        Obtiene el directorio seleccionado por el usuario.

        Returns:
            str: El directorio seleccionado.
        """
        return self.directory_entry.get()