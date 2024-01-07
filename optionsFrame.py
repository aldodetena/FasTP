import tkinter as tk
import ipFilter
from tkinter import messagebox
from tkinter import filedialog

class OptionsFrame(tk.Frame):
    def __init__(self, master, **kwargs):
        # Extrae 'show_server_callback' de kwargs
        self.show_server_callback = kwargs.pop('show_server_callback', None)

        super().__init__(master, **kwargs)

        self.ip_filter = ipFilter.IPFilter('blocked_ips')  # 'blocked_ips.ipf' será el archivo utilizado

        self.tls_var = tk.BooleanVar()
        self.tls_checkbox = tk.Checkbutton(self, text="Activar TLS", variable=self.tls_var, command=self.on_tls_checkbox)
        self.tls_checkbox.pack()

        # Botón para gestionar IPs
        self.ip_manage_button = tk.Button(self, text="Gestionar IPs", command=self.open_ip_manage_popup)
        self.ip_manage_button.pack()

        # Campo para la ruta del certificado
        self.cert_file_entry = tk.Entry(self)
        self.cert_file_entry.pack()
        self.cert_file_button = tk.Button(self, text="Seleccionar Certificado", command=lambda: self.on_select_file('cert'))
        self.cert_file_button.pack()

        # Campo para la ruta de la clave privada
        self.key_file_entry = tk.Entry(self)
        self.key_file_entry.pack()
        self.key_file_button = tk.Button(self, text="Seleccionar Clave Privada", command=lambda: self.on_select_file('key'))
        self.key_file_button.pack()

        # Botón para volver al frame principal
        if self.show_server_callback:
            self.back_button = tk.Button(self, text="Volver al Servidor", command=self.show_server_callback)
            self.back_button.pack()

    def on_tls_checkbox(self):
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
    
    def is_tls_enabled(self):
        return self.tls_var.get()

    def get_tls_cert_file(self):
        return self.cert_file_entry.get()

    def get_tls_key_file(self):
        return self.key_file_entry.get()

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
        self.popup = tk.Toplevel(self)
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