from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
import json

class CustomFTPHandler(FTPHandler):
    gui = None  # Variable de clase para mantener la referencia a la GUI
    ip_filter = None  # Referencia a IPFilter
    login_attempts = {}  # Diccionario para rastrear los intentos fallidos

    def load_config(filename):
        with open(filename, 'r') as file:
            return json.load(file)

    config = load_config('config.json')
    max_attempts = config['max_login_attempts']

    def on_connect(self):
        # Primero, verifica si la IP está bloqueada
        if CustomFTPHandler.ip_filter and CustomFTPHandler.ip_filter.is_blocked(self.remote_ip):
            CustomFTPHandler.handle_log("Conexión bloqueada: " + self.remote_ip)
            self.close_when_done()
            return

        # Verifica los intentos de inicio de sesión fallidos y bloquea si es necesario
        if self.check_and_block_login_attempt(self.remote_ip):
            CustomFTPHandler.handle_log("Bloqueado por demasiados intentos fallidos: " + self.remote_ip)
            self.close_when_done()
            return
        else:
            super().on_connect()
            CustomFTPHandler.handle_log(f"Cliente conectado: {self.remote_ip}")
            if CustomFTPHandler.gui:
                CustomFTPHandler.gui.update_user_count(1)

    def on_disconnect(self):
        super().on_disconnect()
        CustomFTPHandler.handle_log(f"Cliente desconectado: {self.remote_ip}")
        if CustomFTPHandler.gui:
            CustomFTPHandler.gui.update_user_count(-1)

    def on_login_failed(self, username, password):
        CustomFTPHandler.handle_log(f"Intento de inicio de sesión fallido para el usuario '{username}'")
        ip = self.remote_ip
        self.check_and_block_login_attempt(ip)

    def check_and_block_login_attempt(self, ip):
        attempts = CustomFTPHandler.login_attempts.get(ip, [0])[0]
        attempts += 1
        CustomFTPHandler.login_attempts[ip] = [attempts]

        if attempts >= CustomFTPHandler.max_attempts:
            if CustomFTPHandler.ip_filter.add_ip(ip):
                CustomFTPHandler.handle_log(f"IP {ip} bloqueada permanentemente por demasiados intentos fallidos.")
                return True
        return False
    
    @staticmethod
    def handle_log(message):
        # Maneja el registro de eventos, ya sea en la GUI o en el log estándar.
        if CustomFTPHandler.gui:
            CustomFTPHandler.gui.log_event(message)
        else:
            print(message)

class CustomTLSFTPHandler(TLS_FTPHandler, CustomFTPHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Requerir TLS para el control y/o los canales de datos
        self.tls_control_required = True
        self.tls_data_required = True