from pyftpdlib.handlers import FTPHandler
import time
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
    block_time = config['block_time_seconds']

    def on_connect(self):
    # Primero, verifica si la IP está bloqueada
        if CustomFTPHandler.ip_filter and CustomFTPHandler.ip_filter.is_blocked(self.remote_ip):
            self.log("Conexión bloqueada: " + self.remote_ip)
            self.close_when_done()
            return

        # Luego, verifica los intentos de inicio de sesión fallidos
        if not self.check_login_attempt(self.remote_ip):
            self.log("Bloqueado por demasiados intentos fallidos: " + self.remote_ip)
            self.close_when_done()
        else:
            super().on_connect()
            if CustomFTPHandler.gui:
                CustomFTPHandler.gui.log_event(f"Cliente conectado: {self.remote_ip}")
                CustomFTPHandler.gui.update_user_count(1)

    def on_disconnect(self):
        super().on_disconnect()
        if CustomFTPHandler.gui:
            CustomFTPHandler.gui.log_event(f"Cliente desconectado: {self.remote_ip}")
            CustomFTPHandler.gui.update_user_count(-1)

    def on_login_failed(self, username, password):
        ip = self.remote_ip
        attempts, last_attempt_time = CustomFTPHandler.login_attempts.get(ip, [0, time.time()])
        if time.time() - last_attempt_time > CustomFTPHandler.block_time:
            attempts = 0
        CustomFTPHandler.login_attempts[ip] = [attempts + 1, time.time()]
        if attempts >= CustomFTPHandler.max_attempts:
            self.log("Demasiados intentos fallidos: " + ip)
            self.close_when_done()

    def check_login_attempt(self, ip):
        attempts, last_attempt_time = CustomFTPHandler.login_attempts.get(ip, [0, time.time()])
        if attempts >= CustomFTPHandler.max_attempts and time.time() - last_attempt_time < CustomFTPHandler.block_time:
            return False
        return True