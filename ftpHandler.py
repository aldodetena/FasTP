from pyftpdlib.handlers import FTPHandler
import time

class CustomFTPHandler(FTPHandler):
    gui = None  # Variable de clase para mantener la referencia a la GUI
    login_attempts = {}  # Diccionario para rastrear los intentos fallidos

    def on_connect(self):
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
        if time.time() - last_attempt_time > 600:  # 10 minutos para restablecer el conteo
            attempts = 0
        CustomFTPHandler.login_attempts[ip] = [attempts + 1, time.time()]
        if attempts >= 3:  # Número máximo de intentos
            self.log("Demasiados intentos fallidos: " + ip)
            self.close_when_done()

    def check_login_attempt(self, ip):
        attempts, last_attempt_time = CustomFTPHandler.login_attempts.get(ip, [0, time.time()])
        if attempts >= 3 and time.time() - last_attempt_time < 600:  # Bloqueo si supera los intentos
            return False
        return True