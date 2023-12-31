from pyftpdlib.handlers import FTPHandler

class CustomFTPHandler(FTPHandler):
    gui = None  # Variable de clase para mantener la referencia a la GUI

    def on_connect(self):
        super().on_connect()
        if CustomFTPHandler.gui:
            CustomFTPHandler.gui.log_event(f"Cliente conectado: {self.remote_ip}")
            CustomFTPHandler.gui.update_user_count(1)

    def on_disconnect(self):
        super().on_disconnect()
        if CustomFTPHandler.gui:
            CustomFTPHandler.gui.log_event(f"Cliente desconectado: {self.remote_ip}")
            CustomFTPHandler.gui.update_user_count(-1)