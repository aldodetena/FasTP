from pyftpdlib.handlers import TLS_FTPHandler
import json

class CustomTLSFTPHandler(TLS_FTPHandler):
    """
    Clase para manejar conexiones FTP seguras (TLS/SSL). Incluye manejo de intentos de inicio de sesión fallidos y
    bloqueo de IPs basado en esos intentos. También proporciona un mecanismo para registrar eventos a través de una GUI.

    Atributos de clase:
    - gui: Referencia opcional a una GUI para registro de eventos.
    - ip_filter: Referencia a una instancia de IPFilter para manejar el bloqueo de IPs.
    - login_attempts: Diccionario para rastrear los intentos de inicio de sesión fallidos por IP.
    """
    gui = None  # Variable de clase para mantener la referencia a la GUI
    ip_filter = None  # Referencia a IPFilter
    login_attempts = {}  # Diccionario para rastrear los intentos fallidos
    tls_control_required = True
    tls_data_required = True

    def load_config(filename):
        """
        Carga la configuración del servidor FTP desde un archivo JSON. Si el archivo
        no se encuentra, retorna configuraciones predeterminadas.

        Args:
            filename (str): Ruta al archivo de configuración JSON.

        Returns:
            dict: Un diccionario con la configuración cargada. Retorna configuraciones
                predeterminadas si el archivo config.json no se encuentra. Por defecto,
                establece el máximo de intentos de inicio de sesión fallidos a 3.
        """
        try:
            with open(filename, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            # Retorna configuraciones predeterminadas si config.json no se encuentra
            return {"max_login_attempts": 3}

    config = load_config('config.json')
    max_attempts = config['max_login_attempts']

    def on_connect(self):
        """
        Acciones a realizar cuando un cliente se conecta. Verifica si la IP está bloqueada.
        """
        # Primero, verifica si la IP está bloqueada
        if CustomTLSFTPHandler.ip_filter and CustomTLSFTPHandler.ip_filter.is_blocked(self.remote_ip):
            CustomTLSFTPHandler.handle_log("Conexión bloqueada: " + self.remote_ip)
            self.close_when_done()
            return

        # Verifica los intentos de inicio de sesión fallidos y bloquea si es necesario
        if self.check_and_block_login_attempt(self.remote_ip):
            CustomTLSFTPHandler.handle_log("Bloqueado por demasiados intentos fallidos: " + self.remote_ip)
            self.close_when_done()
            return
        else:
            super().on_connect()
            CustomTLSFTPHandler.handle_log(f"Cliente conectado: {self.remote_ip}")
            if CustomTLSFTPHandler.gui:
                CustomTLSFTPHandler.gui.update_user_count(1)

    def on_disconnect(self):
        """
        Acciones a realizar cuando un cliente se desconecta.
        """
        super().on_disconnect()
        CustomTLSFTPHandler.handle_log(f"Cliente desconectado: {self.remote_ip}")
        if CustomTLSFTPHandler.gui:
            CustomTLSFTPHandler.gui.update_user_count(-1)

    def on_login(self, username):
        """
        Acciones a realizar cuando un usuario inicia sesión exitosamente. Limpia los intentos de inicio de sesión fallidos.
        
        Args:
            username: Nombre de usuario del cliente que ha iniciado sesión.
        """
        ip = self.remote_ip
        if ip in CustomTLSFTPHandler.login_attempts:
            del CustomTLSFTPHandler.login_attempts[ip]
        CustomTLSFTPHandler.handle_log(f"Inicio de sesión exitoso para {username}")

    def on_login_failed(self, username, password):
        """
        Acciones a realizar cuando un intento de inicio de sesión falla.
        
        Args:
            username: Nombre de usuario utilizado en el intento fallido.
            password: Contraseña utilizada en el intento fallido.
        """
        CustomTLSFTPHandler.handle_log(f"Intento de inicio de sesión fallido para el usuario '{username}'")

    def check_and_block_login_attempt(self, ip):
        """
        Verifica los intentos de inicio de sesión fallidos y bloquea la IP si supera el máximo permitido.
        
        Args:
            ip: Dirección IP del cliente.
            
        Returns:
            True si la IP ha sido bloqueada, False en caso contrario.
        """
        attempts = CustomTLSFTPHandler.login_attempts.get(ip, [0])[0]
        attempts += 1
        CustomTLSFTPHandler.login_attempts[ip] = [attempts]

        if attempts > CustomTLSFTPHandler.max_attempts:
            if CustomTLSFTPHandler.ip_filter.add_ip(ip):
                CustomTLSFTPHandler.handle_log(f"IP {ip} bloqueada permanentemente por demasiados intentos fallidos.")
                return True
        return False
    
    @staticmethod
    def handle_log(message):
        """
        Registra un mensaje. Si una GUI está disponible, lo registra allí. De lo contrario, lo imprime en la consola.
        
        Args:
            message: Mensaje a registrar.
        """
        # Maneja el registro de eventos, ya sea en la GUI o en el log estándar.
        if CustomTLSFTPHandler.gui:
            CustomTLSFTPHandler.gui.log_event(message)
        else:
            print(message)