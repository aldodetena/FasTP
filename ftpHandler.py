from pyftpdlib.handlers import FTPHandler, TLS_FTPHandler
import json

class CustomFTPHandler(FTPHandler):
    """
    Clase para manejar conexiones FTP personalizadas. Incluye manejo de intentos de inicio de sesión fallidos y
    bloqueo de IPs basado en esos intentos. También proporciona un mecanismo para registrar eventos a través de una GUI.

    Atributos de clase:
    - gui: Referencia opcional a una GUI para registro de eventos.
    - ip_filter: Referencia a una instancia de IPFilter para manejar el bloqueo de IPs.
    - login_attempts: Diccionario para rastrear los intentos de inicio de sesión fallidos por IP.
    """
    gui = None  # Variable de clase para mantener la referencia a la GUI
    ip_filter = None  # Referencia a IPFilter
    login_attempts = {}  # Diccionario para rastrear los intentos fallidos

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
        """
        Acciones a realizar cuando un cliente se desconecta.
        """
        super().on_disconnect()
        CustomFTPHandler.handle_log(f"Cliente desconectado: {self.remote_ip}")
        if CustomFTPHandler.gui:
            CustomFTPHandler.gui.update_user_count(-1)

    def on_login_successful(self, username):
        """
        Acciones a realizar cuando un usuario inicia sesión exitosamente. Limpia los intentos de inicio de sesión fallidos.
        
        Args:
            username: Nombre de usuario del cliente que ha iniciado sesión.
        """
        ip = self.remote_ip
        if ip in CustomFTPHandler.login_attempts:
            del CustomFTPHandler.login_attempts[ip]
        CustomFTPHandler.handle_log(f"Inicio de sesión exitoso para {username}")

    def on_login_failed(self, username, password):
        """
        Acciones a realizar cuando un intento de inicio de sesión falla.
        
        Args:
            username: Nombre de usuario utilizado en el intento fallido.
            password: Contraseña utilizada en el intento fallido.
        """
        CustomFTPHandler.handle_log(f"Intento de inicio de sesión fallido para el usuario '{username}'")
        ip = self.remote_ip
        self.check_and_block_login_attempt(ip)

    def check_and_block_login_attempt(self, ip):
        """
        Verifica los intentos de inicio de sesión fallidos y bloquea la IP si supera el máximo permitido.
        
        Args:
            ip: Dirección IP del cliente.
            
        Returns:
            True si la IP ha sido bloqueada, False en caso contrario.
        """
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
        """
        Registra un mensaje. Si una GUI está disponible, lo registra allí. De lo contrario, lo imprime en la consola.
        
        Args:
            message: Mensaje a registrar.
        """
        # Maneja el registro de eventos, ya sea en la GUI o en el log estándar.
        if CustomFTPHandler.gui:
            CustomFTPHandler.gui.log_event(message)
        else:
            print(message)

class CustomTLSFTPHandler(TLS_FTPHandler, CustomFTPHandler):
    """
    Clase para manejar conexiones FTP seguras (TLS/SSL). Extiende CustomFTPHandler para agregar soporte TLS/SSL.

    Inicializa la conexión con requerimientos TLS para los canales de control y datos, asegurando una comunicación segura.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Requerir TLS para el control y/o los canales de datos
        self.tls_control_required = True
        self.tls_data_required = True