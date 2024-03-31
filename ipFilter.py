import ipaddress
import os

class IPFilter:
    """
    Gestiona el bloqueo y desbloqueo de direcciones IP, proporcionando métodos
    para añadir y eliminar IPs de una lista de bloqueo persistida en un archivo.

    Attributes:
        filename (str): Nombre del archivo donde se guardan las IPs bloqueadas.
        login_attempts (dict): Un diccionario que rastrea los intentos de inicio de sesión fallidos por IP.
        blocked_ips (list): Lista de IPs bloqueadas cargadas desde el archivo.
    """
    def __init__(self, filename, login_attempts=None):
        """
        Inicializa el filtro de IP.

        Args:
            filename (str): Nombre base para el archivo de IPs bloqueadas.
            login_attempts (dict): Diccionario para rastrear intentos de inicio de sesión fallidos.
        """
        self.filename = filename + ".ipf"
        self.login_attempts = login_attempts
        if not os.path.exists(self.filename):
            # Si el archivo no existe, créalo
            open(self.filename, 'a').close()
        self.blocked_ips = self.load_blocked_ips()

    def reload_blocked_ips(self):
        """Recarga la lista de IPs bloqueadas desde el archivo."""
        new_blocked_ips = self.load_blocked_ips()
        if new_blocked_ips != self.blocked_ips:
            self.blocked_ips = new_blocked_ips

    def is_valid_ip(self, ip):
        """
        Verifica si una cadena es una dirección IP válida.

        Args:
            ip (str): La dirección IP a verificar.

        Returns:
            bool: True si es una IP válida, False en caso contrario.
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def add_ip(self, ip):
        """
        Añade una dirección IP a la lista de bloqueo si no está ya presente.

        Args:
            ip (str): La dirección IP a añadir.

        Returns:
            bool: True si la IP se añadió, False si ya estaba en la lista.
        """
        if self.is_valid_ip(ip) and ip not in self.blocked_ips:
            self.blocked_ips.append(ip)
            self.save_blocked_ips()
            return True
        return False

    def remove_ip(self, ip):
        """
        Elimina una dirección IP de la lista de bloqueo.

        Args:
            ip (str): La dirección IP a eliminar.

        Returns:
            bool: True si la IP se eliminó, False si no estaba en la lista.
        """
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self.save_blocked_ips()
            # Eliminar también los intentos fallidos si existen
            self.login_attempts.pop(ip, None)
            return True
        return False

    def is_blocked(self, ip):
        """
        Verifica si una dirección IP está en la lista de bloqueo.

        Args:
            ip (str): La dirección IP a verificar.

        Returns:
            bool: True si la IP está bloqueada, False en caso contrario.
        """
        return ip in self.blocked_ips

    def load_blocked_ips(self):
        """Carga las IPs bloqueadas desde el archivo.

        Returns:
            list: Una lista de direcciones IP bloqueadas.
        """
        try:
            with open(self.filename, 'r') as file:
                return file.read().splitlines()
        except FileNotFoundError:
            return []
        
    def set_login_attempts(self, login_attempts):
        """Establece o actualiza el diccionario de intentos de inicio de sesión fallidos.

        Args:
            login_attempts (dict): Un diccionario que rastrea los intentos de inicio de sesión fallidos por IP.
        """
        self.login_attempts = login_attempts

    def save_blocked_ips(self):
        """Guarda la lista actualizada de IPs bloqueadas en el archivo."""
        try:
            with open(self.filename, 'w') as file:
                for ip in self.blocked_ips:
                    file.write(ip + '\n')
        except IOError as e:
            print(f"Error al guardar las IPs bloqueadas: {e}")