import ipaddress
import threading
import os

class IPFilter:
    def __init__(self, filename):
        self.filename = filename + ".ipf"
        if not os.path.exists(self.filename):
            # Si el archivo no existe, créalo
            open(self.filename, 'a').close()
        self.blocked_ips = self.load_blocked_ips()

    def reload_blocked_ips(self):
        """Método para recargar la lista de IPs bloqueadas desde el archivo."""
        new_blocked_ips = self.load_blocked_ips()
        if new_blocked_ips != self.blocked_ips:
            self.blocked_ips = new_blocked_ips

    def is_valid_ip(self, ip):
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def add_ip(self, ip):
        if self.is_valid_ip(ip) and ip not in self.blocked_ips:
            self.blocked_ips.append(ip)
            self.save_blocked_ips()
            return True
        return False

    def remove_ip(self, ip):
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
            self.save_blocked_ips()
            return True
        return False

    def is_blocked(self, ip):
        return ip in self.blocked_ips

    def load_blocked_ips(self):
        try:
            with open(self.filename, 'r') as file:
                return file.read().splitlines()
        except FileNotFoundError:
            return []

    def save_blocked_ips(self):
        try:
            with open(self.filename, 'w') as file:
                for ip in self.blocked_ips:
                    file.write(ip + '\n')
        except IOError as e:
            print(f"Error al guardar las IPs bloqueadas: {e}")