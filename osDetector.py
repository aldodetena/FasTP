# os_detector.py
import platform
import subprocess

def firewallConf():
    os_type = platform.system()
    try:
        if os_type == "Windows":
            subprocess.run(["powershell.exe", "configure_windows_firewall.ps1"], check=True)
        elif os_type == "Linux":
            subprocess.run(["/bin/bash", "configure_linux_firewall.sh"], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error al configurar el firewall: {e}")
