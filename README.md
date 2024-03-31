# FasTP

Este proyecto es un servidor FTP implementado en Python, que ofrece funcionalidades avanzadas como soporte TLS para conexiones seguras, bloqueo por dirección IP y limitación del número de sesiones simultáneas.

## Características

- **Soporte TLS**: Asegura las conexiones entre el cliente y el servidor utilizando TLS.
- **Bloqueo por IP**: Permite bloquear direcciones IP específicas para mejorar la seguridad.
- **Límite de Sesión**: Limita el número de sesiones simultáneas para optimizar los recursos del servidor.

## Requisitos

- Python 3.6 o superior.
- [pyftpdlib](https://github.com/giampaolo/pyftpdlib): Una biblioteca de Python para construir servidores FTP.
- Certificados SSL/TLS para el soporte de TLS (opcional).
- Tkinter (puede ser que ya venga preinstalador en algunas distros de Linux)

## Instalación

Primero, clona el repositorio e instala las dependencias necesarias:

```bash
git clone <url_del_repositorio>
cd <directorio_del_repositorio>
pip install pyftpdlib
```

## Uso

Para iniciar el servidor FTP, ejecuta:

```bash
python ftpd.py
```

## Para generar los archivos de documentación con pdoc3 en html

Los archivos python tiene el código comentado con docStrings para poder generar archivos de documentación
para poder instalar pdoc3 y usarlo para generar los html, ejecuta:

```bash
pip install pdoc3
pdoc --html <archivo .py del repositorio>
```

Si quieres generar varios archivos al mismo tiempo y en la misma carpeta, ejecuta:

```bash
pdoc --html <archivo .py del repositorio> <archivo .py del repositorio> etc
```

Si quieres empaquetar la aplicación, tienes varias alternativas, de todas formas puede llegar a ser algo tedioso,
personalmente probé pyinstaller para windows, pero tienes que tener bien configurado el entorno y tiene que ser ejecutado en windows,
también probé dpkg para crear un deb, para ubuntu, es un poco mas sencillo que windows pero también lo complica un poco.

Igualmente recomiendo no empaquetarla dado que no esta suficientemente testeado estas soluciones.

## Creación de un archivo ejecutable

### Para Windows (.exe)

Si deseas crear un archivo .exe para Windows, puedes usar PyInstaller:

```bash
pip install pyinstaller
pyinstaller --onefile ftpd.py
```
El ejecutable se encontrará en el directorio dist.

### Para Debian/Ubuntu (.deb)

Para empaquetar la aplicación en un archivo `.deb`, sigue estos pasos:

1. Crea la estructura de directorios necesaria para tu paquete:

```bash
mkdir -p mi-aplicacion-deb/DEBIAN
mkdir -p mi-aplicacion-deb/usr/local/bin
```

2. Crea un archivo de control dentro del directorio DEBIAN con la metadata de tu paquete:

```bash
Copy code
Package: mi-aplicacion
Version: 1.0.0
Architecture: all
Maintainer: Tu Nombre <tu.email@example.com>
Description: Una breve descripción de tu aplicación.
```

3. Copia los archivos de tu aplicación al directorio correspondiente dentro de la estructura de directorios creada. Asegúrate de que tu script o ejecutable esté en mi-aplicacion-deb/usr/local/bin.

4. Desde la terminal, navega al directorio que contiene mi-aplicacion-deb y ejecuta el comando:

```bash
dpkg-deb --build mi-aplicacion-deb
```

Esto generará un archivo .deb que puede ser instalado en sistemas Debian/Ubuntu.

Recuerda adaptar las instrucciones específicamente a los nombres correctos de archivos y directorios.