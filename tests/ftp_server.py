"""
Project developed as part of the Trabajo de Fin de Grado (TFG)
Grado en Ingeniería Informática - UNIR

Author: angelopezg3
Year: 2026
License: MIT

Servidor FTP de pruebas
"""

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

# Configuración
FTP_HOST = "0.0.0.0"  # Escucha en todas las interfaces
FTP_PORT = 21
FTP_USER = "test"
FTP_PASS = "1234"
FTP_DIR = "./ftp_folder"  # Carpeta compartida

# Crear carpeta si no existe
import os
os.makedirs(FTP_DIR, exist_ok=True)

# Configurar autenticación
authorizer = DummyAuthorizer()

# Añadir usuario con permisos
authorizer.add_user(
    username=FTP_USER,
    password=FTP_PASS,
    homedir=FTP_DIR,
    perm="elradfmwMT"  # Todos los permisos
    # Permisos FTP:
    # e = cambiar de directorio (CWD)
    # l = listar archivos y directorios (LIST, NLST)
    # r = descargar / leer archivos (RETR)
    # a = añadir datos a archivos existentes (APPE)
    # d = borrar archivos o directorios (DELE, RMD)
    # f = renombrar archivos (RNFR, RNTO)
    # m = crear directorios (MKD)
    # w = subir / escribir archivos (STOR)
    # M = cambiar permisos de archivos (SITE CHMOD)
    # T = modificar timestamps de archivos (SITE MFMT)
)

# Configurar handler
handler = FTPHandler
handler.authorizer = authorizer

# Banner personalizado
handler.banner = "Test FTP Server - Ready"


def run_ftp_server():
    """
    Iniciar servidor
    """
    server = FTPServer((FTP_HOST, FTP_PORT), handler)
    server.max_cons = 3
    server.max_cons_per_ip = 5

    print(f" FTP Server iniciado en ftp://{FTP_HOST}:{FTP_PORT}")
    print(f" Carpeta: {os.path.abspath(FTP_DIR)}")
    print(f" Usuario: {FTP_USER}")
    print(f" Password: {FTP_PASS}")
    print("Presiona Ctrl+C para detener\n")

    server.serve_forever()

if __name__ == '__main__':
    run_ftp_server()