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
)

# Usuario anónimo (opcional)
# authorizer.add_anonymous(FTP_DIR, perm="elr")

# Configurar handler
handler = FTPHandler
handler.authorizer = authorizer

# Banner personalizado
handler.banner = "Test FTP Server - Ready"

# Iniciar servidor
def run_ftp_server():
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