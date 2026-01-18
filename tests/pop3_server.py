import socket
import threading
import sys
from datetime import datetime

# --- CONFIGURACIÓN DEL SERVIDOR ---
HOST = '0.0.0.0'
PORT = 110
# Credenciales Fijas para la prueba
VALID_USER = "test_user_pop3"
VALID_PASS = "test_pass_123"


# ----------------------------------

def log_message(msg):
    """Función simple de logging para ver la actividad del servidor."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


def handle_client(conn, addr):
    """Maneja la lógica de conexión y comandos POP3 de un cliente."""
    log_message(f"Conexión establecida desde {addr}")

    # 1. Respuesta de Bienvenida (El servidor siempre debe responder primero)
    conn.sendall(b"+OK POP3 server ready\r\n")

    logged_in = False

    try:
        while True:
            # Recibe datos del cliente
            data_raw = conn.recv(1024)
            if not data_raw:
                break

            data = data_raw.decode('ascii', errors='ignore').strip()
            log_message(f"<- Recibido: {data}")

            # 2. Procesamiento de Comandos
            command = data.split(' ')[0].upper()

            # --- FASE DE AUTORIZACIÓN ---

            if command == "USER":
                username = data.split(' ')[1] if len(data.split(' ')) > 1 else ""
                log_message(f"   -> Intentando USER: {username}")
                # El servidor acepta el usuario y pide la contraseña
                conn.sendall(b"+OK User accepted, password required\r\n")

            elif command == "PASS":
                password = data.split(' ')[1] if len(data.split(' ')) > 1 else ""

                # Chequeo de credenciales
                if username == VALID_USER and password == VALID_PASS:
                    logged_in = True
                    conn.sendall(b"+OK Logged in, 0 messages (0 bytes)\r\n")
                    log_message("   -> Autenticación Exitosa.")
                else:
                    conn.sendall(b"-ERR Invalid credentials\r\n")
                    log_message("   -> Autenticación Fallida.")

            # --- FASE DE TRANSACCIÓN (Comandos Post-Login) ---

            elif logged_in and command in ["STAT", "LIST"]:
                # Muestra que la cuenta está vacía para que el cliente no intente descargar
                conn.sendall(b"+OK 0 0\r\n")

                # --- CIERRE DE SESIÓN ---

            elif command == "QUIT":
                conn.sendall(b"+OK POP3 server signing off\r\n")
                break

            # --- COMANDOS NO RECONOCIDOS ---

            elif command not in ["USER", "PASS"]:
                conn.sendall(b"-ERR Unknown or unsupported command\r\n")


    except Exception as e:
        log_message(f"Error en la conexión con {addr}: {e}")

    finally:
        conn.close()
        log_message(f"Conexión con {addr} cerrada.")


def start_pop3_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Permite reusar el puerto inmediatamente
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        log_message(f"[*] Servidor POP3 de prueba escuchando en {HOST}:{PORT}...")

        while True:
            conn, addr = server_socket.accept()
            # Manejar cada conexión en un hilo separado
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

    except PermissionError:
        print(f"[-] ERROR: Permiso denegado. El puerto {PORT} requiere permisos de administrador.")
        sys.exit(1)
    except Exception as e:
        log_message(f"[-] Error crítico del servidor: {e}")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_pop3_server()