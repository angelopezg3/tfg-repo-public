"""
Project developed as part of the Trabajo de Fin de Grado (TFG)
Grado en Ingeniería Informática - UNIR

Author: angelopezg3
Year: 2026
License: MIT

Servidor telnet local de pruebas básico
"""

import socket
import threading
import sys

HOST = '0.0.0.0'  # Escuchar en todas las interfaces
PORT = 23  # Puerto por defecto de Telnet (TCP)

# Credenciales de prueba
VALID_USER = "testuser"
VALID_PASS = "prueba123"


def handle_client(conn, addr):
    """
    Maneja la lógica de conexión y autenticación de un cliente.

    Args:
        conn: socket para la conexión
        addr: tupla con ip y puerto de origen

    """

    print(f"[+] Conexión establecida desde {addr}")

    # 1. Bienvenida y Solicitud de Login
    conn.sendall(b"Bienvenido al Servidor Telnet de Prueba.\r\n")

    try:
        # --- Lógica de Autenticación ---

        # Pedir nombre de usuario
        conn.sendall(b"login: ")
        username = conn.recv(1024).decode().strip()

        # Pedir contraseña
        conn.sendall(b"password: ")
        password = conn.recv(1024).decode().strip()

        if username == VALID_USER and password == VALID_PASS:
            # Autenticación exitosa
            conn.sendall(f"+++ Sesion iniciada para: {username} +++\r\n".encode())
            print(f"[+] Autenticacion exitosa para {username} desde {addr}")

            # 2. Bucle de Sesión (Simulación de comandos)
            while True:
                conn.sendall(b"> ")
                comando = conn.recv(1024).decode().strip()

                if not comando:
                    continue

                if comando.lower() == 'exit' or comando.lower() == 'quit':
                    conn.sendall(b"Adios.\r\n")
                    break

                # Simular respuesta a comandos (solo eco)
                conn.sendall(f"Comando recibido: {comando}\r\n".encode())

        else:
            # Autenticación fallida
            conn.sendall(b"--- Acceso Denegado ---\r\n")
            print(f"[-] Autenticacion fallida: {username}/{password} desde {addr}")

    except Exception as e:
        print(f"[-] Error en la comunicacion con {addr}: {e}")

    finally:
        conn.close()
        print(f"[+] Conexión con {addr} cerrada.")


def start_telnet_server():
    """
    Inicializa el servidor y escucha por conexiones entrantes.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Reutilizar puerto rápidamente si se cierra
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print(f"[*] Servidor Telnet de prueba escuchando en {HOST}:{PORT}...")

        while True:
            # Espera a una conexión
            conn, addr = server_socket.accept()
            # Inicia un nuevo hilo para manejar al cliente
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()

    except PermissionError:
        print(
            f"[-] ERROR: Permiso denegado. El puerto {PORT} requiere permisos de administrador (sudo/Ejecutar como administrador).")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error crítico del servidor: {e}")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_telnet_server()