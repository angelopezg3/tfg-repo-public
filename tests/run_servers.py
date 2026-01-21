"""
Project developed as part of the Trabajo de Fin de Grado (TFG)
Grado en Ingeniería Informática - UNIR

Author: angelopezg3
Year: 2026
License: MIT

Módulo que arranca todos los servers de pruebas (cada uno en un hilo de ejecución distinto)
"""

import ftp_server
import server_basicauth
import telnet_server
import pop3_server
import threading

def run_all_servers():
    # Crear hilo para el FTP server
    t1 = threading.Thread(target=ftp_server.run_ftp_server, daemon=True)
    # Crear hilo para el HTTP Basic Auth server
    t2 = threading.Thread(target=server_basicauth.run_basic_auth_server, daemon=True)
    # Crear hilo para el Telnet server
    t3 = threading.Thread(target=telnet_server.start_telnet_server, daemon=True)
    # Crear hilo para el pop3 server
    t4 = threading.Thread(target=pop3_server.start_pop3_server, daemon=True)

    t1.start()
    t2.start()
    t3.start()
    t4.start()

    print(" Servidores iniciados: FTP (21), POP(110), HTTP (8080), telnet (23)")
    print("Presiona Ctrl+C para detener.")

    # Mantener el proceso principal vivo
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nApagando servidores...")

if __name__ == '__main__':
    run_all_servers()



