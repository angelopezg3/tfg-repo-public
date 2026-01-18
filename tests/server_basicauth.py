from http.server import HTTPServer, SimpleHTTPRequestHandler
import base64


class BasicAuthHandler(SimpleHTTPRequestHandler):
    """Handler con Basic Authentication"""

    # Credenciales: usuario=test, password=1234
    KEY = base64.b64encode(b"test:1234").decode()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Test"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        # Verificar si tiene el header Authorization
        auth_header = self.headers.get('Authorization')

        if auth_header is None:
            self.do_AUTHHEAD()
            self.wfile.write(b'No auth header received')
            return

        # Verificar credenciales
        if auth_header == f'Basic {self.KEY}':
            SimpleHTTPRequestHandler.do_GET(self)
        else:
            self.do_AUTHHEAD()
            self.wfile.write(b'Invalid credentials')

def run_basic_auth_server():
    server_address = ('', 8080)
    httpd = HTTPServer(server_address, BasicAuthHandler)
    print("Servidor HTTP con Basic Auth corriendo en http://localhost:8080")
    print("Usuario: test")
    print("Password: 1234")
    httpd.serve_forever()


if __name__ == '__main__':
    run_basic_auth_server()