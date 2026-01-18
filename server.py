# server.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import time

PORT = 8080

class SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)

    def log_message(self, format, *args):
        return  # disable default logging

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), SimpleHandler)
    print(f"Server listening on port {PORT}")
    server.serve_forever()
