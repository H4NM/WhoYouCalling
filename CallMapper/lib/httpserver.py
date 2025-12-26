from typing import Union, Tuple
from http.server import SimpleHTTPRequestHandler, HTTPServer
from pathlib import Path

def start_http_server(directory: str, host: str, port: int) -> None:
  handler = lambda *args, **kwargs: HttpHandlerWithoutLogging(*args, directory=directory, **kwargs) 
  httpd = HTTPServer((host, port), handler)
  httpd.serve_forever()
  
class HttpHandlerWithoutLogging(SimpleHTTPRequestHandler):
    
    def __init__(self, *args, directory: str=None, **kwargs):
        self.directory = Path(directory).resolve()
        super().__init__(*args, directory=str(self.directory), **kwargs)
        
    def translate_path(self, path):
        requested_path = Path(self.directory) / path.lstrip("/")
        return str(requested_path.resolve())
    
    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()
        
    def log_message(self, format, *args): 
        return 

    def do_POST(self):
        if self.path == "/submit":
            # Read request body
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)

            # Process the data however you like
            print("Received body:", body)

            # Send response
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"received": true}')
            return

        # 404 for POST to unknown endpoints
        self.send_response(404)
        self.end_headers()