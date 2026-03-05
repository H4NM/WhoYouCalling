from typing import Union, Tuple
from http.server import SimpleHTTPRequestHandler, HTTPServer
from pathlib import Path
import json

#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.utils import requests_is_installed
from lib.classes.APILookup import APIStatusMessage

# Serves cached API responses to prevent multiple identical lookups and to have per callmapper session data
CACHED_API_RESPONSES: dict = { }

def start_http_server(directory: str, host: str, port: int, apis:list = []) -> None:
  handler = lambda *args, **kwargs: HttpHandlerWithoutLogging(*args, directory=directory, **kwargs) 
  httpd = HTTPServer((host, port), handler)
  httpd.apis = apis 
  httpd.directory = Path(directory).resolve()
  httpd.serve_forever()
  
class HttpHandlerWithoutLogging(SimpleHTTPRequestHandler):
    
    def __init__(self, *args, directory: str=None, **kwargs):
        self.api_functionality = requests_is_installed()
        super().__init__(*args, directory=directory, **kwargs)
    
    @property
    def apis(self):
        return self.server.apis
        
    def translate_path(self, path):
        requested_path = Path(self.directory) / path.lstrip("/")
        return str(requested_path.resolve())
    
    def end_headers(self):
        # £ Debugging
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "no-referrer")

        self.send_header(
            "Content-Security-Policy",
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "frame-ancestors 'none';"
        )

        self.send_header(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains"
        )
        super().end_headers()
        
    def log_message(self, format, *args): 
        return 

    def validRequestedApiAndType(self, api_name, value_type) -> bool:
        for api in self.apis:
            if api.name == api_name and value_type in api.lookup_types:
                return True
        return False
    
    def get_cached_api_entry(self, api_name: str, value_type: str, value: str, node_id: int) -> dict:
        if node_id in CACHED_API_RESPONSES.keys():
            for cached_api_response in CACHED_API_RESPONSES[node_id]:
                if api_name == cached_api_response['api_name'] and value_type == cached_api_response['value_type'] and value == cached_api_response['value']:
                    return cached_api_response['lookup_results']
        return None
    
    def set_cached_api_entry(self, api_name:str, value_type:str, value:str, node_id:str, lookup_results:str) -> None:
        
        cached_entry = {
            'api_name': api_name,
            'value_type': value_type,
            'value': value,
            'lookup_results': lookup_results
        }
        
        if not node_id in CACHED_API_RESPONSES.keys():
            CACHED_API_RESPONSES[node_id] = []
        CACHED_API_RESPONSES[node_id].append(cached_entry)
    
    def lookupValueViaAPI(self, api_name, value_type, value):
        for api in self.apis:
            if api.name == api_name:
                lookup_results = api.lookup(lookup_type=value_type, lookup_value=value)

                return lookup_results
        return { "status": APIStatusMessage.ERROR, "results": f"Unable to lookup \"{value}\" as \"{value_type}\" via \"{api_name}\""}

    def do_POST(self):
        ##############################
        # STATUS CHECK
        ##############################
        if self.path == "/status":
            if self.api_functionality:
                status = { 'status': 'ok'}
                http_code = 200
            else:
                status = { 'status': 'requests not installed'}   
                http_code = 503 
                
            json_response = json.dumps(status).encode("utf-8")

            self.send_response(http_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(json_response)))
            self.end_headers()
            self.wfile.write(json_response)
            return
        
        ##############################
        # CHECK IF API IS EVEN AVAILABLE
        ##############################
        if not self.api_functionality:
            self.send_response(404)
            self.end_headers()
            
        ##############################
        # LIST AVAILABLE APIS
        ##############################
        if self.path == "/apis":
                
            available_apis = [
                {
                    "name": api.name,
                    "lookup_types": api.lookup_types
                }
                for api in self.apis
            ]

            json_available_apis = json.dumps(available_apis).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(json_available_apis)))
            self.end_headers()
            self.wfile.write(json_available_apis)
            return
        
        ##############################
        # GET ALL CACHED ENTRIES
        ##############################
        elif self.path == "/api/cached":
            cached_api_responses = json.dumps(CACHED_API_RESPONSES).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(cached_api_responses)))
            self.end_headers()
            self.wfile.write(cached_api_responses)
            return 
        
        ##############################
        # API LOOKUP 
        ##############################
        elif self.path.startswith("/api/") and self.path.count("/") == 5: 
            api_name, value_type, value, node_id = self.path.split("/")[2:]
            if self.validRequestedApiAndType(api_name, value_type):

                cached_api_entry = self.get_cached_api_entry(api_name, value_type, value, node_id)
                
                if cached_api_entry:
                    json_cached = json.dumps(cached_api_entry).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(json_cached)))
                    self.end_headers()
                    self.wfile.write(json_cached)
                    return

                lookup_results = self.lookupValueViaAPI(api_name, value_type, value)
                json_response = json.dumps(lookup_results).encode("utf-8")
                
                self.set_cached_api_entry(api_name, value_type, value, node_id, lookup_results)

                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(json_response)))
                self.end_headers()
                self.wfile.write(json_response)
                return

            else:
                self.send_response(400)
                self.end_headers()

        self.send_response(404)
        self.end_headers()