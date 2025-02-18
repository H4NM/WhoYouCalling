from http.server import HTTPServer, SimpleHTTPRequestHandler
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union, Tuple

#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.output import *

class LookupType:
    IP = "ip"
    DOMAIN = "domain"

class NodeType:
    PROCESS = "process"
    IP = "ip"
    DOMAIN = "domain"
    
class EdgeType:
    PROCESS_START = "processStart"
    DNS_QUERY = "dnsQuery"
    DNS_RESOLUTION = "dnsResolution"
    TCPIP_CONNECTION = "tcpipConnection"

class APIErrorType:
    #Will skip processing the endpoint, e.g. if this type of error occurs for lookup on IP 'x.x.x.x' it will continue to the next IP
    NO_RESULTS = "NO_RESULTS"
    INVALID_FORMAT = "INVALID_FORMAT"
    ERROR = "ERROR"
    
    #Will skip the remaining types of endpoints, e.g. if this type of error occurs for lookup on IP 'x.x.x.x' it will skip all other IP lookups
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    WRONG_CREDENTIALS = "WRONG_CREDENTIALS"
    MAJOR_ERROR = "MAJOR_ERROR"

class Report:
    def __init__(self, api_source: str, endpoint:str, endpoint_type: LookupType, presentable_data: dict, is_potentially_malicious: bool):
        self.api_source = api_source
        self.endpoint = endpoint
        self.endpoint_type = endpoint_type
        self.is_potentially_malicious=is_potentially_malicious
        self.presentable_data = []
        self.presentable_data = presentable_data

class APILookup:
    
    @abstractmethod
    def __init__(self, api_source:str, api_key:str = ""):
        import requests
        
        self.api_source: str = api_source
        self.api_key: str = api_key
        self.api_key_required: bool = True
        self.lookup_types: list = [LookupType.IP, LookupType.DOMAIN]
        self.requests = requests
    
    def lookup(self, endpoints: dict) -> list:
        reports = []
        if LookupType.DOMAIN in self.lookup_types:
            reports.extend(self.get_reports(endpoints=endpoints['domains'], type=LookupType.DOMAIN))
        if LookupType.IP in self.lookup_types:
            reports.extend(self.get_reports(endpoints=endpoints['ips'], type=LookupType.IP))
        return reports   
   
    @abstractmethod
    def get_data(self, endpoint: str, lookup_type) -> Union[dict, APIErrorType]:
        return {}
    
    @abstractmethod
    def get_presentable_data_for_domain(self, returned_data: dict) -> Tuple[dict,bool]:
        return {}, True 

    @abstractmethod
    def get_presentable_data_for_ip(self, returned_data: dict) -> Tuple[dict,bool]:
        return {}, True
    
    def has_api_prerequisites(self):
        if not self.api_key and self.api_key_required:
            return False
        else:
            return True
        
    def get_reports(self, endpoints: list, type: LookupType) -> list:
        reports = []
        for endpoint in endpoints:
            returned_data: dict = self.get_data(endpoint, lookup_type=type) 
            if returned_data == APIErrorType.NO_RESULTS:
                ConsoleOutputPrint(msg=f"No results found for endpoint \"{endpoint}\"", print_type="warning")
                continue
            elif returned_data == APIErrorType.INVALID_FORMAT:
                ConsoleOutputPrint(msg=f"Invalid {type} format \"{endpoint}\"", print_type="warning")
                continue
            elif returned_data == APIErrorType.ERROR:
                ConsoleOutputPrint(msg=f"Generic API Error", print_type="warning")
                continue
            elif returned_data == APIErrorType.QUOTA_EXCEEDED:
                ConsoleOutputPrint(msg=f"Quota exceeded. Skipping remaining {type} lookups..", print_type="warning")
                return reports
            elif returned_data == APIErrorType.MAJOR_ERROR:
                ConsoleOutputPrint(msg=f"Major API error. Skipping remaining {type} lookups..", print_type="warning")
                return reports
            elif returned_data == APIErrorType.WRONG_CREDENTIALS:
                ConsoleOutputPrint(msg=f"Wrong credentials provided. Skipping remaining {type} lookups..", print_type="warning")
                return reports
            

            if type == LookupType.DOMAIN:
                presentable_data, is_potentially_malicious = self.get_presentable_data_for_domain(returned_data=returned_data)
            else:
                presentable_data, is_potentially_malicious = self.get_presentable_data_for_ip(returned_data=returned_data)
                
            report = Report(api_source=self.api_source,
                                    endpoint=endpoint,
                                    endpoint_type=type,
                                    presentable_data=presentable_data,
                                    is_potentially_malicious=is_potentially_malicious)
            reports.append(report)
        return reports
 
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
