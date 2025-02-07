from abc import ABC, abstractmethod

class APILookup:
    
    @abstractmethod
    def __init__(self, api_source:str, api_key:str = ""):
        self.api_source = api_source
        self.api_key = api_key
        self.api_key_required = True
        
        import requests
        from callmapper import Report, LookupType, ConsoleOutputPrint
        self.requests = requests
        self.Report = Report
        self.LookupType = LookupType
        self.ConsoleOutputPrint = ConsoleOutputPrint
    
    @abstractmethod
    def lookup(self, endpoints: dict) -> list:
        return []
    
    def has_api_prerequisites(self):
        if not self.api_key and self.api_key_required:
            return False
        else:
            return True