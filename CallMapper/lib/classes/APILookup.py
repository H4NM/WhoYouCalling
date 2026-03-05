from abc import ABC, abstractmethod
from pathlib import Path
from typing import Tuple


#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.classes.APIStatusMessage import APIStatusMessage
from lib.classes.LookupType import LookupType

from lib.utils import get_current_timestamp

class APILookup(ABC):
    
    @abstractmethod
    def __init__(self, api_key:str = ""):
        import requests
        
        self.name: str = "APILookup"
        self.api_key: str = api_key
        self.api_key_required: bool = True
        self.lookup_types: list = []
        self.requests = requests
    
    def lookup(self, lookup_type:LookupType, lookup_value) -> dict:
        """
        This function is invoked when receiving API lookups for specified APIs, lookup types and values.
        It's not meant to be changed for custom APIs. See all the get_* functions as these need to me altered to fit the needs of the API
        
        This function receives the lookup type and the lookup value, sends it to the get_data function in which a API status code and dict is returned.
        Based on the results it prints to the stdout of the server more details of the error. Thereafter, returns the results back to the HTTP server which
        returns it back to the client.
        """
        
        api_status_message, lookup_results = self.get_data(lookup_type=lookup_type, lookup_value=lookup_value) 
        
        returned_api_json = {
            "status": api_status_message,
            "results": lookup_results
        }
        returned_api_json['results']['API Lookup timestamp'] = get_current_timestamp()
       
        return returned_api_json

    @abstractmethod
    def get_data(self, lookup_type:str, lookup_value:str) -> Tuple[APIStatusMessage, dict]:
        return APIStatusMessage.ERROR, {}
    