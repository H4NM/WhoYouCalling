import time
from typing import Tuple, Union

#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.classes import *
from lib.functions import ConsoleOutputPrint


"""
This is where you may add additional lookup functionality to your own APIs 
to enrich your data. All you need to do is to do is use the template class below.

For more instructions or help, checkout the README.md at https://github.com/H4NM/WhoYouCalling/blob/main/CallMapper/README.md
"""


class MyCustomAPILookupClass(APILookup):

    def __init__(self, api_source:str, api_key:str = ""):
        super().__init__(api_source, api_key)
        self.headers = {"x-api-key": self.api_key}
        self.api_key_required = True
        self.lookup_types = [LookupType.IP, LookupType.DOMAIN]
        
    def get_data(self, endpoint: str, lookup_type) -> Union[dict, APIErrorType]:
        url = f"https://my.own.api/api/v2/check?{endpoint}"
        
        try:
            response = self.requests.get(url, headers=self.headers)
            json_response = response.json()

            if response.status_code == 200:
                return json_response
            else:
                ConsoleOutputPrint(msg=f"Error during {self.api_source} lookup of \"{lookup_type}\" \"{endpoint}\". Response: {response.status_code}, {response.text}", print_type="error")
                return None
        except Exception as error_msg:
            ConsoleOutputPrint(msg=f"Error during {self.api_source} lookup of \"{lookup_type}\" \"{endpoint}\": {str(error_msg)}", print_type="error")
            return None
    
    def get_presentable_data_for_ip(self, returned_data: dict) -> Tuple[dict, bool]:
        presentable_data: dict = {}
        status: str = ""
        is_potentially_malicious: bool = False
        
        if returned_data['data']['abuseConfidenceScore'] > 50:
            status = 'Potentially malicious'
            is_potentially_malicious = True
        elif returned_data['data']['totalReports'] > 0:
            status = 'Suspicious'
        else:
            status = 'Harmless or undetected'

        presentable_data['Status'] = status
        presentable_data['Whitelisted'] = returned_data['data']['isWhitelisted']
        presentable_data['Total reports'] = returned_data['data']['totalReports']
        if returned_data['data']['totalReports'] > 0:
            presentable_data['Last reported'] = returned_data['data']['lastReportedAt']
        presentable_data['Abuse confidence score'] = returned_data['data']['abuseConfidenceScore']
        presentable_data['Related domain'] = returned_data['data']['domain']
        presentable_data['Related hostnames'] = ", ".join(returned_data['data']['hostnames'])
        presentable_data['Country'] = f"{returned_data['data']['countryName']}({returned_data['data']['countryCode']})"
        presentable_data['ISP'] = returned_data['data']['isp']
        presentable_data['Type'] = returned_data['data']['usageType']

        return presentable_data, is_potentially_malicious
    
    def get_presentable_data_for_domain(self, returned_data: dict) -> Tuple[dict, bool]:
        presentable_data: dict = {}
        status: str = ""
        is_potentially_malicious: bool = False
        
        if returned_data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            status = 'Potentially malicious'
            is_potentially_malicious = True
        elif returned_data['data']['attributes']['last_analysis_stats']['suspicious'] > 0:
            status = 'Suspicious'
        else:
            status = 'Harmless or undetected'
        
        presentable_data['Status'] = status
        presentable_data['Community votes harmless'] = returned_data['data']['attributes']['total_votes']['harmless']
        presentable_data['Community votes malicious'] = returned_data['data']['attributes']['total_votes']['malicious']
        presentable_data['Reputation'] = returned_data['data']['attributes']['reputation']
        if len(returned_data['data']['attributes']['tags']) > 0:
            presentable_data['Tags'] = ", ".join(returned_data['data']['attributes']['tags'])

        return presentable_data, is_potentially_malicious
    