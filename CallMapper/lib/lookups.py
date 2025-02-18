import time
from typing import Tuple


#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.classes import *
from lib.functions import ConsoleOutputPrint

class VirusTotal(APILookup):

    def __init__(self, api_source:str, api_key:str = ""):
        super().__init__(api_source, api_key)
        self.headers = {"x-apikey": self.api_key}
        self.lookup_types = [LookupType.IP, LookupType.DOMAIN]

    def get_data(self, endpoint: str, lookup_type) -> Union[dict, APIErrorType]:
        api_adapted_lookup_type: str = "ip_addresses" if lookup_type == LookupType.IP else "domains"
        url = f"https://www.virustotal.com/api/v3/{api_adapted_lookup_type}/{endpoint}"
        try:
            response = self.requests.get(url, headers=self.headers)
            json_response = response.json()
            
            if response.status_code == 200:
                return json_response
            else:
                if json_response['error']['code'] == 'NotFoundError':
                    return APIErrorType.NO_RESULTS
                elif json_response['error']['code'] == 'InvalidArgumentError':
                    return APIErrorType.INVALID_FORMAT
                elif json_response['error']['code'] == 'QuotaExceededError':
                    return APIErrorType.QUOTA_EXCEEDED
                elif json_response['error']['code'] == 'WrongCredentialsError':
                    return APIErrorType.WRONG_CREDENTIALS
                else:
                    ConsoleOutputPrint(msg=f"Error during {self.api_source} lookup of \"{lookup_type}\" \"{endpoint}\". Response: {response.status_code}, {response.text}", print_type="error")
                return APIErrorType.NO_RESULTS
        except Exception as error_msg:
            ConsoleOutputPrint(msg=f"Error during {self.api_source} lookup of \"{lookup_type}\" \"{endpoint}\": {str(error_msg)}", print_type="error")
            return APIErrorType.NO_RESULTS
    
    def get_presentable_data_for_domain(self, returned_data: dict) -> Tuple[dict,bool]:
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
    
    def get_presentable_data_for_ip(self, returned_data: dict) -> Tuple[dict,bool]:
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
    
    
class AbuseIPDB(APILookup):

    def __init__(self, api_source:str, api_key:str = ""):
        super().__init__(api_source, api_key)
        self.headers = {"Key": self.api_key, 'Accept': 'application/json'}
        self.lookup_types = [LookupType.IP]
    
    def get_data(self, endpoint: str, lookup_type) -> Union[dict, APIErrorType]:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={endpoint}&maxAgeInDays=90&verbose"
        
        try:
            response = self.requests.get(url, headers=self.headers)
            json_response = response.json()

            if response.status_code == 200:
                return json_response
            elif response.status_code == 429:
                return APIErrorType.QUOTA_EXCEEDED
            elif response.status_code == 401 and 'Your API key is either missing, incorrect, or revoked' in json_response['errors'][0]['detail']:
                return APIErrorType.WRONG_CREDENTIALS
            else:
                ConsoleOutputPrint(msg=f"Error during {self.api_source} lookup of \"{lookup_type}\" \"{endpoint}\". Response: {response.status_code}, {response.text}", print_type="error")
                return APIErrorType.NO_RESULTS
        except Exception as error_msg:
            ConsoleOutputPrint(msg=f"Error during {self.api_source} lookup of \"{lookup_type}\" \"{endpoint}\": {str(error_msg)}", print_type="error")
            return APIErrorType.NO_RESULTS
    
    def get_presentable_data_for_ip(self, returned_data: dict) -> Tuple[dict,bool]:
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

    
    """
if __name__ == '__main__':
    endpoints: dict = {
        'domains': set(),
        'ips': set()
    }
    endpoints['ips'].add("92.255.85.37")

    abuseipdb = VirusTotal("VirusTotal", "")
    print(abuseipdb.lookup(endpoints))
    """