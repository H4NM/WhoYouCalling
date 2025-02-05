import time
from abc import ABC, abstractmethod
from typing import List, Tuple

"""
This is where you may add additional lookup functionality to your own APIs 
to enrich your data additionally. All you need to do is to do is use the template function below.
It will take the endpoints as a parameter in which you may iterate all of the to generate a report for each.
The passed endpoints variable is a dict in the following structure:

endpoints: dict = {
    'domains': set(),
    'ips': set()
}

You need to import the library requests in the parent function for all reports. 
The reason for this is simply due to making this script not requiring the requests library to run.

For more information, see the get_virustotal_report function on how it was made.
"""
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
    def lookup(self, endpoints: dict) -> List:
        return []
    
    def has_api_prerequisites(self):
        print(f"\"{self.api_key}\" {self.api_key_required}")
        # Handle cases where api_key is empty or None
        if not self.api_key and self.api_key_required:
            return False
        else:
            return True

class VirusTotalLookup(APILookup):

    def __init__(self, api_source:str, api_key:str = ""):
        super().__init__(api_source, api_key)
        
    def lookup(self, endpoints: dict) -> List:
        self.headers = {"x-apikey": self.api_key}
        virustotal_reports = []
        if not self.api_key:
            return virustotal_reports
        virustotal_reports.extend(self.get_domain_reports(domains=endpoints['domains']))
        virustotal_reports.extend(self.get_ip_reports(domains=endpoints['ips']))
        return virustotal_reports
    
    def get_data(self, endpoint: str, lookup_type: 'LookupType', sleep_time: int = 10) -> dict:
        api_adapted_lookup_type: str = "ip_addresses" if lookup_type == 'LookupType.IP' else "domains"
        url = f"https://www.virustotal.com/api/v3/{api_adapted_lookup_type}/{endpoint}"
        try:
            response = self.requests.get(url, headers=self.headers)
            if response.status_code == 200:
                return response.json()
            else:
                json_response = response.json()
                if json_response['error']['code'] == 'NotFoundError':
                    self.ConsoleOutputPrint(msg=f"No results found for domain \"{endpoint}\"", print_type="warning")
                elif json_response['error']['code'] == 'InvalidArgumentError':
                    self.ConsoleOutputPrint(msg=f"Invalid domain format \"{endpoint}\"", print_type="warning")
                elif json_response['error']['code'] == 'QuotaExceededError':
                    self.ConsoleOutputPrint(msg=f"Quota exceeded when querying \"{endpoint}\". Sleeping for {sleep_time}s then retrying", print_type="warning")
                    time.sleep(sleep_time)
                    sleep_time += 10
                    return self.get_data(endpoint=endpoint, lookup_type=lookup_type, sleep_time=sleep_time)
                else:
                    self.ConsoleOutputPrint(msg=f"Error during virustotal lookup of \"{lookup_type}\" \"{endpoint}\". Response: {response.status_code}, {response.text}", print_type="error")
                return None
        except Exception as error_msg:
            self.ConsoleOutputPrint(msg=f"Error during virustotal lookup of \"{lookup_type}\" \"{endpoint}\": {str(error_msg)}", print_type="error")
            return None
    
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
    
    def get_ip_reports(self, ips: list) -> list:
        reports = []
        for ip in ips:
            returned_data: dict = self.get_data(ip, lookup_type=self.LookupType.IP) 
            if returned_data == None:
                continue
            presentable_data, is_potentially_malicious = self.get_presentable_data_for_ip(returned_data=returned_data)
            virustotal_report = self.Report(api_source=self.api_source,
                                       endpoint=ip,
                                       endpoint_type=self.LookupType.IP,
                                       presentable_data=presentable_data,
                                       is_potentially_malicious=is_potentially_malicious)
            reports.append(virustotal_report)
        return reports
        
    def get_domain_reports(self, domains: list) -> list:
        reports = []
        for domain in domains:
            returned_data: dict = self.get_data(domain, lookup_type=self.LookupType.DOMAIN) 
            if returned_data == None:
                continue
            presentable_data, is_potentially_malicious = self.get_presentable_data_for_domain(returned_data=returned_data)
            virustotal_report = self.Report(api_source=self.api_source,
                                    endpoint=domain,
                                    endpoint_type=self.LookupType.DOMAIN,
                                    presentable_data=presentable_data,
                                    is_potentially_malicious=is_potentially_malicious)
            reports.append(virustotal_report)
        return reports
    
    

def get_virustotal_report(endpoints: dict, api_source: str,  api_key:str = "") -> list: 
    import requests
    from callmapper import Report, LookupType, ConsoleOutputPrint
    
    headers = {"x-apikey": api_key}
    virustotal_reports = []
    if not api_key:
        return virustotal_reports
    
    def get_data(endpoint: str, lookup_type: LookupType, sleep_time: int = 10) -> dict:
        api_adapted_lookup_type: str = "ip_addresses" if lookup_type == LookupType.IP else "domains"
        url = f"https://www.virustotal.com/api/v3/{api_adapted_lookup_type}/{endpoint}"
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                json_response = response.json()
                if json_response['error']['code'] == 'NotFoundError':
                    ConsoleOutputPrint(msg=f"No results found for domain \"{endpoint}\"", print_type="warning")
                elif json_response['error']['code'] == 'InvalidArgumentError':
                    ConsoleOutputPrint(msg=f"Invalid domain format \"{endpoint}\"", print_type="warning")
                elif json_response['error']['code'] == 'QuotaExceededError':
                    ConsoleOutputPrint(msg=f"Quota exceeded when querying \"{endpoint}\". Sleeping for {sleep_time}s then retrying", print_type="warning")
                    time.sleep(sleep_time)
                    sleep_time += 10
                    return get_data(endpoint=endpoint, lookup_type=lookup_type, sleep_time=sleep_time)
                else:
                    ConsoleOutputPrint(msg=f"Error during virustotal lookup of \"{lookup_type}\" \"{endpoint}\". Response: {response.status_code}, {response.text}", print_type="error")
                return None
        except Exception as error_msg:
            ConsoleOutputPrint(msg=f"Error during virustotal lookup of \"{lookup_type}\" \"{endpoint}\": {str(error_msg)}", print_type="error")
            return None
    
    def get_presentable_data_for_domain(returned_data: dict) -> Tuple[dict,bool]:
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
    
    def get_presentable_data_for_ip(returned_data: dict) -> Tuple[dict,bool]:
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
    
    def get_ip_reports(ips: list) -> list:
        reports = []
        for ip in ips:
            returned_data: dict = get_data(ip, lookup_type=LookupType.IP) 
            if returned_data == None:
                continue
            presentable_data, is_potentially_malicious = get_presentable_data_for_ip(returned_data=returned_data)
            virustotal_report = Report(api_source=api_source,
                                       endpoint=ip,
                                       endpoint_type=LookupType.IP,
                                       presentable_data=presentable_data,
                                       is_potentially_malicious=is_potentially_malicious)
            reports.append(virustotal_report)
        return reports
        
    def get_domain_reports(domains: list) -> list:
        reports = []
        for domain in domains:
            returned_data: dict = get_data(domain, lookup_type=LookupType.DOMAIN) 
            if returned_data == None:
                continue
            presentable_data, is_potentially_malicious = get_presentable_data_for_domain(returned_data=returned_data)
            virustotal_report = Report(api_source=api_source,
                                    endpoint=domain,
                                    endpoint_type=LookupType.DOMAIN,
                                    presentable_data=presentable_data,
                                    is_potentially_malicious=is_potentially_malicious)
            reports.append(virustotal_report)
        return reports
    
    virustotal_reports.extend(get_domain_reports(domains=endpoints['domains']))
    virustotal_reports.extend(get_ip_reports(domains=endpoints['ips']))

    return virustotal_reports


def get_abuseipdb_report(endpoints: dict, api_source: str, api_key:str = "") -> list: 
    import requests
    from callmapper import Report, LookupType, ConsoleOutputPrint

    headers = {"Key": api_key, "Accept": "application/json"}
    abuseipdb_reports = []
    if not api_key:
        return abuseipdb_reports
    
    def get_data(endpoint: str, lookup_type: LookupType, sleep_time: int = 10) -> dict:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={endpoint}&maxAgeInDays=90&verbose"
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                return response.json()
            else:
                json_response = response.json()
                if json_response['error']['code'] == 'NotFoundError':
                    ConsoleOutputPrint(msg=f"No results found for domain \"{endpoint}\"", print_type="warning")
                elif json_response['error']['code'] == 'InvalidArgumentError':
                    ConsoleOutputPrint(msg=f"Invalid domain format \"{endpoint}\"", print_type="warning")
                elif json_response['error']['code'] == 'QuotaExceededError':
                    ConsoleOutputPrint(msg=f"Quota exceeded when querying \"{endpoint}\". Sleeping for {sleep_time}s then retrying", print_type="warning")
                    time.sleep(sleep_time)
                    sleep_time += 10
                    return get_data(endpoint=endpoint, lookup_type=lookup_type, sleep_time=sleep_time)
                else:
                    ConsoleOutputPrint(msg=f"Error during virustotal lookup of \"{lookup_type}\" \"{endpoint}\". Response: {response.status_code}, {response.text}", print_type="error")
                return None
        except Exception as error_msg:
            ConsoleOutputPrint(msg=f"Error during virustotal lookup of \"{lookup_type}\" \"{endpoint}\": {str(error_msg)}", print_type="error")
            return None
    
    def get_presentable_data_for_ip(returned_data: dict) -> Tuple[dict,bool]:
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
    
    def get_ip_reports(ips: list) -> list:
        reports = []
        for ip in ips:
            returned_data: dict = get_data(ip, lookup_type=LookupType.IP) 
            if returned_data == None:
                continue
            presentable_data, is_potentially_malicious = get_presentable_data_for_ip(returned_data=returned_data)
            virustotal_report = Report(api_source=api_source,
                                       endpoint=ip,
                                       endpoint_type=LookupType.IP,
                                       presentable_data=presentable_data,
                                       is_potentially_malicious=is_potentially_malicious)
            reports.append(virustotal_report)
        return reports
    
    abuseipdb_reports.extend(get_ip_reports(domains=endpoints['ips']))

    return abuseipdb_reports
