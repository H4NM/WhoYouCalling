import time
from APILookup import APILookup
from typing import Tuple


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

class VirusTotal(APILookup):

    def __init__(self, api_source:str, api_key:str = ""):
        super().__init__(api_source, api_key)
        self.headers = {"x-apikey": self.api_key}
        
    def lookup(self, endpoints: dict) -> list:
        virustotal_reports = []
        if not self.api_key:
            return virustotal_reports
        virustotal_reports.extend(self.get_domain_reports(domains=endpoints['domains']))
        virustotal_reports.extend(self.get_ip_reports(ips=endpoints['ips']))
        return virustotal_reports
    
    def get_data(self, endpoint: str, lookup_type) -> dict:
        api_adapted_lookup_type: str = "ip_addresses" if lookup_type == self.LookupType.IP else "domains"
        url = f"https://www.virustotal.com/api/v3/{api_adapted_lookup_type}/{endpoint}"
        try:
            response = self.requests.get(url, headers=self.headers)
            json_response = response.json()
            
            if response.status_code == 200:
                return json_response
            else:
                if json_response['error']['code'] == 'NotFoundError':
                    self.ConsoleOutputPrint(msg=f"No results found for domain \"{endpoint}\"", print_type="warning")
                elif json_response['error']['code'] == 'InvalidArgumentError':
                    self.ConsoleOutputPrint(msg=f"Invalid {lookup_type} format \"{endpoint}\"", print_type="warning")
                elif json_response['error']['code'] == 'QuotaExceededError':
                    self.ConsoleOutputPrint(msg=f"Quota exceeded. Skipping remaining {lookup_type} lookups..", print_type="warning")
                    return {'QUOTA_EXCEEDED': 1}
                else:
                    self.ConsoleOutputPrint(msg=f"Error during {self.api_source} lookup of \"{lookup_type}\" \"{endpoint}\". Response: {response.status_code}, {response.text}", print_type="error")
                return None
        except Exception as error_msg:
            self.ConsoleOutputPrint(msg=f"Error during {self.api_source} lookup of \"{lookup_type}\" \"{endpoint}\": {str(error_msg)}", print_type="error")
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
            if 'QUOTA_EXCEEDED' in returned_data:
                return reports
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
            if 'QUOTA_EXCEEDED' in returned_data:
                return reports
            presentable_data, is_potentially_malicious = self.get_presentable_data_for_domain(returned_data=returned_data)
            virustotal_report = self.Report(api_source=self.api_source,
                                    endpoint=domain,
                                    endpoint_type=self.LookupType.DOMAIN,
                                    presentable_data=presentable_data,
                                    is_potentially_malicious=is_potentially_malicious)
            reports.append(virustotal_report)
        return reports
    
class AbuseIPDB(APILookup):

    def __init__(self, api_source:str, api_key:str = ""):
        super().__init__(api_source, api_key)
        self.headers = {"Key": self.api_key, 'Accept': 'application/json'}
        
    def lookup(self, endpoints: dict) -> list:
        abuseipdb_reports = []
        if not self.api_key:
            return abuseipdb_reports
        abuseipdb_reports.extend(self.get_ip_reports(ips=endpoints['ips']))
        return abuseipdb_reports
    
    def get_data(self, endpoint: str, lookup_type) -> dict:
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={endpoint}&maxAgeInDays=90&verbose"
        
        try:
            response = self.requests.get(url, headers=self.headers)
            json_response = response.json()

            if response.status_code == 200:
                return json_response
            elif response.status_code == 429:
                self.ConsoleOutputPrint(msg=f"Quota exceeded. Skipping remaining {lookup_type} lookups..", print_type="warning")
                return {'QUOTA_EXCEEDED': 1}
            else:
                self.ConsoleOutputPrint(msg=f"Error during {self.api_source} lookup of \"{lookup_type}\" \"{endpoint}\". Response: {response.status_code}, {response.text}", print_type="error")
                return None
        except Exception as error_msg:
            self.ConsoleOutputPrint(msg=f"Error during {self.api_source} lookup of \"{lookup_type}\" \"{endpoint}\": {str(error_msg)}", print_type="error")
            return None
    
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
    
    def get_ip_reports(self, ips: list) -> list:
        reports = []
        for ip in ips:
            returned_data: dict = self.get_data(ip, lookup_type=self.LookupType.IP) 
            if returned_data == None:
                continue
            if 'QUOTA_EXCEEDED' in returned_data:
                return reports
            presentable_data, is_potentially_malicious = self.get_presentable_data_for_ip(returned_data=returned_data)
            abuseipdb_report = self.Report(api_source=self.api_source,
                                       endpoint=ip,
                                       endpoint_type=self.LookupType.IP,
                                       presentable_data=presentable_data,
                                       is_potentially_malicious=is_potentially_malicious)
            reports.append(abuseipdb_report)
        return reports
    
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