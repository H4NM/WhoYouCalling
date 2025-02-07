import time
from APILookup import APILookup
from typing import Tuple

class MyCustomAddedAPI(APILookup):

    def __init__(self, api_source:str, api_key:str = ""):
        super().__init__(api_source, api_key)
        self.headers = {"x-api-key": self.api_key}
        
    def lookup(self, endpoints: dict) -> list:
        abuseipdb_reports = []
        if not self.api_key:
            return abuseipdb_reports
        abuseipdb_reports.extend(self.get_ip_reports(ips=endpoints['ips']))
        return abuseipdb_reports
    
    def get_data(self, endpoint: str, lookup_type, sleep_time: int = 10) -> dict:
        url = f"https://my.own.api/api/v2/check?{endpoint}"
        
        try:
            response = self.requests.get(url, headers=self.headers)
            json_response = response.json()

            if response.status_code == 200:
                return json_response
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
            presentable_data, is_potentially_malicious = self.get_presentable_data_for_ip(returned_data=returned_data)
            virustotal_report = self.Report(api_source=self.api_source,
                                       endpoint=ip,
                                       endpoint_type=self.LookupType.IP,
                                       presentable_data=presentable_data,
                                       is_potentially_malicious=is_potentially_malicious)
            reports.append(virustotal_report)
        return reports
    