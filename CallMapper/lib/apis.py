from typing import Tuple


#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.classes.APILookup import APILookup
from lib.classes.LookupType import LookupType
from lib.classes.APIStatusMessage import APIStatusMessage
from lib.utils import convert_unix_epoch_to_standard_datetime   
from lib.output import ConsoleOutputPrint    
    

class VirusTotal(APILookup):

    def __init__(self, api_key:str = ""):
        super().__init__(api_key)
        self.name = "VirusTotal"
        self.headers = {"x-apikey": self.api_key}
        self.lookup_types = [LookupType.IP, LookupType.DOMAIN, LookupType.SHA256, LookupType.SHA1, LookupType.MD5]
        self.api_key_required = True
        
    def get_data(self, lookup_type:LookupType, lookup_value: str) -> Tuple[APIStatusMessage, dict]:
        json_response = {}
        api_adapted_lookup_type: str = '' 
        
        if lookup_type == LookupType.IP:
            api_adapted_lookup_type = 'ip_addresses'
        elif lookup_type == LookupType.DOMAIN:
            api_adapted_lookup_type = 'domains'
        elif lookup_type in [LookupType.SHA256, LookupType.SHA1, LookupType.MD5]: # Redundant but used for clarification
            api_adapted_lookup_type = 'files'
        else:
            return APIStatusMessage.ERROR, json_response
            
        url = f"https://www.virustotal.com/api/v3/{api_adapted_lookup_type}/{lookup_value}"
        
        response = self.requests.get(url, headers=self.headers)
        json_response = response.json()
        try:
            if response.status_code == 200:
                return APIStatusMessage.OK, self.get_presentable_data(json_response,lookup_type)
            else:
                if json_response['error']['code'] == 'NotFoundError':
                    return APIStatusMessage.NO_RESULTS, { 'Status': "Not found" } 
                elif json_response['error']['code'] == 'InvalidArgumentError':
                    return APIStatusMessage.INVALID_FORMAT, json_response
                elif json_response['error']['code'] == 'QuotaExceededError':
                    return APIStatusMessage.QUOTA_EXCEEDED, json_response
                elif json_response['error']['code'] == 'WrongCredentialsError':
                    return APIStatusMessage.WRONG_CREDENTIALS, json_response
                else:
                    ConsoleOutputPrint(msg=f"Error during {self.name} lookup of \"{lookup_type}\" \"{lookup_value}\". Response: {response.status_code}, {response.text}", print_type="error")
                return APIStatusMessage.ERROR, json_response
        except Exception as error_msg:
            ConsoleOutputPrint(msg=f"Error during {self.name} lookup of \"{lookup_type}\" \"{lookup_value}\": {str(error_msg)}", print_type="error")
            return APIStatusMessage.ERROR, json_response
        
        
    def get_presentable_data(self, returned_data: dict, lookup_type) -> dict:
        presentable_data: dict = {}
        status: str = ""
        
        # £ DEBUGGING - REMOVE ME DELETE ME LATER
        import json
        print(lookup_type, json.dumps(returned_data, indent=4))
        
        ##### GENERIC VIRUSTOTAL FIELDS
        if returned_data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
            status = 'Potentially malicious'
        elif returned_data['data']['attributes']['last_analysis_stats']['suspicious'] > 0:
            status = 'Suspicious'
        elif returned_data['data']['attributes']['total_votes']['malicious'] > returned_data['data']['attributes']['total_votes']['harmless']:
            status = 'Suspicious'
        else:
            status = 'Harmless or undetected'
        
        presentable_data['Status'] = status
        presentable_data['Community votes harmless'] = returned_data['data']['attributes']['total_votes']['harmless']
        presentable_data['Community votes malicious'] = returned_data['data']['attributes']['total_votes']['malicious']
        presentable_data['Reputation'] = returned_data['data']['attributes']['reputation']
        if len(returned_data['data']['attributes']['tags']) > 0:
            presentable_data['Tags'] = ", ".join(returned_data['data']['attributes']['tags'])
            
        ##### TYPE SPECIFIC VIRUSTOTAL FIELDS
        if lookup_type == LookupType.IP:
            presentable_data = self.get_suitable_values_for_ip(presentable_data=presentable_data, returned_data=returned_data)
        elif lookup_type == LookupType.DOMAIN:
            presentable_data = self.get_suitable_values_for_domain(presentable_data=presentable_data, returned_data=returned_data)
        elif lookup_type in [LookupType.SHA256, LookupType.SHA1, LookupType.MD5]:
            presentable_data = self.get_suitable_values_for_hash(presentable_data=presentable_data, returned_data=returned_data)
                    
        return presentable_data  
    
    def get_suitable_values_for_ip(self, presentable_data: dict, returned_data: dict):
        
        if 'country' in returned_data['data']['attributes'].keys():
            presentable_data['Country'] = returned_data['data']['attributes']['country']
                
        if 'as_owner' in returned_data['data']['attributes'].keys():
            presentable_data['AS Owner'] = returned_data['data']['attributes']['as_owner']
            
        if 'last_https_certificate_date' in returned_data['data']['attributes'].keys():
            presentable_data['x509 cert analysis date'] = convert_unix_epoch_to_standard_datetime(returned_data['data']['attributes']['last_https_certificate_date'])
            
        if 'last_https_certificate' in returned_data['data']['attributes'].keys():
            vt_res_last_https_certificate = returned_data['data']['attributes']['last_https_certificate'] 
            
            if 'ca_information_access' in vt_res_last_https_certificate['extensions'].keys():
                if 'CA Issuers' in vt_res_last_https_certificate['extensions']['ca_information_access'].keys():
                    presentable_data['CA issuer'] = vt_res_last_https_certificate['extensions']['ca_information_access']['CA Issuers']
            
            if 'subject' in vt_res_last_https_certificate.keys():
                if 'CN' in vt_res_last_https_certificate['subject'].keys():
                    presentable_data['Common name'] = vt_res_last_https_certificate['subject']['CN']
            
            if 'subject_alternative_name' in vt_res_last_https_certificate['extensions'].keys():
                presentable_data['Subject alternative name'] = ",".join(vt_res_last_https_certificate['extensions']['subject_alternative_name'])

            if 'validity' in vt_res_last_https_certificate.keys():
                presentable_data['Cert valid before'] = vt_res_last_https_certificate['validity']['not_after']
                presentable_data['Cert valid after'] = vt_res_last_https_certificate['validity']['not_before']

            if 'thumbprint' in vt_res_last_https_certificate.keys():
                presentable_data['Cert Fingerprint'] = vt_res_last_https_certificate['thumbprint']

            if 'thumbprint_sha256' in vt_res_last_https_certificate.keys():
                presentable_data['Cert Fingerprint (sha256)'] = vt_res_last_https_certificate['thumbprint_sha256']
                
        return presentable_data
    
    def get_suitable_values_for_domain(self, presentable_data: dict, returned_data: dict):
        
        if 'creation_date' in returned_data['data']['attributes'].keys():
             presentable_data['Creation date'] = convert_unix_epoch_to_standard_datetime(returned_data['data']['attributes']['creation_date'])
        
        if 'registrar' in returned_data['data']['attributes'].keys():
            presentable_data['Registrar'] = returned_data['data']['attributes']['registrar']
            
        if 'last_https_certificate_date' in returned_data['data']['attributes'].keys():
            presentable_data['Cert analysis date'] = convert_unix_epoch_to_standard_datetime(returned_data['data']['attributes']['last_https_certificate_date'])
        
        if 'last_https_certificate' in returned_data['data']['attributes'].keys():
            vt_res_last_https_certificate = returned_data['data']['attributes']['last_https_certificate'] 
            
            if 'ca_information_access' in vt_res_last_https_certificate['extensions'].keys():
                if 'CA Issuers' in vt_res_last_https_certificate['extensions']['ca_information_access'].keys():
                    presentable_data['CA issuer'] = vt_res_last_https_certificate['extensions']['ca_information_access']['CA Issuers']
            
            if 'subject' in vt_res_last_https_certificate.keys():
                if 'CN' in vt_res_last_https_certificate['subject'].keys():
                    presentable_data['Common name'] = vt_res_last_https_certificate['subject']['CN']
            
            if 'subject_alternative_name' in vt_res_last_https_certificate['extensions'].keys():
                presentable_data['Subject alternative name'] = ",".join(vt_res_last_https_certificate['extensions']['subject_alternative_name'])

            if 'validity' in vt_res_last_https_certificate.keys():
                presentable_data['Cert valid before'] = vt_res_last_https_certificate['validity']['not_after']
                presentable_data['Cert valid after'] = vt_res_last_https_certificate['validity']['not_before']

            if 'thumbprint' in vt_res_last_https_certificate.keys():
                presentable_data['Cert Fingerprint'] = vt_res_last_https_certificate['thumbprint']

            if 'thumbprint_sha256' in vt_res_last_https_certificate.keys():
                presentable_data['Cert Fingerprint (sha256)'] = vt_res_last_https_certificate['thumbprint_sha256']
        
        if 'whois' in returned_data['data']['attributes'].keys():
            presentable_data['Raw whois'] = returned_data['data']['attributes']['whois']
            
        return presentable_data
    
    
    def get_suitable_values_for_hash(self, presentable_data: dict, returned_data: dict):
        
        if 'pe_info' in returned_data['data']['attributes'].keys():
            vt_res_pe_info = returned_data['data']['attributes']['pe_info']
            if 'imphash' in vt_res_pe_info.keys():
                presentable_data['IMPHash'] = vt_res_pe_info['imphash']
            
            if 'import_list' in vt_res_pe_info.keys():
                imported_dlls = []
                for imports in vt_res_pe_info['import_list']:
                    if 'library_name' in imports.keys():
                        imported_dlls.append(imports['library_name'])
                presentable_data['Imported DLLs'] = ",".join(imported_dlls)
        
        if 'names' in returned_data['data']['attributes'].keys():
            presentable_data['File names'] = ",".join(returned_data['data']['attributes']['names'])
            
        if 'times_submitted' in returned_data['data']['attributes'].keys():
            presentable_data['Times submitted'] = returned_data['data']['attributes']['times_submitted']

        if 'detectiteasy' in returned_data['data']['attributes'].keys():
            vt_res_detectiteasy = returned_data['data']['attributes']['detectiteasy']
            if 'filetype' in vt_res_detectiteasy.keys():
                presentable_data['DetectItEasy.Filetype'] = vt_res_detectiteasy['filetype']
            
            if 'values' in vt_res_detectiteasy.keys():
                for value_index, value in enumerate(vt_res_detectiteasy['values']):
                    for field in value:
                        presentable_data[f'DetectItEasy.FileValue.{value_index}.{field}'] = value[field]
        return presentable_data
    
    
class AbuseIPDB(APILookup):

    def __init__(self, api_key:str = ""):
        super().__init__(api_key)
        self.name = "AbuseIPDB"
        self.headers = {"Key": self.api_key, 'Accept': 'application/json'}
        self.lookup_types = [LookupType.IP]
        self.api_key_required = True

    def get_data(self, lookup_type:LookupType, lookup_value: str) -> Tuple[APIStatusMessage, dict]:
        json_response = {}

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={lookup_value}&maxAgeInDays=90&verbose"
        
        try:
            response = self.requests.get(url, headers=self.headers)
            json_response = response.json()

            if response.status_code == 200:
                return APIStatusMessage.OK, self.get_presentable_data(json_response)
            elif response.status_code == 429:
                return APIStatusMessage.QUOTA_EXCEEDED, json_response
            elif response.status_code == 401 and 'Your API key is either missing, incorrect, or revoked' in json_response['errors'][0]['detail']:
                return APIStatusMessage.WRONG_CREDENTIALS, json_response
            else:
                ConsoleOutputPrint(msg=f"Error during {self.name} lookup of \"{lookup_type}\" \"{lookup_value}\". Response: {response.status_code}, {response.text}", print_type="error")
                return APIStatusMessage.NO_RESULTS, json_response
        except Exception as error_msg:
            ConsoleOutputPrint(msg=f"Error during {self.name} lookup of \"{lookup_type}\" \"{lookup_value}\": {str(error_msg)}", print_type="error")
            return APIStatusMessage.NO_RESULTS, json_response
    
    def get_presentable_data(self, returned_data: dict) -> dict:
        presentable_data: dict = {}
        status: str = ""
        
        if returned_data['data']['abuseConfidenceScore'] > 50:
            status = 'Potentially malicious'
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

        return presentable_data
