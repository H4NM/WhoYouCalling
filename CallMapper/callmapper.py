import json
import os
import sys
import ipaddress
from pathlib import Path
from typing import Tuple, Optional
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime

#=====================================
#  API LOOKUP IMPORTS
#=====================================
import api_lookups

#=====================================
#  CHANGABLE VARIABLES AND FUNCTIONS
#=====================================
HTTP_HOST_ADRESS:str = "127.0.0.1"
HTTP_HOST_PORT:int = 8080
VIRUSTOTAL_API_KEY: str = ""
ABUSEIPDB_API_KEY: str = ""
API_LOOKUPS = {
    'VirusTotal': {
        'api_key': '', 
        'api': api_lookups.VirusTotalLookup,
    },
    'AbuseIPDB': {
        'api_key': '', 
        'api': api_lookups.get_abuseipdb_report,
    }
}


#==================================================
#  Dont touch these variables or anything below :) 
#==================================================
NODE_COUNTER: int = 0
PROCESS_NODE_LOOKUP_INDEX: dict = {}
PROCESS_START_SECONDS_RANGE: int = 3
SCRIPT_DIRECTORY: Path.parent = Path(__file__).parent
HTML_FILE: str = SCRIPT_DIRECTORY / "index.html"
DATA_FILE: str = SCRIPT_DIRECTORY / "data.json"
PERFORM_LOOKUP: bool = False
DATA_FILE_JSON_STRUCTURE: dict = {
    "elements": {
        "nodes": list,
        "edges": list
    }
}
REPORTS = []    


class LookupType:
    IP = "ip"
    DOMAIN = "domain"
    
class Report:
    def __init__(self, api_source: str, endpoint:str, endpoint_type: LookupType, presentable_data: list, is_potentially_malicious: bool):
        self.api_source = api_source
        self.endpoint = endpoint
        self.endpoint_type = endpoint_type
        self.is_potentially_malicious=is_potentially_malicious
        self.presentable_data = []
        for title in presentable_data:
            self.presentable_data.append(get_html_attribute_and_value(title=title, value=presentable_data[title]))
        
class NodeType:
    PROCESS = "process"
    IP = "ip"
    DOMAIN = "domain"
    
class EdgeType:
    PROCESS_START = "processStart"
    DNS_QUERY = "dnsQuery"
    DNS_RESOLUTION = "dnsResolution"
    TCPIP_CONNECTION = "tcpipConnection"
    
class HttpHandlerWithoutLogging(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        return str(SCRIPT_DIRECTORY.resolve() / path.lstrip("/"))
    
    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()
        
    def log_message(self, format, *args): 
        return 

def lookup_endpoints(endpoints: dict) -> None:  
    for name, details in API_LOOKUPS.items():
        ConsoleOutputPrint(msg=f"Performing lookup of endpoints via {name}", print_type="info")
        api_key = details['api_key']
        class_ref = details['api']
        instance = class_ref(name, api_key)
        if instance.has_api_prerequisites():
            ConsoleOutputPrint(msg=f"API key required for lookup via {name}. Skipping..", print_type="warning")
            continue
        result = class_ref(name, api_key).lookup(endpoints)  
        
    for API in API_LOOKUPS:
        API_LOOKUPS[API]['function'](endpoints, API, API_LOOKUPS[API]['api_key'])

def get_unique_endpoints_to_lookup(monitored_processes: dict) -> dict:
    endpoints: dict = {
        'domains': set(),
        'ips': set()
    }
    for process in monitored_processes:
        for connection_record in process['TCPIPTelemetry']:
            endpoints['ips'].add(connection_record['DestinationIP'])
        for dns_query in process['DNSQueries']:
            endpoints['domains'].add(dns_query['DomainQueried'])
        for dns_response in process['DNSResponses']:
            endpoints['domains'].add(dns_response['DomainQueried'])
    return endpoints

def requests_is_installed() -> bool:
    try:
        import requests
        return True
    except ImportError:
        return False

def is_bundled_ipv4(ipv6_address: str) -> Tuple[bool, Optional[str]]:
    try:
        ip = ipaddress.ip_address(ipv6_address)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            return True, str(ip.ipv4_mapped)  
        else:
            return False, None
    except Exception as error_msg:
        ConsoleOutputPrint(msg=f"Error checking if IP was IPv6 mapped IPv4 address {ipv6_address}: {str(error_msg)}", print_type="warning")
        return False, None

def datetime_is_in_range_by_seconds(reference_time: datetime, range_time: datetime, max_second_range: int) -> bool:
    if abs((reference_time - range_time).total_seconds()) <= max_second_range:
        return True
    else:
        return False

def convert_to_datetime_object(date_str: str) -> datetime:
    if '.' in date_str:
        base, fraction = date_str.split('.', 1)
        if '+' in fraction or 'Z' in fraction:
            fraction, offset = fraction.split('+', 1) if '+' in fraction else fraction.split('Z', 1)
            fraction = fraction[:6] 
            date_str = f"{base}.{fraction}+{offset}" if '+' in date_str else f"{base}.{fraction}Z"
        else:
            fraction = fraction[:6] 
            date_str = f"{base}.{fraction}"
    return datetime.fromisoformat(date_str)

def start_http_server() -> None:
  httpd = HTTPServer((HTTP_HOST_ADRESS, HTTP_HOST_PORT), HttpHandlerWithoutLogging)
  httpd.serve_forever()
  
def ConsoleOutputPrint(msg: str = "", print_type: str = "info") -> None:
    prefix: str = ""
    if print_type == "info": 
        prefix = "[*]"
    elif print_type == "warning":
        prefix = "[!]"
    elif print_type == "error":
        prefix = "[?]"
    elif print_type == "fatal":
        prefix = "[!!!]"
    print(f"{prefix} {msg}")

def get_results_file_data(results_file:str) -> list:
    try:
        results_file_object = open(results_file, 'rt')
        results_json_data = json.load(results_file_object)
        return results_json_data
    except Exception as error_msg:
        ConsoleOutputPrint(msg=f"Error when reading results file: {str(error_msg)}", print_type="fatal")
        sys.exit(1)

def output_visualization_data(visualization_data:dict) -> None:
    try:
        json_file = open(DATA_FILE, "wt")
        json.dump(visualization_data, json_file, indent=4)
        json_file.close()
    except Exception as error_msg:
        ConsoleOutputPrint(msg=f"Error when creating visualization data file: {str(error_msg)}", print_type="fatal")
        sys.exit(1)

def validate_structure(data, expected) -> bool:
    if not isinstance(data, dict) or not isinstance(expected, dict):
        return isinstance(data, expected)
    for key, value in expected.items():
        if key not in data or not validate_structure(data[key], value):
            return False
    return True

def index_file_exists() -> bool:
    if HTML_FILE.exists():
        return True
    else:
        return False

def provided_result_file(args: list) -> bool:
    global PERFORM_LOOKUP
    
    if len(args) >= 2:
        results_file:str = sys.argv[1] 
        if not os.path.isfile(results_file):
            ConsoleOutputPrint(msg=f"The provided results file {results_file} is not a valid file.", print_type="error")
            sys.exit(1)
        else:
            if len(args) == 3 and args[2] == 'lookup':
                if requests_is_installed():
                    ConsoleOutputPrint("Required libraries are installed", print_type="info")
                    PERFORM_LOOKUP = True
                else:
                    msg ="""
The library 'requests' doesn't seem to be installed.
It's needed to perform API lookups
Run the following to install it: 
        
        pip install requests

                    """
                    ConsoleOutputPrint(msg, print_type="fatal")
                    sys.exit(1)
            return True
        
    if DATA_FILE.exists():
        try:
            with DATA_FILE.open("rt", encoding="utf-8") as f:
                data = json.load(f)
            if validate_structure(data, DATA_FILE_JSON_STRUCTURE):
                return False
            else:
                ConsoleOutputPrint(msg=f"The provided data file has an invalid JSON structure", print_type="error")
                sys.exit(1)
        except json.JSONDecodeError:
            ConsoleOutputPrint(msg=f"The provided data file has an invalid JSON format", print_type="error")
            sys.exit(1)
    else:
        ConsoleOutputPrint(msg=f"No results file provided nor was a data.json file found in the same directory as the script.", print_type="error")
        sys.exit(1)

def get_visualization_data(monitored_processes: list) -> dict:
    visualization_data = {
        "elements": {
            "nodes": [],
            "edges": []
        }
    }
    visualization_data = get_nodes(visualization_data, monitored_processes)
    visualization_data = get_edges(visualization_data, monitored_processes)
    return visualization_data

def get_edges(visualization_data: dict, monitored_processes: list) -> dict:
    unique_dns_resolution_edges: list = []

    for index, process in enumerate(monitored_processes):
        current_process_node_id = PROCESS_NODE_LOOKUP_INDEX[index] 
        
        for child_process in process['ChildProcesses']:
            for index_2nd, process_2nd in enumerate(monitored_processes):
                if process_2nd['ProcessName'] == child_process['ProcessName'] and process_2nd['PID'] == child_process['PID']:
                    child_process_registered_etw_start_time: datetime = convert_to_datetime_object(child_process['ETWRegisteredStartTime'])
                    process_2nd_added_to_monitoring_time: datetime = convert_to_datetime_object(process_2nd['ProcessAddedToMonitoringTime'])
                    if datetime_is_in_range_by_seconds(reference_time=process_2nd_added_to_monitoring_time, 
                                                       range_time=child_process_registered_etw_start_time, 
                                                       max_second_range=PROCESS_START_SECONDS_RANGE):
                        child_process_node_id = PROCESS_NODE_LOOKUP_INDEX[index_2nd]
                        event_info: str = "started"
                        process_start_edge = get_edge(event=event_info, 
                                                      source=current_process_node_id, 
                                                      target=child_process_node_id,
                                                      type=EdgeType.PROCESS_START)
                        visualization_data["elements"]["edges"].append(process_start_edge)
        
        unique_destination_edges: list = []
        for connection_record in process['TCPIPTelemetry']:
            for node in visualization_data["elements"]["nodes"]:
                if node["data"]["type"] == NodeType.IP and node["data"]["label"] == connection_record['DestinationIP']:
                    simple_connection_record = { 
                                                'dest': connection_record['DestinationIP'],
                                                'dest_port': connection_record['DestinationPort'],
                                                'protocol': connection_record['TransportProtocol'],
                                                'ip_version': connection_record['IPversion']
                                                }
                    if simple_connection_record in unique_destination_edges:
                        continue
                    unique_destination_edges.append(simple_connection_record)
                    
                    event_info: str = f"{connection_record['TransportProtocol']} port {connection_record['DestinationPort']}"
                    tcpip_edge = get_edge(event=event_info, 
                                          source=current_process_node_id, 
                                          target=node['data']['id'],
                                          type=EdgeType.TCPIP_CONNECTION)     
                    
                    visualization_data["elements"]["edges"].append(tcpip_edge)

        for dns_query in process['DNSQueries']:
            for node in visualization_data["elements"]["nodes"]:
                if node["data"]["type"] == NodeType.DOMAIN and node["data"]["label"] == dns_query['DomainQueried']:
                    event_info: str = f"{dns_query['RecordTypeText']}({dns_query['RecordTypeCode']}) query"
                    domain_edge = get_edge(event=event_info,
                                           source=current_process_node_id, 
                                           target=node['data']['id'],
                                           type=EdgeType.DNS_QUERY)     
                    visualization_data["elements"]["edges"].append(domain_edge)
                    
        for dns_response in process['DNSResponses']:
            for node in visualization_data["elements"]["nodes"]:
                if node["data"]["type"] == NodeType.DOMAIN and node["data"]["label"] == dns_response['DomainQueried']:
                    for resolved_ip in dns_response['QueryResult']['IPs']:
                        for node2 in visualization_data["elements"]["nodes"]:
                            is_bundled_ipv4_address, mapped_ipv4 = is_bundled_ipv4(resolved_ip)
                            
                            if is_bundled_ipv4_address:
                                resolved_ip = mapped_ipv4
                                
                            if node2["data"]["type"] == NodeType.IP and node2["data"]["label"] == resolved_ip:
                                
                                simple_dns_resolution = { 
                                                            'domain': dns_response['DomainQueried'],
                                                            'ip': resolved_ip,
                                                            'type': dns_response['RecordTypeText'],
                                                            'type_code': dns_response['RecordTypeCode']
                                                        }
                                if simple_dns_resolution in unique_dns_resolution_edges:
                                    continue
                                unique_dns_resolution_edges.append(simple_dns_resolution)
                                
                                event_info: str = f"{dns_response['RecordTypeText']}({dns_response['RecordTypeCode']}) response"
                                domain_edge = get_edge(event=event_info,
                                                       source=node['data']['id'], 
                                                       target=node2['data']['id'],
                                                       type=EdgeType.DNS_RESOLUTION)     
                                visualization_data["elements"]["edges"].append(domain_edge)
                        
    return visualization_data

def get_edge(event: str, source: int, target:int, type: EdgeType) -> dict:
    return { "data": { "source": source, "target": target, "type": type, "info": event} } 

def get_node(label:str, type: NodeType, monitored_process={}) -> dict:
    global NODE_COUNTER
    NODE_COUNTER += 1
    node_info: list = []
    is_potentially_malicious = False
    node_color: str = ""
    node_shape: str = "ellipse"
    node_width: str = "30"
    node_height: str = "30"
    
    if type == NodeType.PROCESS:
        node_info = get_process_metadata(monitored_process=monitored_process, node_id=NODE_COUNTER)
        node_color = "#cc00cc"
        node_width = "40"
        node_height = "40"
    elif type == NodeType.IP:
        node_info, is_potentially_malicious = get_ip_or_domain_metadata(endpoint=label, type=type)
        node_color = "#2ffcf3"
    elif type == NodeType.DOMAIN:
        node_info, is_potentially_malicious = get_ip_or_domain_metadata(endpoint=label, type=type)
        node_color = "#fcf62f"
        
    if is_potentially_malicious:
        node_shape = "star"
        node_color = "#ff0000"
        node_width = "60"
        node_height = "60"
        
    node: dict = { "data": { "id": NODE_COUNTER, "type": type, "label": label, "shape": node_shape, "width": node_width, "height": node_height, "color": node_color, "info": '<br>'.join(node_info)} } 
        
    return node

def get_html_attribute_and_value(title: str = "", value:str = "") -> str:
    return f"<b>{title}</b>: {value}"

def get_process_metadata(monitored_process: dict, node_id: int) -> list:
    metadata: list = []
    html_node_attribute: str = ""
    metadata.append(f"<h3 id='endpoint-type'>Process</h3>") 
    metadata.append(f"<p id='endpoint-value'>{monitored_process['ProcessName']}-{monitored_process['PID']}</p>") 
    if monitored_process['ExecutableFileName'] != None:
        html_node_attribute = get_html_attribute_and_value(title="Executable", value=monitored_process['ExecutableFileName'])
        metadata.append(html_node_attribute)
    if monitored_process['CommandLine'] != None:
        html_node_attribute = get_html_attribute_and_value(title="Commandline", value=monitored_process['CommandLine'])
        metadata.append(html_node_attribute)
    if monitored_process['IsolatedProcess'] != None:
        html_node_attribute = get_html_attribute_and_value(title="Protected process", value=monitored_process['IsolatedProcess'])
        metadata.append(html_node_attribute)
    if monitored_process['ProcessStartTime'] != None:
        html_node_attribute = get_html_attribute_and_value(title="Started", value=monitored_process['ProcessStartTime'])
        metadata.append(html_node_attribute)
    if monitored_process['ProcessStopTime'] != None:
        html_node_attribute = get_html_attribute_and_value(title="Stopped", value=monitored_process['ProcessStopTime'])
        metadata.append(html_node_attribute)
    metadata.append(f"<button id='deselect-button' onclick=\"deselectNode({node_id})\">Hide process</button>") 
    return metadata

def get_ip_or_domain_metadata(endpoint: str, type: NodeType) -> Tuple[list, bool]:
    metadata: list = []
    is_potentially_malicious: bool = False
    metadata.append(f"<h3 id='endpoint-type'>{type.title()}</h3>") 
    metadata.append(f"<p id='endpoint-value'>{endpoint}</p>") 
    for report in REPORTS:
        if endpoint == report.endpoint and report.endpoint_type == type:
            metadata.append(f"<p id='api-source-title'>{report.api_source}</p>")
            for presentable_text in report.presentable_data:
                metadata.append(presentable_text)
            if report.is_potentially_malicious:
                is_potentially_malicious = True

    if type == NodeType.IP:
        metadata.append(f"<a href='https://ipinfo.io/{endpoint}' target='_blank'>ipinfo.io</a>")
        metadata.append(f"<a href='https://www.virustotal.com/gui/ip-address/{endpoint}' target='_blank'>virustotal.com</a>")
    elif type == NodeType.DOMAIN:
        metadata.append(f"<a href='https://www.whois.com/whois/{endpoint}' target='_blank'>whois.com</a>")
        metadata.append(f"<a href='https://www.virustotal.com/gui/domain/{endpoint}' target='_blank'>virustotal.com</a>")

    return metadata, is_potentially_malicious

def get_nodes(visualization_data: dict, monitored_processes: list) -> dict:
    ips = set()
    domains = set()
    for index, process in enumerate(monitored_processes): 
        process_node: dict = get_node(label=f"{process['ProcessName']}-{process['PID']}", type=NodeType.PROCESS, monitored_process=process)
        PROCESS_NODE_LOOKUP_INDEX[index] = process_node['data']['id'] # Used when establishing edges to know which correlate process to activity
        
        visualization_data["elements"]["nodes"].append(process_node)
        
        for connection_record in process["TCPIPTelemetry"]:
            ips.add(connection_record["DestinationIP"])
        for connection_record in process["DNSQueries"]:
            domains.add(connection_record["DomainQueried"])
        for connection_record in process["DNSResponses"]:
            domains.add(connection_record["DomainQueried"])
     
    for ip in ips:
        ip_node: dict = get_node(label=ip, type=NodeType.IP)
        visualization_data["elements"]["nodes"].append(ip_node)
    
    for domain in domains:
        domain_node: dict = get_node(label=domain, type=NodeType.DOMAIN)
        visualization_data["elements"]["nodes"].append(domain_node)
    
    return visualization_data

def main() -> None:
    if not index_file_exists():
        ConsoleOutputPrint(msg=f"Unable to find index.html in the same directory as the script", print_type="error")
        sys.exit(1)
    results_file_was_provided: bool = provided_result_file(sys.argv)
    if results_file_was_provided:
        results_file: str = sys.argv[1]
        ConsoleOutputPrint(msg=f"Retrieving data from results file", print_type="info")
        monitored_processes: list = get_results_file_data(results_file)
        
        if PERFORM_LOOKUP:
            endpoints: dict = get_unique_endpoints_to_lookup(monitored_processes)
            lookup_endpoints(endpoints) 
        
        ConsoleOutputPrint(msg=f"Creating visualization data", print_type="info")
        visualization_data = get_visualization_data(monitored_processes)
        if os.path.isfile(DATA_FILE):
            while True:
                answer = input("[!] An existing data.json file was found in the same directory as the script. Do you want to overwrite it? (Y/n): ").strip().lower()
                if answer == "y" or answer == "":
                    ConsoleOutputPrint(msg=f"Overwriting existing data.json.", print_type="info")
                    output_visualization_data(visualization_data)
                    break
                elif answer == "n":
                    ConsoleOutputPrint(msg=f"Keeping existing data.json", print_type="info")
                    break  
                else:
                    ConsoleOutputPrint(msg=f"Invalid input. Please enter 'y' or 'n'.", print_type="warning")
        else:
            output_visualization_data(visualization_data)
    else:
        ConsoleOutputPrint(msg=f"Visualizing from existing results file", print_type="info")
    ConsoleOutputPrint(msg=f"Hosting visualization via http://{HTTP_HOST_ADRESS}:{HTTP_HOST_PORT}", print_type="info")
    try:
        start_http_server()
    except KeyboardInterrupt:
        ConsoleOutputPrint(msg=f"Keyboard interuppt. HTTP server shut down", print_type="info")

if __name__ == "__main__":
    main()