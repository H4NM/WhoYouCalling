import json
import os
import sys
import ipaddress
import argparse
from pathlib import Path
from typing import Tuple, Optional
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime

#=====================================
#  API LOOKUP IMPORTS
#=====================================
from api_lookups import *
from custom_api_lookups import *

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
        'api': VirusTotal,
    },
    'AbuseIPDB': {
        'api_key': '', 
        'api': AbuseIPDB,
    }
}

#==================================================
#  Dont touch these variables or anything below :) 
#==================================================
SCRIPT_BANNER = r"""  
        o=o        o         o--o   o            *
   _____      _ _ __  __         \\    o-o        \    
  / ____|    | | |  \/  |    o     o-o             o         
 | |     __ _| | | \  / | __ _ _ __  _ __   ___ _ __ 
 | |    / _` | | | |\/| |/ _` | '_ \| '_ \ / _ \ '__|  o
 | |___| (_| | | | |  | | (_| | |_) | |_) |  __/ |    /
  \_____\__,_|_|_|_|  |_|\__,_| .__/| .__/ \___|_|   o  
  *Part of WhoYouCalling      | |   | |           
                              |_|   |_|           
        o--o                              o--o--o--o
"""
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
REPORTS: list = []    


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

def lookup_endpoints(endpoints: dict, apis_to_use: list) -> None:  
    for api_name in apis_to_use:
        ConsoleOutputPrint(msg=f"Performing {api_name} API lookups...", print_type="info")
        api_key = API_LOOKUPS[api_name]['api_key']
        class_reference = API_LOOKUPS[api_name]['api']
        instance = class_reference(api_name, api_key)
        if not instance.has_api_prerequisites():
            ConsoleOutputPrint(msg=f"API key required for lookup via {api_name}. Skipping..", print_type="warning")
            continue
        REPORTS.extend(instance.lookup(endpoints)) 

def is_private_ip_or_localhost(ip):
    ip_obj = ipaddress.ip_address(ip)
    if ip_obj.is_private or ip_obj.is_loopback:
        return True
    else:
        return False

def is_valid_domain_name(domain):
    if "." in domain:
        return True
    else:
        return False

def get_unique_endpoints_to_lookup(monitored_processes: dict, processes_to_lookup_with_network_activity: list) -> dict:
    endpoints: dict = {
        'domains': set(),
        'ips': set()
    }
    
    for process in monitored_processes:
        if process['ProcessName'] in processes_to_lookup_with_network_activity:
            for connection_record in process['TCPIPTelemetry']:
                if not is_private_ip_or_localhost(connection_record['DestinationIP']):
                    endpoints['ips'].add(connection_record['DestinationIP'])
            for dns_query in process['DNSQueries']:
                if is_valid_domain_name(dns_query['DomainQueried']):
                    endpoints['domains'].add(dns_query['DomainQueried'])
            for dns_response in process['DNSResponses']:
                if is_valid_domain_name(dns_response['DomainQueried']):
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

def valid_structure(data, expected) -> bool:
    if not isinstance(data, dict) or not isinstance(expected, dict):
        return isinstance(data, expected)
    for key, value in expected.items():
        if key not in data or not valid_structure(data[key], value):
            return False
    return True

def file_exists_in_same_script_folder(file: str) -> bool:
    if (SCRIPT_DIRECTORY / file).exists():
        return True
    else:
        return False

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
        metadata.append(f"<a href='https://www.abuseipdb.com/check/{endpoint}' target='_blank'>abuseipdb.com</a>")
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

def get_unique_process_names_with_external_network_activity(monitored_processes: dict) -> set:
    unique_process_names = set()
    for process in monitored_processes:
        if process_has_network_activity(process):
            unique_process_names.add(process['ProcessName'])
    return sorted(unique_process_names)

def process_has_network_activity(process: dict) -> bool:
    not_only_private_or_loopback_traffic: bool = False
    if len(process['TCPIPTelemetry']):
        for connection_record in process['TCPIPTelemetry']:
            if not is_private_ip_or_localhost(connection_record['DestinationIP']):
                not_only_private_or_loopback_traffic = True

    if len(process['TCPIPTelemetry']) > 0 and not_only_private_or_loopback_traffic:
        return True
    elif len(process['DNSQueries']) > 0:
        return True
    elif len(process['DNSResponses']) > 0:
        return True
    else:
        return False

def valid_data_file_exists() -> bool:
    try:
        with DATA_FILE.open("rt", encoding="utf-8") as f:
            data = json.load(f)
        if valid_structure(data, DATA_FILE_JSON_STRUCTURE):
            return True
        else:
            return False
    except json.JSONDecodeError:
        return False

def prompt_user_for_processes_to_lookup(unique_process_names: set) -> list:
    processes_to_lookup: list = []
    ConsoleOutputPrint(msg="Which processes with network activity do you want to lookup IPs and domains for?", print_type="info")
    print("enter \"all\" or nothing for every process, or enter the corresponding number for the ones you want to lookup.") 
    print("Multiple ones can be comma separate, e.g. 3,5,7")
    for counter, process_name in enumerate(unique_process_names):
        print(f" {counter}) {process_name}")
        
    while True:
        answer = input("Choice: ").strip().lower()
        if answer == "all" or answer == "":
            for process_name in unique_process_names:
                processes_to_lookup.append(process_name)
            break
        elif "," in answer:
            multiple_numbers_as_string = answer.split(",")
            multiple_numbers_as_integer: set = set()
            for value in multiple_numbers_as_string:
                try:
                    integer = int(value)
                    if integer >= len(unique_process_names) or integer < 0:
                        ConsoleOutputPrint(msg=f"Provided value {integer} doesn't exist. Skipping..", print_type="warning")
                    else:
                        multiple_numbers_as_integer.add(int(value))
                except:
                    ConsoleOutputPrint(msg=f"Invalid number provided in the comma separated awnser: {answer}", print_type="error")
                    return prompt_user_for_processes_to_lookup(unique_process_names)

            for integer in multiple_numbers_as_integer:
                processes_to_lookup.append(unique_process_names[integer])
            break
        else:
            try:
                integer = int(answer)
                processes_to_lookup.append(unique_process_names[integer])
                break
            except:
                ConsoleOutputPrint(msg=f"Invalid answer provided: {answer}", print_type="warning")
    return processes_to_lookup

def prompt_user_for_apis_to_use() -> list:
    apis_to_use: list = []
    ConsoleOutputPrint(msg="Which APIs do you want to use to lookup IPs and domains?", print_type="info")
    print("enter \"all\" or nothing for every API, or enter the corresponding number for the ones you want to use.") 
    print("Multiple ones can be comma separate, e.g. 0,1,4")
    for counter, api_name in enumerate(API_LOOKUPS):
        print(f" {counter}) {api_name}")
        
    while True:
        answer = input("Choice: ").strip().lower()
        if answer == "all" or answer == "":
            for api in API_LOOKUPS:
                apis_to_use.append(api)
            break
        elif "," in answer:
            multiple_numbers_as_string = answer.split(",")
            multiple_numbers_as_integer: set = set()
            for value in multiple_numbers_as_string:
                try:
                    integer = int(value)
                    if integer >= len(API_LOOKUPS) or integer < 0:
                        ConsoleOutputPrint(msg=f"Provided value {integer} doesn't exist. Skipping..", print_type="warning")
                    else:
                        multiple_numbers_as_integer.add(int(value))
                except Exception as e:
                    ConsoleOutputPrint(msg=f"Invalid number provided in the comma separated awnser: {answer}", print_type="error")
                    return prompt_user_for_apis_to_use()

            for integer in multiple_numbers_as_integer:
                apis_to_use.append(list(API_LOOKUPS.keys())[integer])
            break
        else:
            try:
                integer = int(answer)
                apis_to_use.append(list(API_LOOKUPS.keys())[integer])
                break
            except:
                ConsoleOutputPrint(msg=f"Invalid answer provided: {answer}", print_type="warning")
    return apis_to_use

def prompt_user_for_overwrite_of_data_file() -> bool:
    while True:
        answer = input("[!] An existing data.json file was found in the same directory as the script. Overwrite it? (Y/n): ").strip().lower()
        if answer == "y" or answer == "":
            return True
        elif answer == "n":
            return False
        else:
            ConsoleOutputPrint(msg=f"Invalid input. Please enter 'y' or 'n'.", print_type="warning")

def main() -> None:
    parser = argparse.ArgumentParser(description="A script demonstrating argparse with flags.")
    parser.add_argument("-r", "--results-file", type=str, help="Results file")
    parser.add_argument("-a", "--api-lookup", action="store_true", help="Lookup endpoints against defined APIs")
    args = parser.parse_args()
    print(SCRIPT_BANNER)
    
    if not file_exists_in_same_script_folder("index.html"):
        ConsoleOutputPrint(msg=f"Unable to find index.html in the same directory as the script", print_type="fatal")
        sys.exit(1)
        
    if not args.results_file:
        if not file_exists_in_same_script_folder("data.json"):
            ConsoleOutputPrint(msg=f"Unable to find data.json in the same directory as the script. Please supply a Results.json file or move data.json to the same path as the script", print_type="fatal")
            sys.exit(1)
        if not valid_data_file_exists():
            ConsoleOutputPrint(msg=f"{DATA_FILE} has an invalid JSON structure", print_type="fatal")
            sys.exit(1)
    
    if args.api_lookup and not requests_is_installed():
        msg ="""
The library 'requests' doesn't seem to be installed.
It's needed to perform API lookups
Run the following to install it: 

pip install requests

            """
        ConsoleOutputPrint(msg, print_type="fatal")
        sys.exit(1)
        
    if args.results_file:
        ConsoleOutputPrint(msg=f"Retrieving data from results file", print_type="info")
        monitored_processes: list = get_results_file_data(args.results_file)
        
        if args.api_lookup:
            unique_process_names: set = get_unique_process_names_with_external_network_activity(monitored_processes)
            processes_to_lookup_with_network_activity: list = prompt_user_for_processes_to_lookup(unique_process_names)
            endpoints: dict = get_unique_endpoints_to_lookup(monitored_processes, processes_to_lookup_with_network_activity)
            apis_to_use: list = prompt_user_for_apis_to_use()
            lookup_endpoints(endpoints, apis_to_use) 
        
        ConsoleOutputPrint(msg=f"Creating visualization data", print_type="info")
        visualization_data = get_visualization_data(monitored_processes)
        if os.path.isfile(DATA_FILE):
            if prompt_user_for_overwrite_of_data_file():
                ConsoleOutputPrint(msg=f"Overwriting existing data.json.", print_type="info")
                output_visualization_data(visualization_data)
            else:
                ConsoleOutputPrint(msg=f"Keeping existing data.json", print_type="info")
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