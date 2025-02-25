import json
import ipaddress
import sys
from typing import Tuple, Optional, Union
from datetime import datetime

#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.static import *
from lib.classes import *
from lib.output import *

NODE_COUNTER: int = 0
PROCESS_NODE_LOOKUP_INDEX: dict = {}
REPORTS: list = [] 

def lookup_endpoints(available_apis: dict, endpoints: dict, apis_to_use: list) -> None:  
    for api_name in apis_to_use:
        ConsoleOutputPrint(msg=f"Performing {api_name} API lookups...", print_type="info")
        api_key = available_apis[api_name]['api_key']
        class_reference = available_apis[api_name]['api']
        instance = class_reference(api_name, api_key)
        if not instance.has_api_prerequisites():
            ConsoleOutputPrint(msg=f"Skipping {api_name}. API-key is required", print_type="warning")
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

def start_http_server(directory: str, host: str, port: int) -> None:
  handler = lambda *args, **kwargs: HttpHandlerWithoutLogging(*args, directory=directory, **kwargs) 
  httpd = HTTPServer((host, port), handler)
  httpd.serve_forever()

def get_results_file_data(results_file:str) -> list:
    try:
        results_file_object = open(results_file, 'rt')
        results_json_data = json.load(results_file_object)
        return results_json_data
    except Exception as error_msg:
        ConsoleOutputPrint(msg=f"Error when reading results file: {str(error_msg)}", print_type="fatal")
        sys.exit(1)

def output_visualization_data(data_file: str, visualization_data:dict) -> None:
    try:
        json_file = open(data_file, "wt")
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

def file_exists_in_same_script_folder(directory: str, file: str) -> bool:
    if (directory / file).exists():
        return True
    else:
        return False
    
def get_port_information(transport_protocol: str, port: int) -> Union[str, None]: 
    if port in WELL_KNOWN_PORTS[transport_protocol]:
        return f" ({WELL_KNOWN_PORTS[transport_protocol][port]})"
    else:
        return None

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
                    port_information = get_port_information(transport_protocol = connection_record['TransportProtocol'], port = connection_record['DestinationPort'])
                    if port_information:
                        event_info += port_information
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

def has_prerequisites() -> bool:
    versions = MINIMUM_PYTHON_VERSION.split(".")
    major_version = int(versions[0])
    minor_version = int(versions[1])
    if sys.version_info >= (major_version, minor_version):
        return True
    else:
        return False    
    
def get_ip_or_domain_metadata(endpoint: str, type: NodeType) -> Tuple[list, bool]:
    metadata: list = []
    is_potentially_malicious: bool = False
    metadata.append(f"<h3 id='endpoint-type'>{type.title()}</h3>") 
    metadata.append(f"<p id='endpoint-value'>{endpoint}</p>") 
    for report in REPORTS:
        if endpoint == report.endpoint and report.endpoint_type == type:
            metadata.append(f"<p id='api-source-title'>{report.api_source}</p>")
            for presentable_title in report.presentable_data:
                metadata.append(get_html_attribute_and_value(title=presentable_title, value=report.presentable_data[presentable_title]))
            if report.is_potentially_malicious:
                is_potentially_malicious = True

    if type == NodeType.IP:
        if not is_private_ip_or_localhost(endpoint):
            metadata.append(f"<a id='ip-lookup-link' href='https://ipinfo.io/{endpoint}' target='_blank'>ipinfo.io</a>") 
            metadata.append(f"<a id='ip-lookup-link' href='https://www.virustotal.com/gui/ip-address/{endpoint}' target='_blank'>virustotal.com</a>")
            metadata.append(f"<a id='ip-lookup-link' href='https://www.abuseipdb.com/check/{endpoint}' target='_blank'>abuseipdb.com</a>")
        else:
            metadata.append(f"<p id='invalid-endpoint-title'>Private or localhost IP</p>")

    elif type == NodeType.DOMAIN:
        if is_valid_domain_name(endpoint):
            metadata.append(f"<a id='domain-lookup-link' href='https://www.whois.com/whois/{endpoint}' target='_blank'>whois.com</a>")
            metadata.append(f"<a id='domain-lookup-link' href='https://www.virustotal.com/gui/domain/{endpoint}' target='_blank'>virustotal.com</a>")
        else:
            metadata.append(f"<p id='invalid-endpoint-title'>Single-label domain</p>")
            
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

def valid_data_file_exists(data_file:str ) -> bool:
    try:
        with data_file.open("rt", encoding="utf-8") as f:
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

def prompt_user_for_apis_to_use(available_apis: dict) -> list:
    apis_to_use: list = []
    ConsoleOutputPrint(msg="Which APIs do you want to use to lookup IPs and domains?", print_type="info")
    print("enter \"all\" or nothing for every API, or enter the corresponding number for the ones you want to use.") 
    print("Multiple ones can be comma separate, e.g. 0,1,4")
    for counter, api_name in enumerate(available_apis):
        print(f" {counter}) {api_name}")
        
    while True:
        answer = input("Choice: ").strip().lower()
        if answer == "all" or answer == "":
            for api in available_apis:
                apis_to_use.append(api)
            break
        elif "," in answer:
            multiple_numbers_as_string = answer.split(",")
            multiple_numbers_as_integer: set = set()
            for value in multiple_numbers_as_string:
                try:
                    integer = int(value)
                    if integer >= len(available_apis) or integer < 0:
                        ConsoleOutputPrint(msg=f"Provided value {integer} doesn't exist. Skipping..", print_type="warning")
                    else:
                        multiple_numbers_as_integer.add(int(value))
                except Exception as e:
                    ConsoleOutputPrint(msg=f"Invalid number provided in the comma separated awnser: {answer}", print_type="error")
                    return prompt_user_for_apis_to_use()

            for integer in multiple_numbers_as_integer:
                apis_to_use.append(list(available_apis.keys())[integer])
            break
        else:
            try:
                integer = int(answer)
                apis_to_use.append(list(available_apis.keys())[integer])
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
