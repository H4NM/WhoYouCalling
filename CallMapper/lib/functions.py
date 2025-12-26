import json
import ipaddress
import sys
from typing import Tuple, Optional, Union
from datetime import datetime
import uuid


#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.static import *
from lib.classes import *
from lib.output import *

NODE_COUNTER: int = 0
PROCESS_NODE_LOOKUP_INDEX: dict = {}
REPORTS: list = [] 


def get_unique_id():
    return uuid.uuid4().hex[:24]

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

def get_results_file_data(results_file:str) -> dict:
    try:
        results_file_object = open(results_file, 'rt')
        return json.load(results_file_object)
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

def get_visualization_data(visualization_data:dict, result_file_id:str, results_file_counter:int, monitored_processes: list) -> dict:

    process_node_color: str = PROCESS_NODE_COLORS[results_file_counter-1]
    visualization_data['elements']['nodes'] = get_nodes(nodes=visualization_data['elements']['nodes'], 
                                                        process_node_color=process_node_color,
                                                        result_file_id=result_file_id, 
                                                        monitored_processes=monitored_processes)
    visualization_data['elements']['edges'] = get_edges(edges=visualization_data['elements']['edges'], nodes=visualization_data['elements']['nodes'], monitored_processes=monitored_processes)
    return visualization_data

def get_edges(edges:list, nodes:list, monitored_processes: list) -> dict:
    unique_dns_resolution_edges: list = []
    
    for index, process in enumerate(monitored_processes):
        current_process_node_id = PROCESS_NODE_LOOKUP_INDEX[index] 
        
        for child_process in process['ChildProcesses']:
            for index_2nd, process_2nd in enumerate(monitored_processes):
                if process_2nd['ProcessName'] == child_process['ProcessName'] and process_2nd['PID'] == child_process['PID']:
                    child_process_registered_etw_start_time: datetime = convert_to_datetime_object(child_process['StartTime'])
                    process_2nd_added_to_monitoring_time: datetime = convert_to_datetime_object(process_2nd['AddedToMonitoringTime'])
                    if datetime_is_in_range_by_seconds(reference_time=process_2nd_added_to_monitoring_time, 
                                                       range_time=child_process_registered_etw_start_time, 
                                                       max_second_range=PROCESS_START_SECONDS_RANGE):
                        child_process_node_id = PROCESS_NODE_LOOKUP_INDEX[index_2nd]
                        event_info: str = "started"
                        process_start_edge = get_edge(event=event_info, 
                                                      source=current_process_node_id, 
                                                      target=child_process_node_id,
                                                      type=EdgeType.PROCESS_START)
                        edges.append(process_start_edge)
        
        unique_destination_edges: list = []
        for connection_record in process['TCPIPTelemetry']:
            for node in nodes:
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
                    
                    edges.append(tcpip_edge)

        for dns_query in process['DNSQueries']:
            for node in nodes:
                if node["data"]["type"] == NodeType.DOMAIN and node["data"]["label"] == dns_query['DomainQueried']:
                    event_info: str = f"{dns_query['RecordTypeText']}({dns_query['RecordTypeCode']}) query"
                    domain_edge = get_edge(event=event_info,
                                           source=current_process_node_id, 
                                           target=node['data']['id'],
                                           type=EdgeType.DNS_QUERY)     
                    edges.append(domain_edge)
                    
        for dns_response in process['DNSResponses']:
            for node in nodes:
                if node["data"]["type"] == NodeType.DOMAIN and node["data"]["label"] == dns_response['DomainQueried']:
                    for resolved_ip in dns_response['QueryResult']['IPs']:
                        for node2 in nodes:
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
                                edges.append(domain_edge)
                        
    return edges

def get_edge(event: str, source: int, target:int, type: EdgeType) -> dict:
    return { "data": { "source": source, "target": target, "type": type, "info": event} } 

def get_node(label:str, type: NodeType, monitored_process:dict={}, process_node_color:str = "", result_file_id:str = "") -> dict:
    global NODE_COUNTER
    node: dict = { "data": { } } 
    NODE_COUNTER += 1
    node_info: list = []
    is_potentially_malicious = False
    node_color: str = ""
    node_shape: str = "ellipse"
    node_width: str = "30"
    node_height: str = "30"
    
    if type == NodeType.PROCESS:
        node_info = get_process_metadata(monitored_process=monitored_process, node_id=NODE_COUNTER)
        node_color = process_node_color
        node_width = "40"
        node_height = "40"
    elif type == NodeType.IP:
        node_info, is_potentially_malicious = get_ip_or_domain_metadata(endpoint=label, type=type)
        node_color = IP_NODE_COLOR
    elif type == NodeType.DOMAIN:
        node_info, is_potentially_malicious = get_ip_or_domain_metadata(endpoint=label, type=type)
        node_color = DOMAIN_NODE_COLOR
        
    if is_potentially_malicious:
        node_shape = "star"
        node_color = "#ff0000"
        node_width = "60"
        node_height = "60"
        
    node: dict = { "data": { 
                        "id": NODE_COUNTER, 
                        "type": type, 
                        "result_file_id": result_file_id,
                        "label": label, 
                        "shape": node_shape, 
                        "width": node_width, 
                        "height": node_height, 
                        "color": node_color, 
                        "info": '<br>'.join(node_info)} 
                  } 
        
    return node

def get_process_presentable_details(title:str = "", value:str = "", metadata: list = []) -> list:
    if value != None:
        html_node_attribute: str = get_html_attribute_and_value(title=title, value=value)
        metadata.append(html_node_attribute)
    return metadata

def get_html_attribute_and_value(title: str = "", value:str = "") -> str:
    return f"<b>{title}</b>: {value}"

def get_process_metadata(monitored_process: dict, node_id: int) -> list:
    metadata: list = []
    metadata.append(f"<h3 id='endpoint-type'>Process</h3>") 
    metadata.append(f"<p id='endpoint-value'>{monitored_process['ProcessName']}-{monitored_process['PID']}</p>") 

    process_attributes = {
        'Commandline': monitored_process['CommandLine'],
        'Protected process': monitored_process['IsolatedProcess'],
        'Started': monitored_process['StartTime'],
        'Stopped': monitored_process['StopTime']
    }
    
    process_executable_attributes = {
        'File path': monitored_process['Executable']['FilePath'],
        'MD5': monitored_process['Executable']['MD5'],
        'SHA1': monitored_process['Executable']['SHA1'],
        'SHA256': monitored_process['Executable']['SHA256'],
        'Is signed': monitored_process['Executable']['IsSigned'],
        'Created': monitored_process['Executable']['CreatedTimestamp']
    }
    
    for title in process_attributes:
        metadata = get_process_presentable_details(title=title, value=process_attributes[title], metadata=metadata)
    
    if process_executable_attributes['File path'] != None:
        metadata.append(f"<h4>Executable</h3>") 

        for title in process_executable_attributes:
            metadata = get_process_presentable_details(title=title, value=process_executable_attributes[title], metadata=metadata)
    
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

def get_nodes(nodes: list, process_node_color:str, result_file_id:str, monitored_processes: list) -> list:
    ips = set()
    domains = set()
    for index, process in enumerate(monitored_processes): 
        process_node: dict = get_node(label=f"{process['ProcessName']}-{process['PID']}", 
                                      type=NodeType.PROCESS, 
                                      monitored_process=process, 
                                      process_node_color=process_node_color, 
                                      result_file_id=result_file_id)
        PROCESS_NODE_LOOKUP_INDEX[index] = process_node['data']['id'] # Used when establishing edges to know which correlate process to activity
        
        nodes.append(process_node)
        
        for connection_record in process["TCPIPTelemetry"]:
            ips.add(connection_record["DestinationIP"])
        for connection_record in process["DNSQueries"]:
            domains.add(connection_record["DomainQueried"])
        for connection_record in process["DNSResponses"]:
            domains.add(connection_record["DomainQueried"])
     
    for ip in ips:
        mapped_ip: bool = False
        ip_node: dict = get_node(label=ip, type=NodeType.IP)
        
        # Check if the IP has already been mapped - to avoid duplicates
        for node in nodes:
            if node['data']['type'] == 'ip' and node['data']['label'] == ip_node['data']['label']:
                mapped_ip = True
        if not mapped_ip:
            nodes.append(ip_node)
    
    for domain in domains:
        mapped_domain: bool = False
        domain_node: dict = get_node(label=domain, type=NodeType.DOMAIN)
        # Check if the domain has already been mapped - to avoid duplicates
        for node in nodes:
            if node['data']['type'] == 'domain' and node['data']['label'] == ip_node['data']['label']:
                mapped_ip = True
        if not mapped_domain:
            nodes.append(domain_node)
    return nodes

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
