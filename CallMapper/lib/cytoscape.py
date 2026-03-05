import datetime

from lib.classes.EdgeType import EdgeType
from lib.classes.NodeType import NodeType
from lib.static.static import PROCESS_START_SECONDS_RANGE
from lib.utils import convert_to_datetime_object, datetime_is_in_range_by_seconds, normalize_windows_path
from lib.network import get_port_information, is_bundled_ipv4, is_ip_private, is_ip_multicast, is_ip_ipv4, is_valid_domain_name, is_ip_localhost_or_linklocal

NODE_COUNTER: int = 1000 # Start high since the result files start at 1 which is also used as the ID for the groups that are also nodes
PROCESS_NODE_LOOKUP_INDEX: dict = {}

def get_visualization_data(visualization_data:dict, result_file_id:str, capture_group_color: str, monitored_processes: list, multiple_capture_files:bool, metadata:dict) -> dict:

    visualization_data['elements']['nodes'] = get_nodes(nodes=visualization_data['elements']['nodes'], 
                                                        capture_group_color=capture_group_color,
                                                        result_file_id=result_file_id, 
                                                        monitored_processes=monitored_processes,
                                                        multiple_capture_files=multiple_capture_files,
                                                        metadata=metadata)
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
                                          type=EdgeType.TCPIP_PACKET_SENT,
                                          source_port=connection_record['SourcePort'],
                                          dest_port=connection_record['DestinationPort'],
                                          protocol=connection_record['TransportProtocol'])     
                    
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
                                                       type=EdgeType.DNS_RESOLUTION,
                                                       dns_query_record_type_text=dns_response['RecordTypeText'],
                                                       dns_query_record_type_code=dns_response['RecordTypeCode'])     
                                edges.append(domain_edge)
                        
    return edges

def get_edge(event: str, source: int, target:int, type: EdgeType, 
             source_port: int = 0, 
             dest_port: int = 0, 
             protocol: str = "TCP", 
             dns_query_record_type_text:str = "A",
             dns_query_record_type_code:str = "1") -> dict:
    
    edge = { 
            "data": { 
                "source": source, 
                "target": target, 
                "type": type, 
                "info": event
          } 
    }
    
    if type == EdgeType.TCPIP_PACKET_SENT:
        edge['data']['source_port'] = source_port
        edge['data']['dest_port'] = dest_port
        edge['data']['protocol'] = protocol
    elif type == EdgeType.DNS_QUERY or type == EdgeType.DNS_RESOLUTION:
        edge['data']['record_type_text'] = dns_query_record_type_text
        edge['data']['record_type_code'] = dns_query_record_type_code
    return edge

def get_nodes(nodes: list, capture_group_color:str, result_file_id:str, monitored_processes: list, multiple_capture_files:bool, metadata: dict) -> list:
    ips = set()
    domains = set()
    
    if multiple_capture_files:
        group_node = get_node(label="",type=NodeType.CAPTURE, capture_group_color=capture_group_color, result_file_id=result_file_id)
        group_node_data_with_metadata = group_node['data'] | metadata # Merge dicts
        group_node['data'] = group_node_data_with_metadata
        nodes.append(group_node)
        
    for index, process in enumerate(monitored_processes): 
        process_node: dict = get_node(label=f"{process['ProcessName']}-{process['PID']}", 
                                      type=NodeType.PROCESS, 
                                      monitored_process=process)
        PROCESS_NODE_LOOKUP_INDEX[index] = process_node['data']['id'] # Used when establishing edges to know which correlate process to activity
        process_node["data"]["result_file_id"].append(result_file_id)
        
        if multiple_capture_files:
            process_node["data"]["parent"] = result_file_id
        
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
                if not result_file_id in node["data"]["result_file_id"]:
                    node["data"]["result_file_id"].append(result_file_id)

        if not mapped_ip:
            ip_node["data"]["result_file_id"].append(result_file_id)
            nodes.append(ip_node)
    
    for domain in domains:
        mapped_domain: bool = False
        domain_node: dict = get_node(label=domain, type=NodeType.DOMAIN)
        # Check if the domain has already been mapped - to avoid duplicates
        for node in nodes:
            if node['data']['type'] == 'domain' and node['data']['label'] == domain_node['data']['label']:
                mapped_domain = True
                if not result_file_id in node["data"]["result_file_id"]:
                    node["data"]["result_file_id"].append(result_file_id)
        
        if not mapped_domain:
            domain_node["data"]["result_file_id"].append(result_file_id)
            nodes.append(domain_node)
            
    return nodes

def get_node(label:str, type: NodeType, monitored_process:dict={}, capture_group_color:str="#000", result_file_id:int = None) -> dict:
    global NODE_COUNTER
    NODE_COUNTER += 1

    node: dict = { "data": { 
                        "id": NODE_COUNTER if type != NodeType.CAPTURE else result_file_id, 
                        "type": type, 
                        "result_file_id": [],
                        "label": label,
                        "hasAPIResults": False,
                        "APIResults":{
                            # This data is appended in the web UI
                        }
                    } 
                } 
    
    ### Unique values regarding the nodes
    if type == NodeType.CAPTURE:
        node['data']['color'] = capture_group_color
        node['data']['result_file_id'].append(result_file_id)
        
    elif type == NodeType.PROCESS:

        ### Process details
        node['data']['Name'] = monitored_process['ProcessName']
        node['data']['PID'] = monitored_process['PID']
        node['data']['SessionID'] = monitored_process['SessionID']
        node['data']['Running as user'] = monitored_process['ProcessUser']
        node['data']['Commandline'] = monitored_process['CommandLine']
        node['data']['Protected process'] = monitored_process['IsolatedProcess']
        node['data']['Started'] = monitored_process['StartTime']
        node['data']['Stopped'] = monitored_process['StopTime']
        node['data']['DNS activty'] = True if len(monitored_process['DNSQueries']) > 0 or len(monitored_process['DNSResponses']) > 0 else False
        node['data']['TCPIP activty'] = True if len(monitored_process['TCPIPTelemetry']) > 0 else False

        ### Executable details
        node['data']['File path'] = normalize_windows_path(monitored_process['Executable']['FilePath'])
        node['data']['FileSize'] = monitored_process['Executable']['FileSize']
        
        node['data']['FileCompany'] = monitored_process['Executable']['FileCompany']
        node['data']['FileProductName'] = monitored_process['Executable']['FileProductName']
        node['data']['FileProductVersion'] = monitored_process['Executable']['FileProductVersion']


        node['data']['Is signed'] = monitored_process['Executable']['IsSigned']
        node['data']['Created'] = monitored_process['Executable']['CreatedTimestamp']
        node['data']['MD5'] = monitored_process['Executable']['MD5']
        node['data']['SHA1'] = monitored_process['Executable']['SHA1']
        node['data']['SHA256'] = monitored_process['Executable']['SHA256']
        node['data']['FileEntropy'] = monitored_process['Executable']['FileEntropy']

    elif type == NodeType.IP:
        node['data']['IP'] = label
        node['data']['Local'] = is_ip_localhost_or_linklocal(label) 
        node['data']['Private'] = is_ip_private(label)
        node['data']['Multicast'] = is_ip_multicast(label)
        node['data']['IPv4'] = is_ip_ipv4(label)

    elif type == NodeType.DOMAIN:
        node['data']['Domain'] = label
        node['data']['ValidDomainName'] = is_valid_domain_name(label)
        
    return node


def get_unique_values(unique_values, monitored_processes) -> dict:
    for monitored_process in monitored_processes:
        if monitored_process['ProcessName'] not in unique_values['process_names']:
            unique_values['process_names'].append(monitored_process['ProcessName'])
        for connection_record in monitored_process['TCPIPTelemetry']:
            if connection_record['DestinationIP'] not in unique_values['ips']:
                unique_values['ips'].append(connection_record['DestinationIP'])
        
        for dns_query in monitored_process['DNSQueries']:
            if dns_query['DomainQueried'] not in unique_values['domains']:
                unique_values['domains'].append(dns_query['DomainQueried'])
                
        for dns_response in monitored_process['DNSResponses']:
            if dns_response['DomainQueried'] not in unique_values['domains']:
                unique_values['domains'].append(dns_response['DomainQueried'])

    return unique_values     

def get_destination_ports(cytoscapeEdges: dict) -> dict:
    destination_ports = {
        'TCP': {},
        'UDP': {}
    }
    for edge in cytoscapeEdges:
        if edge['data']['type'] == EdgeType.TCPIP_PACKET_SENT:
            transport_protocol: str = edge['data']['protocol']
            dest_port: int = edge['data']['dest_port']
            destination_ports[transport_protocol][dest_port] = destination_ports[transport_protocol].get(dest_port, 0) + 1

    sorted_ports = {}
    for protocol, ports in destination_ports.items():
        sorted_ports[protocol] = sorted(ports.items(), key=lambda x: x[1], reverse=True)
    return sorted_ports