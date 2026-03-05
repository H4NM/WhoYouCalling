import ipaddress
from typing import Tuple, Optional, Union

from lib.output import ConsoleOutputPrint
from lib.static.invalid_domain_names import INVALID_DOMAINNAMES
from lib.static.well_known_ports import WELL_KNOWN_PORTS

def is_ip_localhost_or_linklocal(ip):
    ip_obj = ipaddress.ip_address(ip)
    return (ip_obj.is_loopback or ip_obj.is_link_local)

def is_ip_private(ip):
    ip_obj = ipaddress.ip_address(ip)
    return (ip_obj.is_private or ip_obj.is_multicast)

def is_ip_multicast(ip):
    ip_obj = ipaddress.ip_address(ip)
    return ip_obj.is_multicast

def is_ip_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False
    
def is_valid_domain_name(domainname: str) -> bool:
    if not '.' in domainname or domainname in INVALID_DOMAINNAMES:
        return False
    return True

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

def get_port_information(transport_protocol: str, port: int) -> Union[str, None]: 
    if port in WELL_KNOWN_PORTS[transport_protocol]:
        return f" ({WELL_KNOWN_PORTS[transport_protocol][port]})"
    else:
        return None