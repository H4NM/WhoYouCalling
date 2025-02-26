
SCRIPT_BANNER = r"""  
        o=o        o         o--o   o            *
   _____      _ _ __  __         \\    o-o        \    
  / ____|    | | |  \/  |    o     o-o             o         
 | |     __ _| | | \  / | __ _ _ __  _ __   ___ _ __ 
 | |    / _` | | | |\/| |/ _` | '_ \| '_ \ / _ \ '__|  o
 | |___| (_| | | | |  | | (_| | |_) | |_) |  __/ |    /
  \_____\__,_|_|_|_|  |_|\__,_| .__/| .__/ \___|_|   o  
   Part of WhoYouCalling      | |   | |           
                              |_|   |_|           
                                          o--o--o--o"""
PROCESS_START_SECONDS_RANGE: int = 3
MINIMUM_PYTHON_VERSION: str = '3.11'
DATA_FILE_JSON_STRUCTURE: dict = {
    "elements": {
        "nodes": list,
        "edges": list
    }
}
REQUESTS_LIBRARY_MISSING_MSG="""The library 'requests' doesn't seem to be installed.
      It's needed to perform API lookups
      Run the following to install it: 

        pip install requests
            """
            
WELL_KNOWN_PORTS = {
    'TCP': {
        20: 'FTP-Data',
        21: 'FTP-Control',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        88: 'Kerberos',
        110: 'POP3',
        135: 'MS-RPC',
        139: 'NetBIOS-SSN',
        143: 'IMAP',
        389: 'LDAP',
        443: 'HTTPS',
        445: 'SMB',
        465: 'SMTPS',
        554: 'RTSP',
        587: 'SMTP',
        593: 'Microsoft DCOM',
        636: 'LDAPS',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'MSSQL',
        1521: 'Oracle DB',
        2049: 'NFS',
        3268: 'LDAP-Global Catalog',
        3269: 'LDAPS-Global Catalog',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5985: 'WinRM-HTTP',
        5986: 'WinRM-HTTPS',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt',
        9200: 'Elasticsearch HTTP', 
        9300: 'Elasticsearch Transport', 
        9389: 'ADWS',
        5044: 'Logstash',
        27017: 'MongoDB',
        49152-65535: 'Dynamic RPC Ports',
    },
    'UDP': {
        53: 'DNS',
        67: 'DHCP-Server',
        68: 'DHCP-Client',
        69: 'TFTP',
        88: 'Kerberos',
        123: 'NTP',
        137: 'NetBIOS-NS',
        138: 'NetBIOS-DGM',
        161: 'SNMP',
        162: 'SNMP-Trap',
        389: 'LDAP',
        445: 'SMB',
        500: 'ISAKMP',
        514: 'Syslog',
        520: 'RIP',
        1194: 'OpenVPN',
        1812: 'RADIUS-Authentication',
        1813: 'RADIUS-Accounting',
        1900: 'UPnP',
        4500: 'IPsec-NAT-Traversal',
        5353: 'mDNS',
        10001: 'Memcached'
    }
}
