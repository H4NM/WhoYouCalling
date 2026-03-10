
import os
import sys
import argparse
from pathlib import Path

#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.cytoscape import  get_visualization_data, get_unique_values, get_destination_ports
from lib.static.static import SCRIPT_BANNER, DEFAULT_HTTP_HOST_ADRESS, DEFAULT_HTTP_HOST_PORT 
from lib.static.capture_group_colors import CAPTURE_GROUP_COLORS
from lib.validation import validate_apis, validate_prerequisites, valid_arguments_were_passed, validate_result_files
from lib.filesystem import get_results_files_recursively, get_results_file_data, output_visualization_data
from lib.apis import VirusTotal, AbuseIPDB
from lib.utils import sort_unique_values, get_comma_separated_results_files, requests_is_installed
from lib.output import ConsoleOutputPrint
from lib.httpserver import start_http_server

#=====================================
#  CHANGABLE VARIABLES AND FUNCTIONS
#=====================================
AVAILABLE_APIS:list = [
    {
        'api_class': VirusTotal,
        'api_key': os.getenv("CALLMAPPER_APIKEY_VIRUSTOTAL", default=''),
    },
    {
        'api_class': AbuseIPDB,
        'api_key': os.getenv("CALLMAPPER_APIKEY_ABUSEIPDB", default=''),  
    }
]

#==================================================
#  Dont touch anything below :-) 
#==================================================

def main() -> None:
    SCRIPT_DIRECTORY: Path.parent = Path(__file__).parent
    WEB_DIRECTORY: Path = SCRIPT_DIRECTORY / "web" 
    DATA_FILE: Path = WEB_DIRECTORY / "data.json"
    
    wyc_result_files: list = []
    valid_apis:list = []
    
    parser = argparse.ArgumentParser(description="A script demonstrating argparse with flags.")
    parser.add_argument("-r", "--results", type=str, help="Results file or directory with result files")
    parser.add_argument("-i", "--ip", type=str, help="IP to serve CallMapper UI", default=DEFAULT_HTTP_HOST_ADRESS)
    parser.add_argument("-p", "--port", type=int, help="Port to serve CallMapper UI", default=DEFAULT_HTTP_HOST_PORT)
    args = parser.parse_args()
    print(SCRIPT_BANNER)
    
    validate_prerequisites(web_directory=WEB_DIRECTORY)
        
    if not valid_arguments_were_passed(args=args, web_directory=WEB_DIRECTORY, data_file=DATA_FILE):
        sys.exit(1)
    
    if os.path.isdir(args.results):
        wyc_result_files = get_results_files_recursively(args.results)
        ConsoleOutputPrint(msg=f"Found {len(wyc_result_files)} Result.json files", print_type="info")
    elif os.path.isfile(args.results):
        wyc_result_files.append(args.results)
    else: # Is comma separated string with result files paths
        wyc_result_files = get_comma_separated_results_files(args.results)
    
    validate_result_files(wyc_result_files=wyc_result_files)
    

    results_file_counter: int = 0
    callmapper_data:dict = {
        "elements": {
            "nodes": [],
            "edges": []
        },
        "summary": {
            "unique":{
            },
            "destination_ports":{
                
            }
        },
        "alerts": [
            
        ],
        "wyc_results_metadata":{
            
        }
    }
    unique_values = {
        'process_names': [],
        'ips': [],
        'domains': []
    }
    
    for result_file in wyc_result_files:
        results_file_counter += 1
        result_file_id = results_file_counter
        capture_group_color: str = CAPTURE_GROUP_COLORS[results_file_counter-1]
        multiple_capture_files: bool = True if len(wyc_result_files) > 1 else False
        
        ConsoleOutputPrint(msg=f"Processing results file {results_file_counter}/{len(wyc_result_files)}", print_type="info")
        wyc_results_json_data: dict = get_results_file_data(result_file) 

        metadata: dict = wyc_results_json_data['Metadata']
        monitored_processes: list = wyc_results_json_data['MonitoredProcesses']
        
        callmapper_data["wyc_results_metadata"][result_file_id] = metadata
        callmapper_data["wyc_results_metadata"][result_file_id]['callmapper_color'] = capture_group_color
        unique_values = get_unique_values(unique_values, monitored_processes)
        
        callmapper_data = get_visualization_data(visualization_data=callmapper_data, 
                                                result_file_id=result_file_id,
                                                metadata=metadata,
                                                capture_group_color=capture_group_color,
                                                monitored_processes=monitored_processes,
                                                multiple_capture_files=multiple_capture_files)
    
    unique_values = sort_unique_values(unique_values)
    callmapper_data['summary']['unique'] = unique_values
    callmapper_data['summary']['destination_ports'] = get_destination_ports(callmapper_data['elements']['edges'])

    output_visualization_data(DATA_FILE, callmapper_data)
    if requests_is_installed():
        valid_apis = validate_apis(available_apis=AVAILABLE_APIS)
    ConsoleOutputPrint(msg=f"Hosting visualization via http://{args.ip}:{args.port}", print_type="info")
    try:
        start_http_server(directory=WEB_DIRECTORY, host=args.ip, port=args.port, apis=valid_apis)
    except KeyboardInterrupt:
        ConsoleOutputPrint(msg=f"Keyboard interuppt. Goodbye!", print_type="info")

if __name__ == "__main__":
    main()
