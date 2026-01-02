
import os
import sys
import argparse
from pathlib import Path

#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.functions import *
from lib.static import SCRIPT_BANNER, DEFAULT_HTTP_HOST_ADRESS, DEFAULT_HTTP_HOST_PORT
from lib.output import * 
from lib.httpserver import *
from lib.validation import *
from lib.prompts import *
from lib.files_and_folders import get_results_files_recursively, get_comma_separated_results_files

#==========  API LOOKUPS  ============
from lib.lookups import *
#from custom.MyCustomAPILookupClass import *

#=====================================
#  CHANGABLE VARIABLES AND FUNCTIONS
#=====================================
AVAILABLE_APIS:dict = {
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
#  Dont touch anything below :-) 
#==================================================

def main() -> None:
    SCRIPT_DIRECTORY: Path.parent = Path(__file__).parent
    WEB_DIRECTORY: Path = SCRIPT_DIRECTORY / "web" 
    DATA_FILE: Path = WEB_DIRECTORY / "data.json"
    
    wyc_result_files: list = []
    
    parser = argparse.ArgumentParser(description="A script demonstrating argparse with flags.")
    parser.add_argument("-r", "--results", type=str, help="Results file or directory with result files")
    parser.add_argument("-i", "--ip", type=str, help="IP to serve CallMapper UI", default=DEFAULT_HTTP_HOST_ADRESS)
    parser.add_argument("-p", "--port", type=int, help="Port to serve CallMapper UI", default=DEFAULT_HTTP_HOST_PORT)
    parser.add_argument("-a", "--api-lookup", action="store_true", help="Lookup endpoints against defined APIs")
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
        "summary":{
            
        },
        "stats":{
            
        },
        "alerts": [
            
        ],
        "wyc_results_metadata":{
            
        }
    }
    
    for result_file in wyc_result_files:
        results_file_counter += 1
        result_file_id = results_file_counter
        
        ConsoleOutputPrint(msg=f"Processing results file {results_file_counter}/{len(wyc_result_files)}", print_type="info")
        wyc_results_json_data: dict = get_results_file_data(result_file) 
    
        metadata: dict = wyc_results_json_data['Metadata']
        monitored_processes: list = wyc_results_json_data['MonitoredProcesses']
        
        callmapper_data[result_file_id] = metadata
        
        ### £ OLD API LOOKUPS
        """
        if args.api_lookup:
            unique_process_names: set = get_unique_process_names_with_external_network_activity(monitored_processes)
            processes_to_lookup_with_network_activity: list = prompt_user_for_processes_to_lookup(unique_process_names)
            endpoints: dict = get_unique_endpoints_to_lookup(monitored_processes, processes_to_lookup_with_network_activity)
            apis_to_use: list = prompt_user_for_apis_to_use(AVAILABLE_APIS)
            lookup_endpoints(AVAILABLE_APIS, endpoints, apis_to_use) 
        """

        callmapper_data = get_visualization_data(visualization_data=callmapper_data, 
                                                result_file_id=result_file_id,
                                                results_file_counter=results_file_counter,
                                                monitored_processes=monitored_processes)
        
    output_visualization_data(DATA_FILE, callmapper_data)
    
    ConsoleOutputPrint(msg=f"Hosting visualization via http://{args.ip}:{args.port}", print_type="info")
    try:
        start_http_server(directory=WEB_DIRECTORY, host=args.ip, port=args.port)
    except KeyboardInterrupt:
        ConsoleOutputPrint(msg=f"Keyboard interuppt. Goodbye!", print_type="info")

if __name__ == "__main__":
    main()
