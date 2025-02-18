
import os
import sys
import argparse
from pathlib import Path

#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.functions import *
from lib.static import SCRIPT_BANNER
from lib.output import * 

#==========  API LOOKUPS  ============
from lib.lookups import *
#from custom.MyCustomAPILookupClass import *

#=====================================
#  CHANGABLE VARIABLES AND FUNCTIONS
#=====================================
HTTP_HOST_ADRESS:str = "127.0.0.1"
HTTP_HOST_PORT:int = 8080
AVAILABLE_APIS = {
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
    DATA_FILE: str = SCRIPT_DIRECTORY / "data.json"
    
    parser = argparse.ArgumentParser(description="A script demonstrating argparse with flags.")
    parser.add_argument("-r", "--results-file", type=str, help="Results file")
    parser.add_argument("-a", "--api-lookup", action="store_true", help="Lookup endpoints against defined APIs")
    args = parser.parse_args()
    print(SCRIPT_BANNER)
    
    if not file_exists_in_same_script_folder(SCRIPT_DIRECTORY, "index.html"):
        ConsoleOutputPrint(msg=f"Unable to find index.html in the same directory as the script", print_type="fatal")
        sys.exit(1)
        
    if not args.results_file:
        if not file_exists_in_same_script_folder(SCRIPT_DIRECTORY, "data.json"):
            ConsoleOutputPrint(msg=f"Unable to find data.json in the same directory as the script. Please supply a Results.json file or move data.json to the same path as the script", print_type="fatal")
            sys.exit(1)
        if not valid_data_file_exists(DATA_FILE):
            ConsoleOutputPrint(msg=f"{DATA_FILE} has an invalid JSON structure", print_type="fatal")
            sys.exit(1)
    
    if args.api_lookup and not requests_is_installed():
        ConsoleOutputPrint(REQUESTS_LIBRARY_MISSING_MSG, print_type="fatal")
        sys.exit(1)
        
    if args.results_file:
        ConsoleOutputPrint(msg=f"Retrieving data from results file", print_type="info")
        monitored_processes: list = get_results_file_data(args.results_file)
        
        if args.api_lookup:
            unique_process_names: set = get_unique_process_names_with_external_network_activity(monitored_processes)
            processes_to_lookup_with_network_activity: list = prompt_user_for_processes_to_lookup(unique_process_names)
            endpoints: dict = get_unique_endpoints_to_lookup(monitored_processes, processes_to_lookup_with_network_activity)
            apis_to_use: list = prompt_user_for_apis_to_use(AVAILABLE_APIS)
            lookup_endpoints(AVAILABLE_APIS, endpoints, apis_to_use) 
        
        ConsoleOutputPrint(msg=f"Creating visualization data", print_type="info")
        visualization_data = get_visualization_data(monitored_processes)
        if os.path.isfile(DATA_FILE):
            if prompt_user_for_overwrite_of_data_file():
                ConsoleOutputPrint(msg=f"Overwriting existing data.json.", print_type="info")
                output_visualization_data(DATA_FILE, visualization_data)
            else:
                ConsoleOutputPrint(msg=f"Keeping existing data.json", print_type="info")
        else:
            output_visualization_data(DATA_FILE, visualization_data)
    else:
        ConsoleOutputPrint(msg=f"Visualizing from existing results file", print_type="info")
    ConsoleOutputPrint(msg=f"Hosting visualization via http://{HTTP_HOST_ADRESS}:{HTTP_HOST_PORT}", print_type="info")
    try:
        start_http_server(directory=SCRIPT_DIRECTORY, host=HTTP_HOST_ADRESS, port=HTTP_HOST_PORT)
    except KeyboardInterrupt:
        ConsoleOutputPrint(msg=f"Keyboard interuppt. Goodbye!", print_type="info")

if __name__ == "__main__":
    main()