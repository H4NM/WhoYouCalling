#=====================================
#  NATIVE LIBRARIES 
#=====================================
import sys
import os
import json

#=====================================
#  CUSTOM LIBRARIES 
#=====================================
from lib.static import *
from lib.classes import *
from lib.output import *
from lib.prompts import prompt_user_for_continue_with_faulty_results_file
from lib.functions import has_prerequisites, file_exists_in_same_script_folder, valid_data_file_exists, requests_is_installed

def valid_arguments_were_passed(args: object, web_directory:str, data_file:str) -> bool:
    if not args.results:
        if not file_exists_in_same_script_folder(web_directory, "data.json"):
            ConsoleOutputPrint(msg=f"Unable to find data.json in the same directory as the script. Please supply a Results.json or directory with them or move data.json to the same path as the script", print_type="fatal")
            return False
        
        if not valid_data_file_exists(data_file):
            ConsoleOutputPrint(msg=f"{data_file} has an invalid JSON structure", print_type="fatal")
            return False
    
    if args.api_lookup and not requests_is_installed():
        ConsoleOutputPrint(REQUESTS_LIBRARY_MISSING_MSG, print_type="fatal")
        return False
    
    if not os.path.isfile(args.results) and not os.path.isdir(args.results) and not ',' in args.results:
        ConsoleOutputPrint(msg=f"Invalid argument passed as file(s) or directory for results files: \"{args.results}\"", print_type="fatal")
        return False
    
    return True
    
def validate_prerequisites(web_directory:str) -> None:
    if not has_prerequisites():
        ConsoleOutputPrint(msg=f"Invalid python version. You need atleast python version {MINIMUM_PYTHON_VERSION}. You have {sys.version}", print_type="fatal")
        sys.exit(1) 

    if not file_exists_in_same_script_folder(web_directory, "index.html"):
        ConsoleOutputPrint(msg=f"Unable to find index.html in the same directory as the script", print_type="fatal")
        sys.exit(1)

def is_valid_results_file(results_file:str) -> dict:
    try:
        results_file_object = open(results_file, 'rt')
        json.load(results_file_object)
        return True
    except Exception as error_msg:
        ConsoleOutputPrint(msg=f"Error when reading results file: {str(error_msg)}", print_type="fatal")
        return False

def validate_result_files(wyc_result_files:list) -> list:
    final_wyc_result_files: list = []
    for result_file in wyc_result_files:
        if not is_valid_results_file(results_file=result_file):
            if not prompt_user_for_continue_with_faulty_results_file(results_file=result_file):
                ConsoleOutputPrint(msg=f"Stopping...", print_type="fatal")
                sys.exit(1)
        final_wyc_result_files.append(result_file)
    
    if not final_wyc_result_files:
        ConsoleOutputPrint(msg=f"No result files to process. exitting...", print_type="fatal")
        sys.exit(1)
    return final_wyc_result_files