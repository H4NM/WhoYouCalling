#=====================================
#  NATIVE LIBRARIES 
#========  FUNCTIONS & CLASSES =======
import os
import json
import sys

#=====================================
#  CUSTOM LIBRARIES 
#=====================================
from lib.static.static import WYC_RESULT_FILE, DATA_FILE_JSON_STRUCTURE
#from lib.validation import valid_structure
from lib.output import ConsoleOutputPrint

def get_results_files_recursively(path:str, result_files: list = []) -> list:
    for entry in os.listdir(path):
        full_path = os.path.join(path, entry)
        if os.path.isdir(full_path):
            result_files = get_results_files_recursively(full_path, result_files)
        elif os.path.basename(full_path) == WYC_RESULT_FILE:
            result_files.append(full_path)
    return result_files


def file_exists_in_same_script_folder(directory: str, file: str) -> bool:
    if (directory / file).exists():
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
        json.dump(visualization_data, json_file, indent=False)
        json_file.close()
    except Exception as error_msg:
        ConsoleOutputPrint(msg=f"Error when creating visualization data file: {str(error_msg)}", print_type="fatal")
        sys.exit(1)
