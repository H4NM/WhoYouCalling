
#=====================================
#  NATIVE LIBRARIES 
#========  FUNCTIONS & CLASSES =======
import os


#=====================================
#  CUSTOM LIBRARIES 
#=====================================
from lib.static import WYC_RESULT_FILE

def get_results_files_recursively(path:str, result_files: list = []) -> list:
    for entry in os.listdir(path):
        full_path = os.path.join(path, entry)
        if os.path.isdir(full_path):
            result_files = get_results_files_recursively(full_path, result_files)
        elif os.path.basename(full_path) == WYC_RESULT_FILE:
            result_files.append(full_path)
    return result_files

def get_comma_separated_results_files(csv:str) -> list:
    return csv.split(',')