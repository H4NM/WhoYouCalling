
#=====================================
#  NATIVE LIBRARIES 
#========  FUNCTIONS & CLASSES =======
import os

def get_results_files_recursively(path:str) -> list:
    result_files:list = []
    for entry in os.listdir(path):
        full_path = os.path.join(path, entry)
        if os.path.isdir(full_path):
            get_results_files_recursively(full_path)
        elif os.path.basename(full_path) == 'Result.json':
            result_files.append(full_path)
    return result_files

def get_comma_separated_results_files(csv:str) -> list:
    return csv.split(',')