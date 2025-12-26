
#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.output import ConsoleOutputPrint

def prompt_user_for_processes_to_lookup(unique_process_names: set) -> list:
    processes_to_lookup: list = []
    ConsoleOutputPrint(msg="Which processes with network activity do you want to lookup IPs and domains for?", print_type="info")
    print("enter \"all\" or nothing for every process, or enter the corresponding number for the ones you want to lookup.") 
    print("Multiple ones can be comma separate, e.g. 3,5,7")
    for counter, process_name in enumerate(unique_process_names):
        print(f" {counter}) {process_name}")
        
    while True:
        answer = input("Choice: ").strip().lower()
        if answer == "all" or answer == "":
            for process_name in unique_process_names:
                processes_to_lookup.append(process_name)
            break
        elif "," in answer:
            multiple_numbers_as_string = answer.split(",")
            multiple_numbers_as_integer: set = set()
            for value in multiple_numbers_as_string:
                try:
                    integer = int(value)
                    if integer >= len(unique_process_names) or integer < 0:
                        ConsoleOutputPrint(msg=f"Provided value {integer} doesn't exist. Skipping..", print_type="warning")
                    else:
                        multiple_numbers_as_integer.add(int(value))
                except:
                    ConsoleOutputPrint(msg=f"Invalid number provided in the comma separated awnser: {answer}", print_type="error")
                    return prompt_user_for_processes_to_lookup(unique_process_names)

            for integer in multiple_numbers_as_integer:
                processes_to_lookup.append(unique_process_names[integer])
            break
        else:
            try:
                integer = int(answer)
                processes_to_lookup.append(unique_process_names[integer])
                break
            except:
                ConsoleOutputPrint(msg=f"Invalid answer provided: {answer}", print_type="warning")
    return processes_to_lookup

def prompt_user_for_apis_to_use(available_apis: dict) -> list:
    apis_to_use: list = []
    ConsoleOutputPrint(msg="Which APIs do you want to use to lookup IPs and domains?", print_type="info")
    print("enter \"all\" or nothing for every API, or enter the corresponding number for the ones you want to use.") 
    print("Multiple ones can be comma separate, e.g. 0,1,4")
    for counter, api_name in enumerate(available_apis):
        print(f" {counter}) {api_name}")
        
    while True:
        answer = input("Choice: ").strip().lower()
        if answer == "all" or answer == "":
            for api in available_apis:
                apis_to_use.append(api)
            break
        elif "," in answer:
            multiple_numbers_as_string = answer.split(",")
            multiple_numbers_as_integer: set = set()
            for value in multiple_numbers_as_string:
                try:
                    integer = int(value)
                    if integer >= len(available_apis) or integer < 0:
                        ConsoleOutputPrint(msg=f"Provided value {integer} doesn't exist. Skipping..", print_type="warning")
                    else:
                        multiple_numbers_as_integer.add(int(value))
                except Exception as e:
                    ConsoleOutputPrint(msg=f"Invalid number provided in the comma separated awnser: {answer}", print_type="error")
                    return prompt_user_for_apis_to_use()

            for integer in multiple_numbers_as_integer:
                apis_to_use.append(list(available_apis.keys())[integer])
            break
        else:
            try:
                integer = int(answer)
                apis_to_use.append(list(available_apis.keys())[integer])
                break
            except:
                ConsoleOutputPrint(msg=f"Invalid answer provided: {answer}", print_type="warning")
    return apis_to_use

def prompt_user_for_overwrite_of_data_file() -> bool:
    while True:
        answer = input("[!] An existing data.json file was found in the same directory as the script. Overwrite it? (Y/n): ").strip().lower()
        if answer == "y" or answer == "":
            return True
        elif answer == "n":
            return False
        else:
            ConsoleOutputPrint(msg=f"Invalid input. Please enter 'y' or 'n'.", print_type="warning")

def prompt_user_for_continue_with_faulty_results_file(results_file:str) -> bool:
    while True:
        answer = input(f"[!] The results file \"{results_file}\" is faulty. Do you want to skip it and continue? (Y/n): ").strip().lower()
        if answer == "y" or answer == "":
            return True
        elif answer == "n":
            return False
        else:
            ConsoleOutputPrint(msg=f"Invalid input. Please enter 'y' or 'n'.", print_type="warning")
