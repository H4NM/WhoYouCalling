
#=====================================
#  CUSTOM LIBRARIES 
#========  FUNCTIONS & CLASSES =======
from lib.output import ConsoleOutputPrint

def prompt_user_for_continue_with_faulty_results_file(results_file:str) -> bool:
    while True:
        answer = input(f"[!] The results file \"{results_file}\" is faulty. Do you want to skip it and continue? (Y/n): ").strip().lower()
        if answer == "y" or answer == "":
            return True
        elif answer == "n":
            return False
        else:
            ConsoleOutputPrint(msg=f"Invalid input. Please enter 'y' or 'n'.", print_type="warning")
