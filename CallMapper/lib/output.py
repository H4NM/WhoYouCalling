def ConsoleOutputPrint(msg: str = "", print_type: str = "info") -> None:
    prefix: str = ""
    if print_type == "info": 
        prefix = "[*]"
    elif print_type == "warning":
        prefix = "[!]"
    elif print_type == "error":
        prefix = "[?]"
    elif print_type == "fatal":
        prefix = "[!!!]"
    print(f"{prefix} {msg}")