
SCRIPT_BANNER = r"""  
        o=o        o         o--o   o            *
   _____      _ _ __  __         \\    o-o        \    
  / ____|    | | |  \/  |    o     o-o             o         
 | |     __ _| | | \  / | __ _ _ __  _ __   ___ _ __ 
 | |    / _` | | | |\/| |/ _` | '_ \| '_ \ / _ \ '__|  o
 | |___| (_| | | | |  | | (_| | |_) | |_) |  __/ |    /
  \_____\__,_|_|_|_|  |_|\__,_| .__/| .__/ \___|_|   o  
   Part of WhoYouCalling      | |   | |           
                              |_|   |_|           
                                          o--o--o--o"""
PROCESS_START_SECONDS_RANGE: int = 3
MINIMUM_PYTHON_VERSION: str = '3.11'
DATA_FILE_JSON_STRUCTURE: dict = {
    "elements": {
        "nodes": list,
        "edges": list
    }
}
REQUESTS_LIBRARY_MISSING_MSG="""The library 'requests' doesn't seem to be installed.
      It's needed to perform API lookups
      Run the following to install it: 

        pip install requests
            """
            