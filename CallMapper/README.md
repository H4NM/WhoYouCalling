# CallMapper
CallMapper offers a network graph with analytics of looking up domains and IP addresses against APIs, or via static links to websites such as [ipinfo.io](https://ipinfo.io/), [whois.com](https://www.whois.com/), [abuseipdb.com](https://www.abuseipdb.com/) and [virustotal.com](https://www.virustotal.com/).

## How it works:
1. `callmapper.py` parses the JSON results file from WhoYouCalling and creates a `data.json` file in the same directory as the script. If the flag for API lookups is provided, the data in the `data.json` files are enriched with stored HTML.
2. `callmapper.py` hosts a HTTP server in the same directory as the script at localhost port 8080 that serves the `data.json` and the `index.html` with other related resources (css, js and icon).
3. You can now view the visualization via http://127.0.0.1:8080 in a web browser

## Usage:

**Visualize the output from WhoYouCalling**:
```
python callmapper.py -r ./Result.json
```
> **Note:** You can visualize an already existing data.json file by not providing a Result.json and if that data.json file exists in the same directory as callmapper.py.

**Visualize the output from WhoYouCalling and enrich the data with API lookups**:
```
python callmapper.py --results-file ./Result.json --api-lookup
```

## Dependencies
**CallMapper** has been tested and works with Python version 3.9 or later. The packages that are used: 
- Visualization: 
  - [Cytoscape.js](https://github.com/cytoscape/cytoscape)
- API Lookups:
  - [requests](https://pypi.org/project/requests/) (*Optional - if API lookup of IPs and domains is wanted.*)

In order to run **CallMapper**, all you really need is Python.

## Using API lookups
When running `callmapper.py` with the flag `--api-lookup` or `-a` for short, you will be prompted to choose which processes with network activity you want to lookup. 
Thereafter, you will be asked which API's you want to use to perform the lookups against. Both of the prompts accept an empty answer for selecting everything.

The list of available API's can be found in `callmapper.py` in the variable `AVAILABLE_APIS`.
`AVAILABLE_APIS` is a dict with the title of the API as a key, with two subkeys; `api_key` and `api`. 

```python
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
```

The included APIs, `VirusTotal` and `AbuseIPDB`, both require an API key. Their defined class, found in `/lib/api_lookups.py`, specifiy if the API source requires an API key or not. The API key is added in their respective respective `api_key` field in `AVAILABLE_APIS`. 
If the field is empty and the API source requires an API key, and you as a user specified you want to use that api during the prompt, it will simply be skipped.

## Add you own API integration
> **Note:** Only REST APIs are supported.

To create your own API integration, there's a template in `/custom/custom_api_lookups.py`. 
Any API integration must have the following structure:

```python

class MyCustomAPILookupClass(APILookup):

    def __init__(self, api_source:str, api_key:str = ""):
        super().__init__(api_source, api_key)
        self.headers = {"x-api-key": self.api_key}
        self.api_key_required = True
        self.lookup_types = [LookupType.IP, LookupType.DOMAIN]
        
    def get_data(self, endpoint: str, lookup_type) -> dict:
        url = f"https://my.own.api/api/v2/check?{endpoint}"
        response = self.requests.get(url, headers=self.headers)
        #...
        json_response = response.json()
    
    def get_presentable_data_for_ip(self, returned_data: dict) -> Tuple[dict, bool]:
        presentable_data: dict = {}
        is_potentially_malicious: bool = False
        #...
        return presentable_data, is_potentially_malicious
    
    def get_presentable_data_for_domain(self, returned_data: dict) -> Tuple[dict, bool]:
        presentable_data: dict = {}
        is_potentially_malicious: bool = False
        #.... 
        return presentable_data, is_potentially_malicious
```
The function `__init__` is invoked when the object of the class is initiated. In there, you need to define:
    1. If the API-key is required or not: `self.api_key_required = True`
    2. Should you lookup IPs, domains or both: `self.lookup_types = [LookupType.IP, LookupType.DOMAIN]`
You can also define the requests header if needed, e.g. `self.headers = {"x-api-key": self.api_key}`. Otherwise you can define it in `get_data`.

The function `get_data` is the one conducting the actual HTTP REST API lookup. It will simply query the endpoint, using `self.requests` (yes, that's an object inherited requests). The reason behind assigning the library `requests` to an object variable was to ensure that CallMapper doesn't require the library `requests` to run - this also why there's no `requirements.txt` file here :-). The `get_data` function processes the request to the extent of validating if successful data was returned or not. Thereafter it's only returned as a JSON object. Worth noting is that `get_data` may have a different URL depending on the endpoint type, in which is needs to be able to process both types. It is possible to return, as of now, three different API error types. If `MAJOR_ERROR`, `QUOTA_EXCEEDED`, or `WRONG_CREDENTIALS` are returned, the remaining types of endpoints will be skipped. If any other type of error is returned, it will simply attempt to lookup the next endpoint.   

```python
class APIErrorType:
    NO_RESULTS = "NO_RESULTS"
    INVALID_FORMAT = "INVALID_FORMAT"
    ERROR = "ERROR"
    WRONG_CREDENTIALS = "WRONG_CREDENTIALS"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    MAJOR_ERROR = "MAJOR_ERROR"
```

The function `get_presentable_data_for_ip` and `get_presentable_data_for_domain` simply takes the returned JSON object retrieves the fields that are of value and places them within a flat dict (not nested). The keys in the dict will be the titles presented in the visualization and the data with be the corresponding values. The functions will return the dict and a bool wether the retrieved data indicates that the endpoint may be malicious. If the bool variable is returned `True` (potentially malicious), the nodes take a red star shape in the network graph, clearly indicating that they're worth investigating. 

When it's done and ready, import the custom API you have defined in `/custom/` (e.g. `from custom.MyCustomAPILookupClass import *`) in `callmapper.py`, then simply add it in the same fashion as `VirusTotal` and `AbuseIPDB` are in `AVAILABLE_APIS`. 