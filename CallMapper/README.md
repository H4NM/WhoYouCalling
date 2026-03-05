# CallMapper
CallMapper offers a network graph with analytics of looking up domains and IP addresses against APIs, or via static links to websites such as [ipinfo.io](https://ipinfo.io/), [whois.com](https://www.whois.com/), [abuseipdb.com](https://www.abuseipdb.com/) and [virustotal.com](https://www.virustotal.com/).

## How it works:
1. `callmapper.py` parses JSON results file(s) from WhoYouCalling and creates a `data.json` file in a web directory with the script.
2. `callmapper.py` hosts a HTTP server in the same directory as the script with `index.html` and other related resources (css & js).
3. You can now view the visualization via http://127.0.0.1:8080 or at specified IP and port in a standard web browser 

> *CallMapper supports reading up to 10 result files from WhoYouCalling, enabling for a more in depth understanding to if there's a common IP being contacted for multiple captures.*

## Usage:

**Visualize the output from WhoYouCalling**:
```
python callmapper.py -r ./Result.json
```

## Dependencies
**CallMapper** has been tested and works with Python version 3.11 or later. The packages that are used: 
- Visualization: 
  - [Cytoscape.js](https://github.com/cytoscape/cytoscape)
  - [fcose](https://github.com/iVis-at-Bilkent/cytoscape.js-fcose)
- API Lookups:
  - [requests](https://pypi.org/project/requests/) (*Optional - if API lookup of IPs and domains is wanted.*)

In order to run **CallMapper**, all you really need is Python. Ideally, CallMapper would use flask or another web application framework to better serve and render data. However, in this case i've strived for ease of use. 

## Using API lookups
In order to use any of the APIs, you need to either statically set the respective API key for the API you want to use, or set the environment variable.  

```python
AVAILABLE_APIS = [
    {
        'api_class': VirusTotal,
        'api_key': os.getenv("CALLMAPPER_APIKEY_VIRUSTOTAL", default=''),
    },
    {
        'api_class': AbuseIPDB,
        'api_key': os.getenv("CALLMAPPER_APIKEY_ABUSEIPDB", default=''),  
    }
]
```

If API keys are provided, API lookups will be displayed when inspecting any of the nodes. They're not visible to some, such as internal IPs or domainnames, or when fields that may be looked up are not present. 
