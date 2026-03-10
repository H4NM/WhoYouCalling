# CallMapper
CallMapper offers a network graph with analytics of looking up domains and IP addresses against APIs, or via static links to websites such as [ipinfo.io](https://ipinfo.io/), [whois.com](https://www.whois.com/), [abuseipdb.com](https://www.abuseipdb.com/) and [virustotal.com](https://www.virustotal.com/).

## How it works:
1. `callmapper.py` parses JSON results file(s) from WhoYouCalling and creates a `data.json` file in a web directory with the script.
2. `callmapper.py` hosts a HTTP server in the same directory as the script with `index.html` and other related resources (css & js).
3. You can now view the visualization via http://127.0.0.1:8080 or at specified IP and port in a standard web browser 

> CallMapper supports reading up to 10 result files from WhoYouCalling, enabling for a more in depth understanding to if there's a common IP being contacted for multiple captures. In order to load multiple result files, either specify a folder to the `-r` flag and CallMapper will automatically recursively look for files named "Result.json" and attempt to load and parse them. If specific files are wanted, you may provide with a comma separated value to the `-r` argument. 

## Usage:

**Visualize the output from WhoYouCalling**:
```
python callmapper.py -r ./Result.json
```

### Filtering

In the `Map` tab in the hosted Web UI, you may filter the nodes in the network graph in the left side pane. The filtering works by only showing data related to the specified filter. For instance, if you specifiy destination IP to be 8.8.8.8, only that IP node will be visible if it's included.  

The input fields, selection boxes and "free text", can either filter nodes or the edges. The edges can be filtered based on the transport protocol or the destination port. When filtered, there may be nodes that are "isolated", e.g. do not have any edge to another node. In this case, it's recommended to check the `Isolated nodes` checkbox under `General exclusion`. 

For all of the "free text" fields, you may also negate the filter with prepending the exclamation character before the value (`!`). For instance, you do NOT want to see traffic going to port 443, in which you can specifiy `!443` in the destination port field. Or perhaps, you do not want to see domains ending with .com, you add `!.com`, etc.

Some of the fields filter a bit differently than others, as i've adjusted them based on what they're filtering.

| Type | Field | Logic | Filters |  
| --- | --- | --- | --- | 
| General | `Processes without telemetry` | Filters processes that do not have any TCIP activity. Useful when filtering for IPs, Ports or transport protocol.  | Nodes |
| General | `IPs and domains without process` | Filters IPs and domains that are not connected to a process. Useful when filtering for processes. | Nodes |
| General | `Isolated nodes` | Filters nodes that are isolated. Works just like the general exclusion for `Processes without telemetry` and `IPs and domains without process` but it captures all nodes | Nodes |
| General | `Loopback or linklocal` | Filters IPs that are either loopback or linklocal | Nodes |   
| TCPIP | `External or local IPs` | Filters if the IP is a external (Public) or local (Private) IP | Nodes |
| TCPIP | `IP Version` | Filters IPs that's either IPv4 or IPv6 | Nodes | 
| TCPIP | `Transport Protocol` | Filters traffic that's either TCP or UDP | Edges | 
| TCPIP | `Destination IP` | Filters IPs that starts with the provided value. Allows for narrowing down traffic to specific networks. I'd like to call it poor mans CIDR filtering | Nodes | 
| TCPIP | `Destination Port` | Filters traffic going to the provided value with an exact match | Edges | 
| DNS | `Domain name` | Filters domains that contain the provided value as domain name| Nodes |  
| Process | `Process name` | Filters processes that contain the provided value as process name | Nodes |
| Process | `Executable Path` | Filters processes that contain the provided value as executable path | Nodes |
| Process | `Executable created after` | Filters processes for the provided date or with full time for executables creation time. For instance, `2026-01-01` works, as well as `2026-01-01 13:14:24` | Nodes | 
| Process | `Executable created before` | Filters processes for the provided date or with full time for executables creation time. For instance, `2026-01-01` works, as well as `2026-01-01 13:14:24`  | Nodes | 

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
