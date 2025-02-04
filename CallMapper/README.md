# CallMapper
CallMapper is a visualization solution that offers a network graph with analytics of looking up domains and IP addresses via static links to websites such as ipinfo.com, whois.com and virustotal.com. It will also be possible to perform API lookups that will populate the visualized data with more details. The choice to use python and javascript is mainly due to simplicity. Python offers flexible JSON processing and transparency as all it requires is one script. The Cytoscape javascript library offers a greater amount of customization and interaction with the visualized data. 

## How it works:
1. callmapper.py processes the JSON results file from WhoYouCalling and creates a data.json file in the same directory as the script.
2. callmapper.py hosts a HTTP server in the same directory as the script at localhost port 8080 that serves the data.json and the cytoscape.min.js file
3. You can now view the visualization via http://127.0.0.1:8080 in a web browser

## Usage:

**Visualize the output from WhoYouCalling**:
```
python callmapper.py Result.json
```
> **Note:** You can visualize an already existing data.json file by not providing a Result.json and if that data.json file exists in the same directory as callmapper.py.
