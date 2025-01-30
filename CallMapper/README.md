# CallMapper
CallMapper is a visualization solution that offers a network graph with analytics support of looking up domains and IP addresses via static links to websites such as ipinfo.com, whois.com and virustotal.com. It will also be possible to perform API lookups that will populate the visualized data with more details. The choice to use python and javascript is mainly due to simplicity. Python offers flexible JSON processing and transparency as all it requires is one script. The Cytoscape javascript library offers a greater amount of customization and interaction with the visualized data. 

## Usage:

**Visualize the output from WhoYouCalling**:
```
python callmapper.py Result.json
```
> **Note:** You can visualize an already existing data.json file by not providing a Result.json and if that data.json file exists in the same directory as callmapper.py.
