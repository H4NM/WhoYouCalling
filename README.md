<h1 align="center">WhoYouCalling 📞</h1>

<p align="center">
  <img src="imgs/version.svg" />
  <img src="imgs/target_framework.svg" />
  <img src="imgs/dependencies.svg" />
  <img src="imgs/visualization_dependencies.svg" />
</p>

<p align="center">
  <em>A Windows commandline tool that monitors process TCPIP and DNS activity using [Windows Event Tracing (ETW)](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-). A packet capture file (.pcap) can be generated and filtered based on the recorded TCPIP activity, allowing for a full packet capture per process.</em> 
</p>

This tool is for anyone that would like to know what network traffic is coming from processes in Windows:
- **Security researchers**: Understanding an application and identifying flaws.
- **Game hackers**: Understanding game traffic for possible packet manipulation.
- **Red teamers**: Payload creators for testing detection.
- **Blue teamers**: Incident response and controlled malware analysis.
- **System administrators**: Understanding which traffic a host or process requires before a migration.
- **Curious/paranoid people**: That just wants to understand who processes are calling.


## Some features: 
- Generates a full packet capture (.pcap) file per process.
- Creates Wireshark (DFL) filters based on DNS responses.
- Produces nework filters per process (BPF & DFL).
- Timer for automated monitoring.
- JSON and simplified text output of results.
- Retrieves metadata about binaries related to the processes.
- Visualize processes, IPs and domains with a network graph.
- Perform API lookups to VirusTotal and AbuseIPDB. 

## Usage:
> WhoYouCalling must be run as **administrator** (for packet capture and listening to ETW).

WhoYouCalling can be run with **three** different modes:
- **Machine**: Registers outgoing TCPIP and DNS traffic from the machine. 
```
wyc.exe --machine 
```
- **Executable**: Executes a specified binary and monitors the TCPIP and DNS activity from that process and child processes.
```
wyc.exe --executable C:\Users\H4NM\Desktop\TestApplication.exe
```
- **PID**: Monitors the TCPIP and DNS activity from the specified process with the provided PID and its child processes. 
```
wyc.exe --pid 24037 
```

For full packet capture you need to [download and install the npcap driver](https://npcap.com/#download). Thereafter you may list the available interfaces to be monitored with `--getinterfaces` or `-g` for short: 
```
wyc.exe --getinterfaces
[*] Available interfaces:
 0) WAN Miniport (Network Monitor)
 1) WAN Miniport (IPv6)
...
 8) Realtek USB GbE Family Controller
        IPv4: 192.168.1.10
        IPv6: fd12:3456:789a:1::2
```

To chose an interface, you can either supply the number in the left list, or provide with the assigned IP of that interface or part of it. For instance,

```
# The interface number specified with the main mode machine 
wyc.exe --machine -i 4

# The full assigned IP with the main mode machine
wyc.exe -M -i 192.168.1.45

# Partial assigned IP with the main mode machine
wyc.exe -M -i 192.168
```
*if there are multiple interfaces with the provided partial IP it will select the first one it encounters.*

## Analyze the results
To analyze and visualize the results, this project includes **CallMapper**, a Python and JavaScript solution that reads the JSON output from WhoYouCalling and hosts a network graph of all processes and their related network activity. **CallMapper** allows for filtering and searching through nodes and performing API lookups of checksums, IPs and domains.

![Example Usage CallMapper](imgs/ExampleUsageCallMapper.gif)

**Simple usage**:
```
python callmapper.py -r ./Result.json
```

See [CallMapper README.md](https://github.com/H4NM/WhoYouCalling/blob/main/CallMapper/README.md) for more.  


### Limitations
- **DNS**: In ETW, `Microsoft-Windows-DNS-Client` only logs A and AAAA queries, neglecting other DNS query types such as PTR, TXT, MX, SOA etc. It does capture CNAME and it's respective adresses, which are part of the DNS response. However, with the FPC the requests are captured either way, just not portrayed as in registered DNS traffic by the application. The FPC and registered TCPIP activity helps identify processes that do not utilize **Windows DNS Client Service** (e.g. `nslookup`) since they're not logged in the DNS ETW.
- **Execution integrity**: Since WhoYouCalling requires elevated privileges to run (*ETW + FPC*), spawned processes naturally inherits the security token making them also posess the same integrity level - and .NET api does not work too well with creating less privileged processes from an already elevated state.
  The best and most reliable approach was to duplicate the low privileged token of the desktop shell in an interactive logon (explorer.exe).
  However, there may be use cases in which WhoYouCalling is executed via a remote management tool like PowerShell, SSH or PsExec, where there is no instance of a desktop shell, in these case you need to provide a username and password of a user that may execute it. It's also not currently possible to delegate the privilege of executing applications in an elevated state to other users, meaning that if you want to start another application with WYC in an elevated state, you need to be signed in as the user with administrator rights and provide the flag for running elevated.  

### Dependencies
Nuget packages: 
- [SharpCap](https://github.com/dotpcap/sharppcap)
- [Microsoft.Diagnostics.Tracing.TraceEvent](https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent/)

Network Driver (*Optional - if full packet capture is wanted.*):
- [npcap](https://npcap.com/#download) 

### Installing/Compiling instructions
Follow these steps for compiling from source:
1. **Install .NET 8**  
   Ensure [.NET 8](https://learn.microsoft.com/en-us/dotnet/core/install/windows) is installed on your system.

2. **(Optional) Install Npcap**  
   Download and install [Npcap](https://npcap.com/#download) to enable packet capture in Windows.  
   > **Note:** Npcap is not required and you may provide the flag to disable packet capture when running the program.

3. **Clone the Repository**  
   Download the source code by cloning this repository:
```sh
git clone https://github.com/H4NM/WhoYouCalling.git
```

4. **Enter project**
```sh
cd WhoYouCalling
```

5. **Install the related packages (SharpCap and TraceEvent).**
```
dotnet restore
```

6. **Build the project**
```
dotnet publish -c Release -r win-x64 --self-contained true
```

7. **Run it**
```
bin\Release\net8.0\win-x64\wyc.exe [arguments]...
```

## What about ProcMon, TCPView and Pktmon??

Some of the best methods of monitoring network activities by a process in Windows is with the Sysinternal tools [ProcMon](https://learn.microsoft.com/sv-se/sysinternals/downloads/procmon) or [TCPView](https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview). 
There's also the native Windows application [Pktmon](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon) that's great for capturing packets in different network stacks and event correlations.

The tools and what they're offering:
- **ProcMon**: <i>Continous</i> TCPIP traffic monitoring of processes.
- **TCPView**: Retrieves  <i>active</i> TCPIP connections of processes.
- **Pktmon**: Collects packets from different network stacks.

Neither ProcMon nor TCPView captures the DNS traffic or provides with packet capture. Pktmon doesnt register which PID or process name the network packet comes from unless combined with additional log sources. But it doesn't filter a packet capture file for these.
The main downsides that are adressed by WhoYouCalling:
1. **Manual work**: To get a Full Packet Capture per process you need to manually start a packet capture with a tool like Wireshark/Tshark, and create a filter for endpoints based on the results of ProcMon or TCPView, which can be time consuming and potential endpoints may be missed due to human error if the process is not automated. Pktmon still requires manual mapping with events from other log sources.
2. **Child processes**: It can be tedious to maintain a track record of all of the child processes that may spawn and the endpoints they're communicating with.
3. **DNS queries**: Neither ProcMon nor TCPView supports capturing DNS queries. They do provide with insights of UDP/TCP sent to port 53, but no information of the actual domain name that's queried nor the given address response.

Simply put, WhoYouCalling is a combination of these tools and addresses the downsides defined above, and more. 
I still highly recommend the other listed tools as they may fit other use cases. ProcMon, for instance, can provide with information of file system activity and access right invocations, which WhoYouCalling cant.
WhoYouCalling is strictly for network based activity analysis of processes.


# 🐛 Bugs or Requests? ✨ Create an issue! 🚀

### To Do:
- Refactor. Lots and lots to refactor and make more tidy :)

### Nice to have
- Linux port
