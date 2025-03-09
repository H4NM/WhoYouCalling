# WhoYouCalling 

![WYC version](imgs/version.svg)
![Framework](imgs/target_framework.svg)
![WYC dependencies](imgs/dependencies.svg)
![Visualization dependencies](imgs/visualization_dependencies.svg)

A Windows commandline tool that monitors a process network activity using [Windows Event Tracing (ETW)](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-) and full packet capture. A packet capture file (.pcap) is generated and filtered based on the recorded TCPIP activity, allowing for a pcap file per process.  
WhoYouCalling makes process network monitoring hella' easy.

### FAQ
<details>
  <summary>Who is this tool for?</summary>
  

It's a tool for anyone that would like to know what network traffic is coming from processes in Windows. Some examples:
- **Blueteamers**: Incident response and controlled malware analysis.
- **Security researchers**: Understanding what an application is doing to identify vulnerabilities.
- **Game hackers**: Understanding game traffic for possible packet manipulation.
- **Red teamers**: Payload creators for testing detection.
- **Sysadmins**: Understanding which traffic a host or process requires before a migration.
- **Curious/paranoid people**: That just wants to understand who the heck processes are calling.

</details>

<details>
  <summary>What about ProcMon, TCPView and Pktmon??</summary>

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

</details>

<details>
  <summary>What does this tool not do?</summary>

  - **TCPIP**: WhoYouCalling does not capture traffic outside of the TCPIP stack, e.g. ICMP (layer 3, network) and ARP (layer 2, data link).
  - **Server applications**: The tool does not monitor process socket creations for listening to ports, as it's mainly focused on processes in a client perspective. However, it can still be useful for monitoring to server applications based on their overall TCPIP activity.

</details>


## Features: 
- Start or monitor an already running process.
- Monitor every running process simultaneously.
- Create a full packet capture (.pcap) file per process.
- Monitor processes based on process name.
- Run executables as other users and in elevated or unelevated state. 
- Record TCPIP activities, IPv4 and IPv6.
- Record DNS requests and responses.
- Create Wireshark filter based on DNS responses for domains.
- Specify pcap filtering to only record TCPIP activity being sent from the process.
- Timer for automated monitoring.
- Monitoring is applied to all spawned child processes by default.
- Spawned process and its childprocesses can be killed on stop. 
- JSON output of results.
- Perform API lookups to get the reputation of IPs and domains.
- Generate a Wireshark DFL filter per process.
- Generate a BPF filter per process.
- Visualize the processes and their network activity with an interactive network graph.
- Perform automatic API lookups of IPs and domains.

## Usage:
> **Note:** Must be run as administrator - for packet capture and listening to ETW.

![Example Usage](imgs/ExampleUsage.gif)

**Get a list of available interfaces to monitor**:
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

**Capture every network and process activity from everything**:
```
wyc.exe --illuminate --interface 8
```

**Execute a binary with arguments. Output the results to a folder on the user desktop**:
```
wyc.exe --executable C:\Users\H4NM\Desktop\TestApplication.exe --arguments "--pass=ETph0n3H0m3" --interface 4 --output C:\Users\H4NM\Desktop
```

**Listen to process with PID 24037 and skip packet capture**:
```
wyc.exe --PID 24037 --nopcap --output C:\Users\H4NM\AppData\Local\Temp
```

**Run sus.exe for 60 seconds with FPC on the 8th interface. When the timer expires, kill tracked processes - including child processes**:
```
wyc.exe -e C:\Users\H4NM\Desktop\sus.exe -t 60 -k -i 8 -o C:\Users\H4NM\Desktop
```

**Execute firefox.exe and monitor for other processes with an including name pattern** (*This is especially needed if the main processes calls an already running process like `explorer.exe` to start a child process, if only the PID or executable is provided at start.*)
```
wyc.exe -e "C:\Program Files\Mozilla Firefox\firefox.exe" --nopcap --names "firefox.exe,svchost,cmd"
```

## Analyze the results
To analyze and visualize the results, this repo includes **CallMapper**, a Python and JavaScript solution that reads the JSON output from WhoYouCalling and hosts a network graph of all processes and their related network activity. **CallMapper** allows for performing automatic API lookups of IPs and domains to statically enrich the data.

![Example Usage CallMapper](imgs/ExampleUsageCallMapper.gif)

**Simple usage**:
```
python callmapper.py -r ./Result.json
```

See [CallMapper README.md](https://github.com/H4NM/WhoYouCalling/blob/main/CallMapper/README.md) for more.  

### Complementary Tools
There are other tools that can compliment your quest of application network analysis:
- [Frida](https://frida.re/): Provides the most granular interaction with applications in which you can view API calls made. 
	- *"It lets you inject snippets of JavaScript or your own library into native apps on Windows, macOS, GNU/Linux, iOS, watchOS, tvOS, Android, FreeBSD, and QNX."*
- [Deluder](https://github.com/Warxim/deluder) and [PETEP (PEnetration TEsting Proxy)](https://github.com/Warxim/petep): Deluder uses frida but acts as an interface towards capturing the network traffic made by the application, similar to **WhoYoucalling**. Deluder also allows for many other fun things, including integration with the PETEP proxy for viewing and editing packets live.
- [Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview): A simple and native sandbox in Windows. I strongly recommend using a sandbox or VM when when executing unknown applications. There's also the possibility of adding your own configuration for the Windows Sandbox to harden it a bit further or include WhoYouCalling with the sandbox on start. See more [here](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)

### Limitations
- **DNS**: In ETW, `Microsoft-Windows-DNS-Client` only logs A and AAAA queries, neglecting other DNS query types such as PTR, TXT, MX, SOA etc. It does capture CNAME and it's respective adresses, which are part of the DNS response. However, with the FPC the requests are captured either way, just not portrayed as in registered DNS traffic by the application. The FPC and registered TCPIP activity helps identify processes that do not utilize **Windows DNS Client Service** (e.g. `nslookup`) since they're not logged in the DNS ETW.
- **Execution integrity**: Since WhoYouCalling requires elevated privileges to run (*ETW + FPC*), spawned processes naturally inherits the security token making them also posess the same integrity level - and .NET api does not work too well with creating less privileged processes from an already elevated state.
  The best and most reliable approach was to duplicate the low privileged token of the desktop shell in an interactive logon (explorer.exe).
  However, there may be use cases in which WhoYouCalling is executed via a remote management tool like PowerShell, SSH or PsExec, where there is no instance of a desktop shell, in these case you need to provide a username and password of a user that may execute it. It's also not currently possible to delegate the privilege of executing applications in an elevated state to other users, meaning that if you want to start another application with WYC in an elevated state, you need to be signed in as the user with administrator rights and provide the flag for running elevated.  

### Dependencies
This project has been tested and works with .NET 8 with two nuget packages, and drivers for capturing network packets: 
- FPC: 
  - [SharpCap](https://github.com/dotpcap/sharppcap)
  - [npcap](https://npcap.com/#download) (*Optional - if full packet capture is not needed.*)
- ETW: [Microsoft.Diagnostics.Tracing.TraceEvent](https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent/)

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


# 🐛 Bugs or Requests? ✨ Create an issue! 🚀

### To Do:
- Refactor. Lots and lots to refactor and make more tidy :)

### Nice to have
- Linux port
- Process network redirect to proxy for TLS inspection
