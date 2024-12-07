# WhoYouCalling 

![Python Versions](imgs/version.svg)
![Groppy version](imgs/target_framework.svg)
![Groppy version](imgs/dependencies.svg)

Monitors network activity made by a process through the use of [Windows Event Tracing (ETW)](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-) and Full Packet Capture (FPC). Filters a generated .pcap file with BPF based on the detected network activity made by the process. 
This application makes process network monitoring hella' easy.

<details>
  <summary>"Why not just use ProcMon+Wireshark??"🤔🤔</summary>

One of the best methods of monitoring activities by a process in Windows is with the Sysinternal tool [ProcMon](https://learn.microsoft.com/sv-se/sysinternals/downloads/procmon). 
However, there are some downsides:
1. **Manual Work**: To get a Full Packet Capture per process you need to manually start a packet capture with a tool like Wireshark/Tshark, and create a filter for endpoints based on the results of ProcMon, which can be timeconsuming and potential endpoints may be missed due to human error if the process is not automated.
2. **Child processes**: It can be tedious to maintain a track record of all of the child processes that may spawn and the endpoints they're communicating with.
3. **DNS queries**: (AFAIK) ProcMon doesn't support capturing DNS queries. It does provide with UDP/TCP sent to port 53, but no information of the actual domain name that's queried nor the given address response.
</details>

## Features: 
- Can monitor every running process.
- Can monitor a specific process.
- Can start an executable and monitor it's process.
- Can monitor additional related processes based on executable names.
- Executables can be run as other users and in elevated and unelevated states. 
- Creates a full packet capture .pcap file per process.
- Records TCPIP activities made by a processes, IPv4 and IPv6.
- Records DNS requests and responses made and retrieved by applications.
- Creates Wireshark filter for domains queried via DNS with the DNS responses.
- Can specify pcap filtering to only record TCPIP activity being sent from the process.
- Can be automated with a timer.
- By default all monitoring is applied to all spawned child processes.
- Can kill spawned process and its childprocesses on stop. 
- Process and DNS results can be exported to JSON.
- Can generate a Wireshark DFL filter per process.
- Can generate a BPF filter per process.

## Usage:
(*Must be run as administrator - for packet capture and listening to ETW*) 

![Example Usage](imgs/ExampleUsage.gif)

**Get a list of available interfaces to monitor**:
```
WhoYouCalling.exe --getinterfaces
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
WhoYouCalling.exe --illuminate --interface 8
```

**Execute a binary with arguments. Output the results to a folder on the user desktop**:
```
WhoYouCalling.exe --execute C:\Users\H4NM\Desktop\TestApplication.exe --arguments "--pass=ETph0n3H0m3" --interface 4 --output C:\Users\H4NM\Desktop
```

**Listen to process with PID 1337 and output the results to json. Skip packet capture**:
```
WhoYouCalling.exe --PID 24037 --nopcap --json --output C:\Users\H4NM\AppData\Local\Temp
```

**Run sus.exe for 60 seconds with FPC on the 8th interface. When the timer expires, kill tracked processes - including child processes**:
```
WhoYouCalling.exe -e C:\Users\H4NM\Desktop\sus.exe -t 60 -k -i 8 -o C:\Users\H4NM\Desktop
```

**Execute firefox.exe and monitor for other processes with an including name pattern** (*This is especially needed if the main processes calls an already running process like `explorer.exe` to start a child process, if only the PID or executable is provided at start.*)
```
WhoYouCalling.exe -e "C:\Program Files\Mozilla Firefox\firefox.exe" --nopcap --names "firefox.exe,svchost,cmd"
```

### Complementary Tools
There are other tools that can compliment your quest of application network analysis:
- [Frida](https://frida.re/): Provides the most granular interaction with applications in which you can view API calls made. 
	- *"It lets you inject snippets of JavaScript or your own library into native apps on Windows, macOS, GNU/Linux, iOS, watchOS, tvOS, Android, FreeBSD, and QNX."*
- [Deluder](https://github.com/Warxim/deluder) and [PETEP (PEnetration TEsting Proxy)](https://github.com/Warxim/petep): Deluder uses frida but acts as an interface towards capturing the network traffic made by the application, similar to **WhoYoucalling**. Deluder also allows for many other fun things, including integration with the PETEP proxy for viewing and editing packets live.
- [Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview): A simple and native sandbox in Windows. I strongly recommend using a sandbox or VM when when executing unknown applications. There's also the possibility of adding your own configuration for the Windows Sandbox to harden it a bit further or include WhoYouCalling with the sandbox on start. See more [here](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file)

### Limitations
- **DNS**: In ETW, `Microsoft-Windows-DNS-Client` only logs A and AAAA queries, neglecting other DNS query types such as PTR, TXT, MX, SOA etc. It does capture CNAME and it's respective adresses, which are part of the DNS response. However, with the FPC the requests are captured either way, just not portrayed as in registered DNS traffic by the application.
- **Execution integrity**: It's currently not possible to delegate the privilege of executing applications in an elevated state to other users, meaning that if you want to run the application elevated you need to be signed in as the user with administrator rights.   
  Since WhoYouCalling requires elevated privileges to run (*ETW + FPC*), spawned processes naturally inherits the security token making them also posess the same integrity level - and .NET api does not work too well with creating less privileged processes from an already elevated state.
  The best and most reliable approach was to duplicate the low privileged token of the desktop shell in an interactive logon (explorer.exe).
  However, there may be use cases in which WhoYouCalling is executed via a remote management tool like PowerShell, SSH or PsExec, where there is no instance of a desktop shell, in these case you need to provide a username and password of a user that may execute it. 

### Dependencies
This project has been tested and works with .NET 8 with two nuget packages, and drivers for capturing network packets: 
- FPC: 
  - [SharpCap](https://github.com/dotpcap/sharppcap)
  - [npcap](https://npcap.com/#download)
- ETW: [Microsoft.Diagnostics.Tracing.TraceEvent](https://www.nuget.org/packages/Microsoft.Diagnostics.Tracing.TraceEvent/)

*npcap is optional when running WhoYouCalling if packet capture is not needed*

### Installing/Compiling instructions
Follow these steps for compiling from source:
1. Make sure [.NET 8](https://learn.microsoft.com/en-us/dotnet/core/install/windows) is installed

2. Download and install [npcap](https://npcap.com/#download). It enables packet capture in Windows. It's not needed if the flag for not capturing packets is provided.

3. Download this repo
```
git clone https://github.com/H4NM/WhoYouCalling.git
```

4. Enter project
```
cd WhoYouCalling
```

5. Install the related packages (SharpCap and TraceEvent). 
```
dotnet restore
```

6. Build 
```
dotnet publish -c Release -r win-(x64 or x86) --self-contained true
```

7. Run
```
bin\Release\net8.0\win-x64\WhoYouCalling.exe [arguments]...
```



# 🐛 Bugs or Requests? ✨ Create an issue! 🚀

### To Do:
- Refactor. Lots and lots to refactor and make more tidy :) 
- Add a summary text report

### Nice to have
- Network graph visualizing the process tree and summarized network traffic by each process