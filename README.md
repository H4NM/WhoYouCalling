﻿# WhoYouCalling 

Monitors network activity made by a process through the use of [Windows Event Tracing (ETW)](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/event-tracing-for-windows--etw-) and Full Packet Capture (FPC). Filters a generated .pcap file with BPF based on the detected network activity made by the process. 
This application makes process network monitoring hella' easy.

<details>
  <summary>"Why not just use ProcMon+Wireshark??"🤔🤔</summary>

One of the best methods of monitoring activities by a process in Windows is with the Sysinternal tool [ProcMon](https://learn.microsoft.com/sv-se/sysinternals/downloads/procmon). 
However, there are some downsides:
1. **Manual Work**: To get a Full Packet Capture per process you need to manually start a packet capture with a tool like Wireshark/Tshark, and create a filter for endpoints based on the results of ProcMon, which can be timeconsuming and potential endpoints may be missed due to human error if the process is not automated.
2. **Child processes**: It can be tedious to maintain a track record of all of the child processes that may spawn and the endpoints they're communicating with.
3. **DNS queries**: (AFAIK) ProcMon doesn't support capturing DNS queries. It does enable provide with UDP Send to port 53, but no information of the actual domain name that's queried nor the given address response.
</details>

## Features: 
- Can start and monitor an executable.
- Can monitor an already running process.
- Can monitor additional related processes based on executable names.
- Creates a full packet capture .pcap file per process.
- Records TCPIP activities made by a processes, netflow style.
- Records DNS requests and responses made and retrieved by applications.
- Can specify pcap filtering to only record TCPIP activity being sent from the process. This is applied to the recorded .pcap.
- Can be automated with a timer.
- By default all monitoring is applied to all spawned child processes.
- Can kill spawned process and its childprocesses on stop. 
- Process and DNS results can be exported to JSON.
- Can generate a Wireshark DFL filter per process.
- Can generate a BPF filter per process.

## Usage:
(*Must be run as administrator - for packet capture and listening to ETW*) 

**Execute a binary with arguments and track all child processes made by it. Output the results to a folder on the user desktop**:
`WhoYouCalling.exe -e C:\Users\Desktop\TestApplication.exe -a "--pass=ETph0n3H0m3" -f -i 4 -o C:\Users\H4NM\Desktop`

**Listen to process with PID 1337 and output the results to json. Skip FPC (Which will only log the ETW activity)**:
`WhoYouCalling.exe --pid 1337 --nopcap --json --output C:\Users\H4NM\AppData\Local\Temp`

**Run sus.exe for 60 seconds with FPC on the 8th enumerated interface. When the timer expires, kill all tracked pprocesses - including child processes**:
`WhoYouCalling.exe -e C:\Users\H4NM\Desktop\sus.exe -t 60 -k -i 8 -o C:\Users\H4NM\Desktop`
	
### Example results
![ConsoleResults](imgs/ExampleConsoleOutput.png)
![FolderResults](imgs/ExampleOutput.png)

### Complementary Tools
There are other tools that can compliment your quest of application network analysis:
- [Frida](https://frida.re/): Provides the most granular interaction with applications in which you can view API calls made. 
	- *"It lets you inject snippets of JavaScript or your own library into native apps on Windows, macOS, GNU/Linux, iOS, watchOS, tvOS, Android, FreeBSD, and QNX."*
- [Deluder](https://github.com/Warxim/deluder) and [PETEP (PEnetration TEsting Proxy)](https://github.com/Warxim/petep): Deluder uses frida but acts as an interface towards capturing the network traffic made by the application, similar to **WhoYoucalling**. Deluder also allows for many other fun things, including integration with the PETEP proxy for viewing and editing packets live.

Did i miss any other suitable tool? Let me know.

### Limitations
- **DNS**: In ETW, `Microsoft-Windows-DNS-Client` only logs A and AAAA queries, neglecting other DNS query types such as PTR, TXT, MX, SOA etc. It does capture CNAME and it's respective adresses, which are part of the DNS response. However, with the FPC the requests are captured either way, just not portrayed as in registered DNS traffic by the application.

### To Do:
- Add inverted communication, in which only received to the process filter is applied.
  - Also adjust flag for specifying. Atm it's a bool flag. It should be able to take options such as direction of communication 
- Refactor. Lots and lots to refactor and make more tidy :) 