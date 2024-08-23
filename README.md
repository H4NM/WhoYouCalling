# WhoYouCalling
Reviews the network activity made by an executable through the use of Windows Event Tracing (ETW) and by conducting a Full Packet Capture that's subjected to BPF filtering based on the detected network activity made by the process. 

### To do:
- [X] ~~Remove debugging function and only have one in which the type is debug~~
- [X] ~~Add cmdline flags~~ 
- [X] ~~Add check for if the Process with provided PID is running~~
- [X] ~~Add functionality to enable~~
	- [X] ~~timer of function executed~~ 
	- [X] ~~PID provided only~~ 
	- [X] ~~Retrieve ImageName from PID~~
	- [X] ~~Remove Full PCAP when done~~
- [X] ~~Add decent way of asserting the processed data for generating a BPF Filter~~
- [X] Make JSON export possible
- [X] Make the bpfBasedFilters a whole new Dict that takes multiple different types of data for each PID. This will be harder to maintain but due to the increase of interesting data to store and to the potential need of having output to JSON format it would be beneficial. Will be painful to change.
	- [X] The current state of BPF Filters strictly reflect the actions of the process of reading sent, and not received packets. This may not be preferred when doing application analys, except if you only want to inspect what the applications says...
- [X] Enable creating PCAPs for each child process and main process only / Create text-files with defined BPF filters per process
		- Side note: Discovered that some binaries may utilize calling an already running process (such as steam games), in which tracking the child process is not possible UNLESS the running steam process is terminated beforehand in which calling the binary directly also invokes steam which in turn is classfied as a child process etc. 
- [ ] Possibly add check if the defined network device is not localhost, in which network activity of localhost should not define the BPF filter since they're redundant
- [ ] Add flag to only filter one way communication for FPC. Default will include response as well.
- [X] ~~Features~~
  - [X] ~~specifing an existing PID to listen to rather than starting an executable~~
  - [X] ~~Specifying directory in which the captured root folder is created~~
  - [X] ~~Specifying a Timer for which the executable runs where its terminated afterwards to enable automating the process~~
