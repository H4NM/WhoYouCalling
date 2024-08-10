# WhoYouCalling
Reviews the network activity made by an executable through the use of Windows Event Tracing (ETW) and by conducting a Full Packet Capture that's subjected to BPF filtering based on the detected network activity made by the process. 

### To do:
- [X] Remove debugging function and only have one in which the type is debug.
- [X] Add cmdline flags 
	- [ ] Add flag for specifying output dir
- [X] Add check for if the Process with provided PID is running
- [ ] Add functionality to enable:
	- [X] timer of function executed (needs tweaking)
	- [X] PID provided only 
	- [X] Retrieve ImageName from PID
	- [X] Remove Full PCAP when done
- [ ] Add smart way of asserting the processed data for generating a BPF Filter
- [ ] When debugging is inactive, have the output be statistically based and updated with ANSII(?) to clear the previous output to prevent polluting the terminal
- Features
  - [ ] specifing an existing PID to listen to rather than starting an executable
  - [ ] Specifying directory in which the captured root folder is created
  - [ ] Specifying a Timer for which the executable runs where its terminated afterwards to enable automating the process
  - [ ] Specify debugging levels in which the exact packets from FPC is also logged to show if any packets are captured