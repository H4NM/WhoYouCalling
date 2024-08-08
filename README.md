# WhoYouCalling
Reviews the network activity made by an executable through the use of Windows Event Tracing (ETW) and by conducting a Full Packet Capture that's subjected to BPF filtering based on the detected network activity made by the process. 

### To do:
- [ ] Remove debugging function and only have one in which the type is debug.
- [ ] Add cmdline flags 
- [ ] Add smart way of asserting the processed data for generating a BPF Filter
- Features
  - [ ] specifing an existing PID to listen to rather than starting an executable