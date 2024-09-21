
using System.Timers;
using System.Text.Json;

//ETW
using Microsoft.Diagnostics.Tracing.Session;

// CUSTOM
using WhoYouCalling.Utilities;
using WhoYouCalling.Process;
using WhoYouCalling.Network;
using WhoYouCalling.Network.FPC;
using WhoYouCalling.Network.DNS;
using WhoYouCalling.ETW;
using WhoYouCalling.WhoYouCalling.Network;
using WhoYouCalling.Utilities.Arguments;

namespace WhoYouCalling
{
    class Program
    {
        private static List<int> s_trackedChildProcessIds = new List<int>(); // Used for tracking the corresponding executable name to the spawned processes
        private static List<string> s_etwActivityHistory = new List<string>(); // Summary of the network activities made

        private static Dictionary<int, HashSet<NetworkPacket>> s_processNetworkTraffic = new Dictionary<int, HashSet<NetworkPacket>>();
        private static Dictionary<int, MonitoredProcess> s_collectiveProcessInfo = new Dictionary<int, MonitoredProcess>();
        private static Dictionary<string, HashSet<DNSResponse>> s_dnsQueryResults = new Dictionary<string, HashSet<DNSResponse>>();

        private static bool s_shutDownMonitoring = false;
        private static string s_mainExecutableFileName = "";

        private static LivePacketCapture s_livePacketCapture = new LivePacketCapture();
        private static KernelListener s_etwKernelListener = new KernelListener();
        private static DNSClientListener s_etwDnsClientListener = new DNSClientListener();

        private static string s_rootFolderName = "";
        private static string s_fullPcapFile = "";
        private static string s_etwHistoryFile = "";
        private static string s_jsonResultsFile = "";
        private static string s_jsonDNSFile = "";

        private static int s_combinedFilterProcId = 0;

        private static DateTime s_startTime = DateTime.Now;

        // Arguments
        private static ArgumentData s_argumentData;
        public static bool Debug = false;
        public static bool TrackChildProcesses = true;

        static void Main(string[] args)
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                ConsoleOutput.Print("Please run me as Administrator!", PrintType.Warning);
                return;
            }

            ArgumentManager argsManager = new ArgumentManager();
            s_argumentData = argsManager.ParseArguments(args);

            if (s_argumentData.InvalidArgumentValueProvided || argsManager.IsNotValidCombinationOfArguments(s_argumentData)) {
                ConsoleOutput.PrintHeader();
                ConsoleOutput.PrintHelp();
                System.Environment.Exit(1);
            }
            
            SetPublicVariablesFromArgument();

            SetCancelKeyEvent();
            ConsoleOutput.PrintStartMonitoringText();
            if (Debug)
            {
                ConsoleOutput.PrintArgumentValues(s_argumentData);
            }

            ConsoleOutput.Print("Retrieving executable filename", PrintType.Debug);
            s_mainExecutableFileName = GetExecutableFileName(s_argumentData.TrackedProcessId, s_argumentData.ExecutablePath);

            s_rootFolderName = Generic.NormalizePath(Generic.GetRunInstanceFolderName(s_mainExecutableFileName));

            s_argumentData.OutputDirectory = Generic.NormalizePath(s_argumentData.OutputDirectory);

            if (s_argumentData.ProvidedOutputDirectory) // If catalog to save data is specified
            {
                s_rootFolderName = $"{s_argumentData.OutputDirectory}{s_rootFolderName}";
            }

            ConsoleOutput.Print($"Creating folder {s_rootFolderName}", PrintType.Debug);
            FileAndFolders.CreateFolder(s_rootFolderName);
            SetGeneralMonitoringFileNames();

            // Retrieve network interface devices
            var devices = NetworkCaptureManagement.GetNetworkInterfaces(); // Returns a LibPcapLiveDeviceList
            if (devices.Count == 0)
            {
                ConsoleOutput.Print($"No network devices were found..", PrintType.Fatal);
                System.Environment.Exit(1);
            }
            using var device = devices[s_argumentData.NetworkInterfaceChoice];
            s_livePacketCapture.SetCaptureDevice(device);

            ConsoleOutput.Print($"Starting monitoring...", PrintType.Info);
            // Create and start thread for capturing packets if enabled
            if (!s_argumentData.NoPacketCapture) { 
                Thread fpcThread = new Thread(() => s_livePacketCapture.StartCaptureToFile(s_fullPcapFile));
                ConsoleOutput.Print($"Starting packet capture saved to \"{s_fullPcapFile}\"", PrintType.Debug);
                fpcThread.Start();
            }

            // Create and start threads for ETW. Had to make two separate functions for a dedicated thread for interoperability
            Thread etwKernelListenerThread = new Thread(() => s_etwKernelListener.Listen());
            Thread etwDnsClientListenerThread = new Thread(() => s_etwDnsClientListener.Listen());
            
            ConsoleOutput.Print("Starting ETW sessions", PrintType.Debug);
            etwKernelListenerThread.Start();
            etwDnsClientListenerThread.Start();

            if (s_argumentData.ExecutablePathProvided)
            {
                Thread.Sleep(3000); //Sleep is required to ensure ETW Subscription is timed correctly to capture the execution
                try
                {
                    ConsoleOutput.Print($"Executing \"{s_argumentData.ExecutablePath}\" with args \"{s_argumentData.ExecutableArguments}\"", PrintType.Debug);
                    ConsoleOutput.Print($"Executing \"{s_argumentData.ExecutablePath}\"", PrintType.Info);
                    s_argumentData.TrackedProcessId = ProcessManager.StartProcessAndGetId(s_argumentData.ExecutablePath, s_argumentData.ExecutableArguments);
                    CatalogETWActivity(eventType: EventType.Process, executable: s_mainExecutableFileName, execType: "Main", execAction: "started", execPID: s_argumentData.TrackedProcessId);
                }
                catch (Exception ex)
                {
                    ConsoleOutput.Print($"An error occurred while starting the process: {ex.Message}", PrintType.Fatal);
                    System.Environment.Exit(1);
                }
            }
            else // PID to an existing process was provided
            {
                ConsoleOutput.Print($"Listening to PID \"{s_argumentData.TrackedProcessId}\"", PrintType.Info);
                CatalogETWActivity(eventType: EventType.Process, executable: s_mainExecutableFileName, execType: "Main", execAction: "being listened to", execPID: s_argumentData.TrackedProcessId);
            }

            s_etwDnsClientListener.SetPIDAndImageToTrack(s_argumentData.TrackedProcessId, s_mainExecutableFileName);
            s_etwKernelListener.SetPIDAndImageToTrack(s_argumentData.TrackedProcessId, s_mainExecutableFileName);
            InstantiateProcessVariables(pid: s_argumentData.TrackedProcessId, executable: s_mainExecutableFileName);

            if (s_argumentData.ProcessRunTimerWasProvided)
            {
                double processRunTimerInMilliseconds = Generic.ConvertToMilliseconds(s_argumentData.ProcessRunTimer);
                System.Timers.Timer timer = new System.Timers.Timer(processRunTimerInMilliseconds);
                timer.Elapsed += TimerShutDownMonitoring;
                timer.AutoReset = false;
                ConsoleOutput.Print($"Starting timer set to {s_argumentData.ProcessRunTimer} seconds", PrintType.Debug);
                timer.Start();
            }

            while (true) // Continue monitoring and output statistics
            {
                ConsoleOutput.PrintMetrics();
                if (s_shutDownMonitoring) // If shutdown has been signaled
                {
                    ShutdownMonitoring();
                    break;
                }
            }
        }

        private static void ShutdownMonitoring()
        {
            Console.WriteLine(""); // Needed to adjust a linebreak since the runningStats print above uses Console.Write()
            ConsoleOutput.Print($"Stopping monitoring", PrintType.Info);
            if (s_argumentData.KillProcesses) // If a timer was specified and that processes should be killed
            {
                ProcessManager.KillProcess(s_argumentData.TrackedProcessId);
                foreach (int childPID in s_trackedChildProcessIds)
                {
                    ConsoleOutput.Print($"Killing child process with PID {childPID}", PrintType.Debug);
                    ProcessManager.KillProcess(childPID);
                }
            }
            ConsoleOutput.Print($"Stopping ETW sessions", PrintType.Debug);
            StopETWSessions();

            Dictionary<int, string> computedBPFFilterByPID = new Dictionary<int, string>();
            Dictionary<int, string> computedDFLFilterByPID = new Dictionary<int, string>();

            if (!s_argumentData.NoPacketCapture)
            {
                ConsoleOutput.Print($"Stopping packet capture saved to \"{s_fullPcapFile}\"", PrintType.Debug);
                s_livePacketCapture.StopCapture();

                ConsoleOutput.Print($"Producing filters", PrintType.Debug);
                computedBPFFilterByPID = NetworkFilter.GetNetworkFilter(s_processNetworkTraffic, s_argumentData.StrictCommunicationEnabled, FilterType.BPF);
                computedDFLFilterByPID = NetworkFilter.GetNetworkFilter(s_processNetworkTraffic, s_argumentData.StrictCommunicationEnabled, FilterType.DFL); 

                if (computedBPFFilterByPID.ContainsKey(s_combinedFilterProcId)) // 0 represents the combined BPF filter for all applications
                {
                    string filteredPcapFile = @$"{s_rootFolderName}\All {computedBPFFilterByPID.Count} processes filter.pcap";
                    string processBPFFilterTextFile = @$"{s_rootFolderName}\All {computedBPFFilterByPID.Count} processes filter.txt";
                    ConsoleOutput.Print($"Filtering saved pcap \"{s_fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter \"{computedBPFFilterByPID[s_combinedFilterProcId]}\"", PrintType.Debug);

                    FilePacketCapture filePacketCapture = new FilePacketCapture();
                    filePacketCapture.FilterCaptureFile(computedBPFFilterByPID[s_combinedFilterProcId], s_fullPcapFile, filteredPcapFile);
                    if (s_argumentData.OutputBPFFilter) // If BPF Filter is to be written to text file.
                    {
                        FileAndFolders.CreateTextFileString(processBPFFilterTextFile, computedBPFFilterByPID[s_combinedFilterProcId]); // Create textfile containing used BPF filter
                    }
                }

            }

            foreach (var kvp in s_collectiveProcessInfo)
            {
                int pid = kvp.Key;
                MonitoredProcess monitoredProcess = kvp.Value;

                // Check if the processes has any network activities recorded. If not, go to next process
                if (monitoredProcess.DNSQueries.Count() == 0 &&
                    monitoredProcess.IPv4LocalhostEndpoint.Count() == 0 &&
                    monitoredProcess.IPv4TCPEndpoint.Count() == 0 &&
                    monitoredProcess.IPv4UDPEndpoint.Count() == 0 &&
                    monitoredProcess.IPv6LocalhostEndpoint.Count() == 0 &&
                    monitoredProcess.IPv6TCPEndpoint.Count() == 0 &&
                    monitoredProcess.IPv6UDPEndpoint.Count() == 0)
                {
                    ConsoleOutput.Print($"Not creating folder with results for PID {pid}. No activities found", PrintType.Debug);
                    continue;
                }

                string executable = monitoredProcess.ImageName;
                string executabelNameAndPID = $"{executable}-{pid}";
                string processFolderInRootFolder = @$"{s_rootFolderName}\{executabelNameAndPID}";

                ConsoleOutput.Print($"Creating folder {processFolderInRootFolder}", PrintType.Debug);
                FileAndFolders.CreateFolder(processFolderInRootFolder);

                OutputProcessDNSDetails(monitoredProcess.DNSQueries, 
                                        outputFile: @$"{processFolderInRootFolder}\DNS queries.txt");

                OutputProcessNetworkDetails(monitoredProcess.IPv4TCPEndpoint,
                                            outputFile: @$"{processFolderInRootFolder}\IPv4 TCP Endpoints.txt",
                                            packetType: PacketType.IPv4TCP);

                OutputProcessNetworkDetails(monitoredProcess.IPv6TCPEndpoint,
                                            outputFile: @$"{processFolderInRootFolder}\IPv6 TCP Endpoints.txt",
                                            packetType: PacketType.IPv6TCP);

                OutputProcessNetworkDetails(monitoredProcess.IPv4UDPEndpoint,
                                            outputFile: @$"{processFolderInRootFolder}\IPv4 UDP Endpoints.txt",
                                            packetType: PacketType.IPv4UDP);

                OutputProcessNetworkDetails(monitoredProcess.IPv6UDPEndpoint,
                                            outputFile: @$"{processFolderInRootFolder}\IPv6 UDP Endpoints.txt",
                                            packetType: PacketType.IPv6UDP);

                OutputProcessNetworkDetails(monitoredProcess.IPv4LocalhostEndpoint,
                                            outputFile: @$"{processFolderInRootFolder}\Localhost Endpoints.txt",
                                            packetType: PacketType.IPv4Localhost);

                OutputProcessNetworkDetails(monitoredProcess.IPv6LocalhostEndpoint,
                                            outputFile: @$"{processFolderInRootFolder}\Localhost Endpoints IPv6.txt",
                                            packetType: PacketType.IPv6Localhost);

                // Wireshark DFL Filter
                if (s_argumentData.OutputWiresharkFilter)
                {
                    if (computedDFLFilterByPID.ContainsKey(pid))
                    {
                        string processDFLFilterTextFile = @$"{processFolderInRootFolder}\Wireshark filter.txt";
                        FileAndFolders.CreateTextFileString(processDFLFilterTextFile, computedDFLFilterByPID[pid]);
                    }
                    else if (computedDFLFilterByPID.ContainsKey(s_combinedFilterProcId))
                    {
                        string processDFLFilterTextFile = @$"{s_rootFolderName}\All {computedDFLFilterByPID.Count} processes filter.txt";
                        FileAndFolders.CreateTextFileString(processDFLFilterTextFile, computedDFLFilterByPID[s_combinedFilterProcId]); // Create textfile containing used BPF filter
                    }
                }


                // FPC
                if (computedBPFFilterByPID.ContainsKey(pid)) // Creating filtered FPC based on application activity
                {
                    string filteredPcapFile = @$"{processFolderInRootFolder}\Network Packets.pcap";
                    string processBPFFilterTextFile = @$"{processFolderInRootFolder}\BPF filter.txt";

                    ConsoleOutput.Print($"Filtering saved pcap \"{s_fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter.", PrintType.Debug);
                    FilePacketCapture filePacketCapture = new FilePacketCapture();
                    filePacketCapture.FilterCaptureFile(computedBPFFilterByPID[pid], s_fullPcapFile, filteredPcapFile);
                    if (s_argumentData.OutputBPFFilter) // If BPF Filter is to be written to text file.
                    {
                        FileAndFolders.CreateTextFileString(processBPFFilterTextFile, computedBPFFilterByPID[pid]); // Create textfile containing used BPF filter
                    }
                }
                else
                {
                    ConsoleOutput.Print($"Skipping creating dedicated PCAP file for {executable}. No recorded BPF filter", PrintType.Debug);
                }

            }

            // Cleanup 
            if (!s_argumentData.SaveFullPcap && !s_argumentData.NoPacketCapture)
            {
                ConsoleOutput.Print($"Deleting full pcap file {s_fullPcapFile}", PrintType.Debug);
                FileAndFolders.DeleteFile(s_fullPcapFile);
            }


            // Action
            if (s_etwActivityHistory.Count > 0)
            {
                ConsoleOutput.Print($"Creating ETW history file \"{s_etwHistoryFile}\"", PrintType.Debug);
                FileAndFolders.CreateTextFileListOfStrings(s_etwHistoryFile, s_etwActivityHistory);
            }
            else
            {
                ConsoleOutput.Print("Not creating ETW history file since no activity was recorded", PrintType.Warning);
            }

            if (s_argumentData.DumpResultsToJson)
            {
                var options = new JsonSerializerOptions { WriteIndented = true };

                ConsoleOutput.Print($"Creating json results file for process results \"{s_jsonResultsFile}\"", PrintType.Debug);
                string jsonProcessString = JsonSerializer.Serialize(s_collectiveProcessInfo, options);
                File.WriteAllText(s_jsonResultsFile, jsonProcessString);

                ConsoleOutput.Print($"Creating json results file for DNS responses \"{s_jsonDNSFile}\"", PrintType.Debug);
                string jsonDNSString = JsonSerializer.Serialize(s_dnsQueryResults, options);
                File.WriteAllText(s_jsonDNSFile, jsonDNSString);
            }
            else
            {
                ConsoleOutput.Print($"Not creating json results file \"{s_jsonResultsFile}\"", PrintType.Debug);
            }
            var endTime = DateTime.Now;
            string monitorDuration = Generic.GetPresentableDuration(s_startTime, endTime);
            ConsoleOutput.Print($"Finished! Monitor duration: {monitorDuration}. Results are in the folder {s_rootFolderName}", PrintType.InfoTime);
        }

        private static void SetPublicVariablesFromArgument()
        {
            Debug = s_argumentData.Debug;
            TrackChildProcesses = s_argumentData.TrackChildProcesses;
        }

        private static void SetCancelKeyEvent()
        {
            Console.CancelKeyPress += (sender, e) => // For manual cancellation of application
            {
                s_shutDownMonitoring = true;
                e.Cancel = true;
            };
        }

        private static void SetGeneralMonitoringFileNames()
        {
            s_fullPcapFile = @$"{s_rootFolderName}\Full Network Packet Capture.pcap";
            s_etwHistoryFile = @$"{s_rootFolderName}\ETW history.txt";
            s_jsonResultsFile = @$"{s_rootFolderName}\Process details.json";
            s_jsonDNSFile = @$"{s_rootFolderName}\DNS responses.json";
        }

        private static void OutputProcessNetworkDetails(HashSet<DestinationEndpoint> networkHashSet, string outputFile = "", PacketType packetType = PacketType.IPv4TCP)
        {
            if (networkHashSet.Count() > 0)
            {
                List<string> networkDetails = NetworkUtils.ConvertDestinationEndpoints(networkHashSet); // Convert to list from hashset to be able to pass to function
                ConsoleOutput.Print($"Creating file {outputFile} with all {packetType} details", PrintType.Debug);
                FileAndFolders.CreateTextFileListOfStrings(outputFile, networkDetails);
            }
            else
            {
                ConsoleOutput.Print($"Not creating {packetType} file, none found for process", PrintType.Debug);
            }
        }

        private static void OutputProcessDNSDetails(HashSet<DNSQuery> dnsHashSet, string outputFile = "")
        {
            if (dnsHashSet.Count() > 0)
            {
                List<string> dnsDetails = ParseDNSQueries(dnsHashSet); // Convert to list from hashset to be able to pass to function
                ConsoleOutput.Print($"Creating file {outputFile} with all DNS details", PrintType.Debug);
                FileAndFolders.CreateTextFileListOfStrings(outputFile, dnsDetails);
            }
            else
            {
                ConsoleOutput.Print($"Not creating DNS file, none found for process", PrintType.Debug);
            }
        }

        private static void StopETWSessions()
        {
            s_etwKernelListener.StopSession();
            s_etwDnsClientListener.StopSession();
            if (s_etwKernelListener.GetSessionStatus())
            {
                ConsoleOutput.Print($"Kernel ETW session still running...", PrintType.Warning);
            }
            else
            {
                ConsoleOutput.Print($"Successfully stopped Kernel ETW session", PrintType.Debug);
            }

            if (s_etwDnsClientListener.GetSessionStatus())
            {
                ConsoleOutput.Print($"DNS Client ETW session still running...", PrintType.Warning);
            }
            else
            {
                ConsoleOutput.Print($"Successfully stopped ETW DNS Client session", PrintType.Debug);
            }
        }
     
        private static List<string> ParseDNSQueries(HashSet<DNSQuery> dnsQueries)
        {
            HashSet<string> uniqueDomainNames = new HashSet<string>(); 
            foreach (DNSQuery dnsQuery in dnsQueries) // Get the unique domain names only since the DNSQuery objects also contains DNS query type
            {
                uniqueDomainNames.Add(dnsQuery.DomainQueried);
            }

            List<string> enrichedDNSQueries = new List<string>();

            foreach (string domainName in uniqueDomainNames)
            {
                string enrichedQuery = domainName;

                if (s_dnsQueryResults.ContainsKey(domainName))
                {
                    HashSet<string> ipsForDomain = new HashSet<string>();

                    foreach (DNSResponse response in s_dnsQueryResults[domainName])
                    {
                        foreach (string ip in response.QueryResult.IPs)
                        {
                            ipsForDomain.Add(ip);
                        }
                    }

                    enrichedQuery = $"{domainName}   {string.Join(", ", ipsForDomain)}";
                }
                enrichedDNSQueries.Add(enrichedQuery);
            }

            enrichedDNSQueries.Sort();
            return enrichedDNSQueries;
        }

        public static void CatalogETWActivity(string executable = "N/A",
                                             string execType = "N/A", // Main or child process
                                             string execAction = "started",
                                             string execObject = "N/A",
                                             int execPID = 0,
                                             int parentExecPID = 0,
                                             EventType eventType = EventType.Network, 
                                             NetworkPacket networkPacket = new NetworkPacket(),
                                             DNSResponse dnsResponse = new DNSResponse(),
                                             DNSQuery dnsQuery = new DNSQuery())
        {

            string timestamp = Generic.GetTimestampNow();
            string historyMsg = "";

            switch (eventType)
            {
                case EventType.Network: // If its a network related activity
                    {
                        historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) sent a {networkPacket.IPversion} {networkPacket.TransportProtocol} packet to {networkPacket.DestinationIP}:{networkPacket.DestinationPort}";
                        // Create BPF filter objects
                        DestinationEndpoint dstEndpoint = new DestinationEndpoint
                        {
                            IP = networkPacket.DestinationIP,
                            Port = networkPacket.DestinationPort
                        };

                        string bpfBasedIPVersion = "";

                        if (networkPacket.IPversion == "IPv4")
                        {

                            if (networkPacket.DestinationIP == "127.0.0.1")
                            {
                                s_collectiveProcessInfo[execPID].IPv4LocalhostEndpoint.Add(dstEndpoint);
                            }
                            else if (networkPacket.TransportProtocol == "TCP")
                            {
                                s_collectiveProcessInfo[execPID].IPv4TCPEndpoint.Add(dstEndpoint);
                            }
                            else if (networkPacket.TransportProtocol == "UDP")
                            {
                                s_collectiveProcessInfo[execPID].IPv4UDPEndpoint.Add(dstEndpoint);
                            }
                        }
                        else if (networkPacket.IPversion == "IPv6")
                        {
                
                            if (networkPacket.DestinationIP == "::1")
                            {
                                s_collectiveProcessInfo[execPID].IPv6LocalhostEndpoint.Add(dstEndpoint);
                            }
                            else if (networkPacket.TransportProtocol == "TCP")
                            {
                                s_collectiveProcessInfo[execPID].IPv6TCPEndpoint.Add(dstEndpoint);
                            }
                            else if (networkPacket.TransportProtocol == "UDP")
                            {
                                s_collectiveProcessInfo[execPID].IPv6UDPEndpoint.Add(dstEndpoint);
                            }
                        }

                        s_processNetworkTraffic[execPID].Add(networkPacket);
                        break;
                    }
                case EventType.Process: // If its a process related activity
                    {
                        historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) {execAction}";
                        break;
                    }
                case EventType.Childprocess: // If its a process starting another process
                    {
                        historyMsg = $"{timestamp} - {executable}[{parentExecPID}]({execType}) {execAction} {execObject}[{execPID}]";
                        s_collectiveProcessInfo[parentExecPID].ChildProcess.Add(execPID);
                        break;
                    }
                case EventType.DNSQuery: // If its a DNS query made 
                    {
                        s_collectiveProcessInfo[execPID].DNSQueries.Add(dnsQuery);
                        
                        historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) made a DNS lookup for {dnsQuery.DomainQueried}";
                        break;
                    }
                case EventType.DNSResponse: // If its a DNS response 
                    {
                        if (dnsResponse.StatusCode == 87) // DNS status code 87 is not an official status code of the DNS standard.
                        {                                 // Only something made up by Windows.
                                                          // Excluding these should not affect general analysis of the processes
                            return;
                        }

                        /* Normally i would prefer that the domain name queried is only entered 
                         * into this dict when its a query and not in the operation of 
                         * managing the response itself. However, in the use-case of listening to a running 
                         * process via specifing the PID, the query itself may have been missed, but the response is catched.
                         * This is also why it has been added that s_collectiveProcessInfo[execPID].dnsQueries.Add(dnsQuery) 
                         * is made within this part, even though it may seem redundant it's still registered proof that a process 
                         * made a DNS call. Furthermore, s_collectiveProcessInfo is a hashset so there will be no duplicates as well.
                         */

                        if (!s_dnsQueryResults.ContainsKey(dnsResponse.DomainQueried)) // Check if DNS domain exists as key. 
                        {
                            s_dnsQueryResults[dnsResponse.DomainQueried] = new HashSet<DNSResponse>(); // Add the key with an empty defined hashset
                        }

                        s_dnsQueryResults[dnsResponse.DomainQueried].Add(dnsResponse);

                        s_collectiveProcessInfo[execPID].DNSQueries.Add(new DNSQuery {
                            DomainQueried = dnsResponse.DomainQueried,
                            RecordTypeCode = dnsResponse.RecordTypeCode,
                            RecordTypeText = dnsResponse.RecordTypeText
                        }); // See comment above to why this is also here. 

                        historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) received {dnsResponse.RecordTypeText}({dnsResponse.RecordTypeCode}) DNS response {dnsResponse.StatusText}({dnsResponse.StatusCode}) for {dnsResponse.DomainQueried} is {String.Join(", ", dnsResponse.QueryResult.IPs)}";
                        break;

                    }
            }
            ConsoleOutput.Print(historyMsg, PrintType.Debug);
            s_etwActivityHistory.Add(historyMsg);
        }

        private static void TimerShutDownMonitoring(object source, ElapsedEventArgs e)
        {
            s_shutDownMonitoring = true;
            ConsoleOutput.Print($"Timer expired", PrintType.Info);
        }

        private static string GetExecutableFileName(int pid = 0, string executablePath = "")
        {
            string executableFileName = "";
            if (pid != 0) //When a PID was provided rather than the path to an executable
            {
                if (ProcessManager.IsProcessRunning(pid)) {
                    executableFileName = ProcessManager.GetProcessFileName(pid);
                }
                else
                {
                    ConsoleOutput.Print($"Unable to find active process with pid {pid}", PrintType.Fatal);
                    System.Environment.Exit(1);
                }
            }
            else // When the path to an executable was provided
            {
                executableFileName = Path.GetFileName(executablePath);
            }
            return executableFileName;
        }

        public static void InstantiateProcessVariables(int pid, string executable)
        {
            if (!s_collectiveProcessInfo.ContainsKey(pid) && !s_processNetworkTraffic.ContainsKey(pid))
            {
                s_collectiveProcessInfo[pid] = new MonitoredProcess
                {
                    ImageName = executable
                };
                s_processNetworkTraffic[pid] = new HashSet<NetworkPacket>(); // Add the main executable processname
            }
        }

        public static bool TrackExecutablesByName()
        {
            return s_argumentData.ExecutableNamesToMonitorProvided;
        }

       public static bool IsTrackedExecutableName(string executable)
        {
            if (s_argumentData.ExecutableNamesToMonitor.Contains(executable)) 
            {
                return true;
            }
            else
            {
                return false;
            }
        }

       public static bool IsTrackedChildPID(int pid)
        {
            if (s_trackedChildProcessIds.Contains(pid))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        public static void RemoveChildPID(int pid)
        {
            s_trackedChildProcessIds.Remove(pid);
        }
        public static void AddChildPID(int pid)
        {
            s_trackedChildProcessIds.Add(pid);
        }

        public static string GetTrackedPIDImageName(int pid)
        {
            return s_collectiveProcessInfo[pid].ImageName;
        }

        public static int GetDNSActivityCount()
        {
            return s_dnsQueryResults.Count();
        }

        public static int GetETWActivityCount()
        {
            return s_etwActivityHistory.Count();
        }

        public static int GetLivePacketCount()
        {
            return s_livePacketCapture.GetPacketCount();
        }

        public static int GetProcessesCount()
        {
            return s_collectiveProcessInfo.Count();
        }
    }
}