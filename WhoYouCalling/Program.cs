
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
using WhoYouCalling.Utilities.Arguments;


/*
                                                                   ? 
                                                                   | 
  __      ___      __   __         ___      _ _ _              .===:
  \ \    / / |_  __\ \ / /__ _  _ / __|__ _| | (_)_ _  __ _    |[_]|
   \ \/\/ /| ' \/ _ \ V / _ \ || | (__/ _` | | | | ' \/ _` |   |:::|
    \_/\_/ |_||_\___/|_|\___/\_,_|\___\__,_|_|_|_|_||_\__, |   |:::|
                                                      |___/     \___\

By Hannes Michel (@H4NM)
*/

namespace WhoYouCalling
{
    class Program
    {
        private static int s_trackedMainPid = 0;
        private static List<int> s_trackedChildProcessIds = new(); // Used for tracking the corresponding executable name to the spawned processes
        private static List<string> s_etwActivityHistory = new(); // Summary of the network activities made

        private static Dictionary<int, HashSet<ConnectionRecord>> s_processNetworkTraffic = new();
        private static Dictionary<int, MonitoredProcess> s_collectiveProcessInfo = new();
        private static Dictionary<string, HashSet<DNSResponse>> s_dnsQueryResults = new();

        private static bool s_shutDownMonitoring = false;
        private static bool s_timerExpired = false;
        private static string s_mainExecutableFileName = "";
        private static string s_mainExecutableCommandLine = "";

        private static LivePacketCapture s_livePacketCapture = new();
        private static KernelListener s_etwKernelListener = new();
        private static DNSClientListener s_etwDnsClientListener = new();

        private static string s_rootFolderName = "";
        private static string s_fullPcapFile = "";
        private static string s_etwHistoryFile = "";
        private static string s_jsonResultsFile = "";
        private static string s_jsonDNSFile = "";

        private static DateTime s_startTime = DateTime.Now;

        // Arguments
        private static ArgumentData s_argumentData;

        static void Main(string[] args)
        {

            if (!(TraceEventSession.IsElevated() ?? false))
            {
                ConsoleOutput.Print("Please run me as Administrator!", PrintType.Warning);
                return;
            }

            ArgumentManager argsManager = new();
            s_argumentData = argsManager.ParseArguments(args);

            if (s_argumentData.InvalidArgumentValueProvided || !argsManager.IsValidCombinationOfArguments(s_argumentData)) {
                ConsoleOutput.PrintHeader();
                ConsoleOutput.PrintHelp();
                System.Environment.Exit(1);
            }

            SetCancelKeyEvent();
            ConsoleOutput.PrintStartMonitoringText();
            if (Debug())
            {
                ConsoleOutput.PrintArgumentValues(s_argumentData);
            }

            ConsoleOutput.Print("Retrieving executable filename", PrintType.Debug);
            s_mainExecutableFileName = GetExecutableFileNameWithPIDOrPath(s_argumentData.TrackedProcessId, s_argumentData.ExecutablePath);
            s_mainExecutableCommandLine = GetMainExecutableCommandLine(s_mainExecutableFileName, s_argumentData.ExecutableArguments);
            s_rootFolderName = Generic.NormalizePath(Generic.GetRunInstanceFolderName(s_mainExecutableFileName));

            s_argumentData.OutputDirectory = Generic.NormalizePath(s_argumentData.OutputDirectory);

            if (s_argumentData.ProvidedOutputDirectory) // If catalog to save data is specified
            {
                s_rootFolderName = $"{s_argumentData.OutputDirectory}{s_rootFolderName}";
            }

            ConsoleOutput.Print($"Creating folder {s_rootFolderName}", PrintType.Debug);
            FileAndFolders.CreateFolder(s_rootFolderName);
            s_fullPcapFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderEntirePcapFileName}";
            s_etwHistoryFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderETWHistoryFileName}";
            s_jsonResultsFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderJSONProcessDetailsFileName}";
            s_jsonDNSFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderJSONDNSResponseFileName}";

            ConsoleOutput.Print($"Starting monitoring...", PrintType.Info);
            if (!s_argumentData.NoPacketCapture) {
                // Retrieve network interface devices
                var devices = NetworkCaptureManagement.GetNetworkInterfaces(); 
                if (devices.Count == 0)
                {
                    ConsoleOutput.Print($"No network devices were found..", PrintType.Fatal);
                    System.Environment.Exit(1);
                }
                using var device = devices[s_argumentData.NetworkInterfaceChoice];
                s_livePacketCapture.SetCaptureDevice(device);
                Thread fpcThread = new(() => s_livePacketCapture.StartCaptureToFile(s_fullPcapFile));
                ConsoleOutput.Print($"Starting packet capture saved to \"{s_fullPcapFile}\"", PrintType.Debug);
                fpcThread.Start();
            }

            // Create and start threads for ETW. Had to make two separate functions for a dedicated thread for interoperability
            Thread etwKernelListenerThread = new(() => s_etwKernelListener.Listen());
            Thread etwDnsClientListenerThread = new(() => s_etwDnsClientListener.Listen());
            
            ConsoleOutput.Print("Starting ETW sessions", PrintType.Debug);
            etwKernelListenerThread.Start();
            etwDnsClientListenerThread.Start();

            if (s_argumentData.ExecutablePathProvided) // If an executable was provided and not a pid
            {
                Thread.Sleep(Constants.Timeouts.ETWSubscriptionTimingTime); //Sleep is required to ensure ETW Subscription is timed correctly to capture the execution
                try
                {
                    string executionContext = "";
                    if (s_argumentData.RunExecutableWithHighPrivilege)
                    {
                        executionContext = "elevated";
                        s_trackedMainPid = ProcessManager.StartProcessAndGetId(executablePath: s_argumentData.ExecutablePath, 
                                                                               arguments: s_argumentData.ExecutableArguments,
                                                                               runPrivileged: true);
                    }
                    else
                    {
                        executionContext = "unelevated";
                        if (s_argumentData.UserNameProvided && s_argumentData.UserPasswordProvided)
                        {
                            s_trackedMainPid = ProcessManager.StartProcessAndGetId(executablePath: s_argumentData.ExecutablePath,
                                                       arguments: s_argumentData.ExecutableArguments,
                                                       username: s_argumentData.UserName,
                                                       password: s_argumentData.UserPassword,
                                                       runPrivileged: false);
                        }
                        else if (Win32.WinAPI.HasShellWindow())
                        {
                            s_trackedMainPid = ProcessManager.StarProcessAndGetPIDWithShellWindow(s_argumentData.ExecutablePath, s_argumentData.ExecutableArguments);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Weird state when starting process. Unprivileged execution, no user nor password provided, not interactive session. Aborting", PrintType.Fatal);
                            System.Environment.Exit(1);
                        }
                    }

                    ConsoleOutput.Print($"Executing \"{s_argumentData.ExecutablePath}\" with args \"{s_argumentData.ExecutableArguments}\" in {executionContext} context", PrintType.Debug);
                    ConsoleOutput.Print($"Executing \"{s_argumentData.ExecutablePath}\"", PrintType.Info);

                    CatalogETWActivity(eventType: EventType.Process, executable: s_mainExecutableFileName, execAction: "started", execPID: s_trackedMainPid);
                }
                catch (Exception ex)
                {
                    ConsoleOutput.Print($"An error occurred while starting the process: {ex.Message}", PrintType.Fatal);
                    System.Environment.Exit(1);
                }
            }
            else // PID to an existing process was provided
            {
                s_trackedMainPid = s_argumentData.TrackedProcessId;
                ConsoleOutput.Print($"Listening to PID {s_trackedMainPid}({s_mainExecutableFileName})", PrintType.Info);
                CatalogETWActivity(eventType: EventType.Process, executable: s_mainExecutableFileName, execAction: "being listened to", execPID: s_trackedMainPid);
            }

            s_etwDnsClientListener.SetPIDAndImageToTrack(s_trackedMainPid, s_mainExecutableFileName);
            s_etwKernelListener.SetPIDAndImageToTrack(s_trackedMainPid, s_mainExecutableFileName);
            InstantiateProcessVariables(pid: s_trackedMainPid, executable: s_mainExecutableFileName, commandLine: s_mainExecutableCommandLine);

            if (s_argumentData.ProcessRunTimerWasProvided)
            {
                double processRunTimerInMilliseconds = Generic.ConvertToMilliseconds(s_argumentData.ProcessRunTimer);
                System.Timers.Timer timer = new(processRunTimerInMilliseconds);
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
                    Console.WriteLine(""); // Needed to adjust a linebreak since the runningStats print above uses Console.Write
                    if (s_timerExpired)
                    {
                        ConsoleOutput.Print($"Timer expired", PrintType.Info);
                    }
                    ConsoleOutput.Print($"Stopping monitoring", PrintType.Info);
                    ShutdownMonitoring();
                    break;
                }
            }
        }

        private static void ShutdownMonitoring()
        {
            if (s_argumentData.KillProcesses) // If spawned processes are to be killed
            {
                ProcessManager.KillProcess(s_trackedMainPid); // Kill main process
                foreach (int childPID in s_trackedChildProcessIds) // Kill child processes
                {
                    ConsoleOutput.Print($"Killing child process with PID {childPID}", PrintType.Debug);
                    ProcessManager.KillProcess(childPID);
                }
            }
            ConsoleOutput.Print($"Stopping ETW sessions", PrintType.Debug);
            StopETWSession(s_etwKernelListener);
            StopETWSession(s_etwDnsClientListener);

            Dictionary<int, string> computedBPFFilterByPID = new();
            Dictionary<int, string> computedDFLFilterByPID = new();


            ConsoleOutput.Print($"Producing filters", PrintType.Debug);
            computedBPFFilterByPID = GetProcessNetworkFilter(s_processNetworkTraffic, s_argumentData.StrictCommunicationEnabled, FilterType.BPF);
            computedDFLFilterByPID = GetProcessNetworkFilter(s_processNetworkTraffic, s_argumentData.StrictCommunicationEnabled, FilterType.DFL);

            if (s_argumentData.OutputBPFFilter) // If BPF Filter is to be written to text file.
            {
                if (computedBPFFilterByPID.TryGetValue(Constants.Miscellaneous.CombinedFilterProcessID, out string? text))
                {
                    string processBPFFilterTextFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderBPFFilterFileName}";
                    FileAndFolders.CreateTextFileString(processBPFFilterTextFile, text); // Create textfile containing used BPF filter
                }
            }

            if (!s_argumentData.NoPacketCapture)
            {
                ConsoleOutput.Print($"Stopping packet capture saved to \"{s_fullPcapFile}\"", PrintType.Debug);
                s_livePacketCapture.StopCapture();

                if (computedBPFFilterByPID.TryGetValue(Constants.Miscellaneous.CombinedFilterProcessID, out string? bpfFilter)) // 0 represents the combined BPF filter for all applications
                {
                    string filteredPcapFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderAllProcessesFilteredPcapFileName}";

                    ConsoleOutput.Print($"Filtering saved pcap \"{s_fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter \"{bpfFilter}\"", PrintType.Debug);
                    FilePacketCapture filePacketCapture = new();
                    filePacketCapture.FilterCaptureFile(bpfFilter, s_fullPcapFile, filteredPcapFile);
                    
                }
            }

            if (s_argumentData.OutputWiresharkFilter && computedDFLFilterByPID.TryGetValue(Constants.Miscellaneous.CombinedFilterProcessID, out string? combinedProcessWiresharkFilter))
            {
                string processDFLFilterTextFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderDFLFilterFileName}";
                FileAndFolders.CreateTextFileString(processDFLFilterTextFile, combinedProcessWiresharkFilter); // Create textfile containing used BPF filter
            }

            foreach (var kvp in s_collectiveProcessInfo)
            {
                int pid = kvp.Key;
                MonitoredProcess monitoredProcess = kvp.Value;

                if (ProcessHasNoRecordedNetworkActivity(monitoredProcess)) // Check if the processes has any network activities recorded. If not, go to next process
                {
                    ConsoleOutput.Print($"Not outputting results for PID {pid}. No network activities recorded", PrintType.Debug);
                    continue;
                }

                string executable = monitoredProcess.ImageName;
                string executabelNameAndPID = $"{executable}-{pid}";
                string processFolderInRootFolder = @$"{s_rootFolderName}\{executabelNameAndPID}";

                ConsoleOutput.Print($"Creating folder {processFolderInRootFolder}", PrintType.Debug);
                FileAndFolders.CreateFolder(processFolderInRootFolder);

                // Network results text files
                OutputProcessDNSDetails(monitoredProcess.DNSQueries, 
                                        outputFile: @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderDNSQueriesFileName}");

                OutputDNSWiresharkFilters(strictComsEnabled: s_argumentData.StrictCommunicationEnabled,
                                          dnsQueries: monitoredProcess.DNSQueries,
                                          processFolder: processFolderInRootFolder);

                OutputProcessNetworkDetails(monitoredProcess.IPv4TCPEndpoint,
                                            outputFile: @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderIPv4TCPEndpoints}",
                                            packetType: PacketType.IPv4TCP);

                OutputProcessNetworkDetails(monitoredProcess.IPv6TCPEndpoint,
                                            outputFile: @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderIPv6TCPEndpoints}",
                                            packetType: PacketType.IPv6TCP);

                OutputProcessNetworkDetails(monitoredProcess.IPv4UDPEndpoint,
                                            outputFile: @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderIPv4UDPEndpoints}",
                                            packetType: PacketType.IPv4UDP);

                OutputProcessNetworkDetails(monitoredProcess.IPv6UDPEndpoint,
                                            outputFile: @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderIPv6UDPEndpoints}",
                                            packetType: PacketType.IPv6UDP);

                OutputProcessNetworkDetails(monitoredProcess.IPv4LocalhostEndpoint,
                                            outputFile: @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderIPv4LocalhostEndpoints}",
                                            packetType: PacketType.IPv4Localhost);

                OutputProcessNetworkDetails(monitoredProcess.IPv6LocalhostEndpoint,
                                            outputFile: @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderIPv6LocalhostEndpoints}",
                                            packetType: PacketType.IPv6Localhost);


                // Wireshark DFL Filter
                if (s_argumentData.OutputWiresharkFilter && computedDFLFilterByPID.TryGetValue(pid, out string? processWiresharkFilter))
                {
                    string processDFLFilterTextFile = @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderDFLFilterFileName}";
                    FileAndFolders.CreateTextFileString(processDFLFilterTextFile, processWiresharkFilter);
                }

                // BPF Filter
                if (s_argumentData.OutputBPFFilter) 
                {
                    if (computedBPFFilterByPID.TryGetValue(pid, out string? processBPFFilterForOutput)) 
                    {
                        string processBPFFilterTextFile = @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderBPFFilterFileName}";
                        FileAndFolders.CreateTextFileString(processBPFFilterTextFile, processBPFFilterForOutput); 
                    }
                }

                // Packet Capture 
                if (!s_argumentData.NoPacketCapture && computedBPFFilterByPID.TryGetValue(pid, out string? processBPFFilterForFiltering))
                {
                    string filteredPcapFile = @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderPcapFileName}";

                    ConsoleOutput.Print($"Filtering saved pcap \"{s_fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter.", PrintType.Debug);

                    var filteringStartTime = DateTime.Now;
                    FilePacketCapture filePacketCapture = new();
                    filePacketCapture.FilterCaptureFile(processBPFFilterForFiltering, s_fullPcapFile, filteredPcapFile);
                    string filterDuration = Generic.GetPresentableDuration(filteringStartTime, DateTime.Now);

                    ConsoleOutput.Print($"Filtered pcap for {executabelNameAndPID} in {filterDuration}", PrintType.Info);
                }
                else
                {
                    ConsoleOutput.Print($"Skipping creating dedicated PCAP file for {executable}. No recorded BPF filter", PrintType.Debug);
                }

            }

            if (!s_argumentData.SaveFullPcap && !s_argumentData.NoPacketCapture)
            {
                ConsoleOutput.Print($"Deleting full pcap file {s_fullPcapFile}", PrintType.Debug);
                FileAndFolders.DeleteFile(s_fullPcapFile);
            }

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

        private static bool ProcessHasNoRecordedNetworkActivity(MonitoredProcess monitoredProcess)
        {
            if (monitoredProcess.DNSQueries.Count() == 0 &&
            monitoredProcess.IPv4LocalhostEndpoint.Count() == 0 &&
            monitoredProcess.IPv4TCPEndpoint.Count() == 0 &&
            monitoredProcess.IPv4UDPEndpoint.Count() == 0 &&
            monitoredProcess.IPv6LocalhostEndpoint.Count() == 0 &&
            monitoredProcess.IPv6TCPEndpoint.Count() == 0 &&
            monitoredProcess.IPv6UDPEndpoint.Count() == 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private static void SetCancelKeyEvent()
        {
            Console.CancelKeyPress += (sender, e) => // For manual cancellation of application
            {
                s_shutDownMonitoring = true;
                e.Cancel = true;
            };
        }

        private static void OutputProcessNetworkDetails(HashSet<NetworkEndpoint> networkHashSet, string outputFile = "", PacketType packetType = PacketType.IPv4TCP)
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

        private static void StopETWSession(Listener etwListener)
        {
            etwListener.StopSession();
            if (etwListener.GetSessionStatus())
            {
                ConsoleOutput.Print($"{etwListener.SourceName} ETW session still running...", PrintType.Warning);
            }
            else
            {
                ConsoleOutput.Print($"Successfully {etwListener.SourceName} ETW session", PrintType.Debug);
            }
        }


        private static void OutputDNSWiresharkFilters(bool strictComsEnabled, HashSet<DNSQuery> dnsQueries, string processFolder = "")
        {
            if (dnsQueries.Count() > 0)
            {
                string processDNSFolder = $"{processFolder}/{Constants.FileNames.ProcessFolderDNSWiresharkFolderName}";
                FileAndFolders.CreateFolder(processDNSFolder);

                HashSet<string> uniqueDomainNames = GetUniqueDomainNameFromDNSQueryObject(dnsQueries: dnsQueries);
                List<string> fullFilterListOfIPs = new();

                foreach (string domainName in uniqueDomainNames)
                {
                    if (s_dnsQueryResults.TryGetValue(domainName, out HashSet<DNSResponse>? dnsResponses))
                    {
                        HashSet<ConnectionRecord> domainIPAdresses = NetworkUtils.GetNetworkAdressesFromDNSResponse(dnsResponses);
                        string domainWiresharkFilterFileName = $"{processDNSFolder}/{domainName}.txt";

                        string domainFilter = Network.NetworkFilter.GetCombinedNetworkFilter(strictComsEnabled: strictComsEnabled,
                                                                                           connectionRecords: domainIPAdresses,
                                                                                           filterPorts: false,
                                                                                           onlyDestIP: true,
                                                                                           filter: FilterType.DFL);
                        FileAndFolders.CreateTextFileString(filePath: domainWiresharkFilterFileName, text: domainFilter);
                    }
                }
            }
        }
        private static HashSet<string> GetUniqueDomainNameFromDNSQueryObject(HashSet<DNSQuery> dnsQueries)
        {
            /*
             * Get the unique domain names only since the DNSQuery objects also contains DNS query type
             */

            HashSet<string> uniqueDomainNames = new();
            foreach (DNSQuery dnsQuery in dnsQueries) 
            {
                uniqueDomainNames.Add(dnsQuery.DomainQueried);
            }
            return uniqueDomainNames;
        }

        private static List<string> ParseDNSQueries(HashSet<DNSQuery> dnsQueries)
        {
            HashSet<string> uniqueDomainNames = GetUniqueDomainNameFromDNSQueryObject(dnsQueries: dnsQueries);
            List<string> presentableDNSQueryFormat = new();

            foreach (string domainName in uniqueDomainNames)
            {
                string presentableQuery = domainName;

                if (s_dnsQueryResults.TryGetValue(domainName, out HashSet<DNSResponse>? dnsResponses))
                {
                    HashSet<string> ipsForDomain = new();

                    foreach (DNSResponse response in dnsResponses)
                    {
                        foreach (string ip in response.QueryResult.IPs)
                        {
                            string actualIP = NetworkUtils.GetActualIP(ip);
                            ipsForDomain.Add(actualIP);
                        }
                    }
                    presentableQuery = $"{domainName}   {string.Join(", ", ipsForDomain)}";
                }
                presentableDNSQueryFormat.Add(presentableQuery);
            }

            presentableDNSQueryFormat.Sort();
            return presentableDNSQueryFormat;
        }
        private static Dictionary<int, string> GetProcessNetworkFilter(Dictionary<int, HashSet<ConnectionRecord>> processNetworkPackets, bool strictComsEnabled, FilterType filter, bool filterPorts = true)
        {
            Dictionary<int, string> filterPerExecutable = new();

            foreach (KeyValuePair<int, HashSet<ConnectionRecord>> entry in processNetworkPackets) //For each Process 
            {
                int pid = entry.Key;
                if (entry.Value.Count == 0) // Check if the executable has any recorded network activity
                {
                    ConsoleOutput.Print($"Not calculating {filter} filter for PID {pid}. No recored network activity", PrintType.Debug);
                    continue;
                }

                string executableFilter = NetworkFilter.GetCombinedNetworkFilter(connectionRecords: entry.Value,
                                                                                 filter: filter,
                                                                                 strictComsEnabled: strictComsEnabled);
                filterPerExecutable[entry.Key] = executableFilter; // Add filter for executable
            }


            if (filterPerExecutable.Count > 1)
            {
                List<string> tempFilterList = new();
                foreach (KeyValuePair<int, string> processFilter in filterPerExecutable)
                {
                    tempFilterList.Add($"({processFilter.Value})");
                }
                filterPerExecutable[Constants.Miscellaneous.CombinedFilterProcessID] = NetworkFilter.JoinFilterList(filter, tempFilterList);
            }
            return filterPerExecutable;
        }

        public static void CatalogETWActivity(string executable = "N/A",
                                             string execAction = "started",
                                             string execObject = "N/A",
                                             string execObjectCommandLine = "",
                                             int execPID = 0,
                                             int parentExecPID = 0,
                                             EventType eventType = EventType.Network,
                                             ConnectionRecord connectionRecord = new(),
                                             DNSResponse dnsResponse = new(),
                                             DNSQuery dnsQuery = new())
        {

            string timestamp = Generic.GetTimestampNow();
            string historyMsg = "";

            switch (eventType)
            {
                case EventType.Network:
                    {
                        historyMsg = $"{timestamp} - {executable}[{execPID}] sent a {connectionRecord.IPversion} {connectionRecord.TransportProtocol} packet to {connectionRecord.DestinationIP}:{connectionRecord.DestinationPort}";
 
                        NetworkEndpoint dstEndpoint = new NetworkEndpoint
                        {
                            IP = connectionRecord.DestinationIP,
                            Port = connectionRecord.DestinationPort
                        };

                        if (connectionRecord.IPversion == Network.IPVersion.IPv4)
                        {

                            if (connectionRecord.DestinationIP == "127.0.0.1")
                            {
                                s_collectiveProcessInfo[execPID].IPv4LocalhostEndpoint.Add(dstEndpoint);
                            }
                            else if (connectionRecord.TransportProtocol == Network.TransportProtocol.TCP)
                            {
                                s_collectiveProcessInfo[execPID].IPv4TCPEndpoint.Add(dstEndpoint);
                            }
                            else if (connectionRecord.TransportProtocol == Network.TransportProtocol.UDP)
                            {
                                s_collectiveProcessInfo[execPID].IPv4UDPEndpoint.Add(dstEndpoint);
                            }
                        }
                        else if (connectionRecord.IPversion == Network.IPVersion.IPv6)
                        {
                
                            if (connectionRecord.DestinationIP == "::1")
                            {
                                s_collectiveProcessInfo[execPID].IPv6LocalhostEndpoint.Add(dstEndpoint);
                            }
                            else if (connectionRecord.TransportProtocol == Network.TransportProtocol.TCP)
                            {
                                s_collectiveProcessInfo[execPID].IPv6TCPEndpoint.Add(dstEndpoint);
                            }
                            else if (connectionRecord.TransportProtocol == Network.TransportProtocol.UDP)
                            {
                                s_collectiveProcessInfo[execPID].IPv6UDPEndpoint.Add(dstEndpoint);
                            }
                        }

                        s_processNetworkTraffic[execPID].Add(connectionRecord);
                        break;
                    }
                case EventType.Process:
                    {
                        historyMsg = $"{timestamp} - {executable}[{execPID}] {execAction}";
                        break;
                    }
                case EventType.Childprocess: 
                    {
                        historyMsg = $"{timestamp} - {executable}[{parentExecPID}] {execAction} {execObject}[{execPID}] with commandline: {execObjectCommandLine}";
                        s_collectiveProcessInfo[parentExecPID].ChildProcess.Add(execPID);
                        break;
                    }
                case EventType.DNSQuery:
                    {
                        s_collectiveProcessInfo[execPID].DNSQueries.Add(dnsQuery);
                        
                        historyMsg = $"{timestamp} - {executable}[{execPID}] made a DNS lookup for {dnsQuery.DomainQueried}";
                        break;
                    }
                case EventType.DNSResponse:  
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

                        if (dnsResponse.QueryResult.IPs.Any())
                        {
                            historyMsg = $"{timestamp} - {executable}[{execPID}] received {dnsResponse.RecordTypeText}({dnsResponse.RecordTypeCode}) DNS response {dnsResponse.StatusText}({dnsResponse.StatusCode}) for {dnsResponse.DomainQueried} with IPs: {String.Join(", ", dnsResponse.QueryResult.IPs)}";
                        }
                        else
                        {
                            historyMsg = $"{timestamp} - {executable}[{execPID}] received {dnsResponse.RecordTypeText}({dnsResponse.RecordTypeCode}) DNS response {dnsResponse.StatusText}({dnsResponse.StatusCode}) for {dnsResponse.DomainQueried}";
                        }
                        break;

                    }
            }
            ConsoleOutput.Print(historyMsg, PrintType.Debug);
            s_etwActivityHistory.Add(historyMsg);
        }

        private static void TimerShutDownMonitoring(object source, ElapsedEventArgs e)
        {
            s_timerExpired = true;
            s_shutDownMonitoring = true;
        }

        private static string GetExecutableFileNameWithPIDOrPath(int pid = 0, string executablePath = "")
        {
            string executableFileName = "";
            if (pid != 0) 
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
            else 
            {
                executableFileName = Path.GetFileName(executablePath);
            }
            return executableFileName;
        }

        private static string GetMainExecutableCommandLine(string executable, string arguments)
        {
            string commandLine;
            if (string.IsNullOrEmpty(arguments))
            {
                commandLine = "";
            }
            else
            {
                commandLine = $"{executable} {arguments}";
            }
            return commandLine;
        }

        public static void InstantiateProcessVariables(int pid, string executable, string commandLine)
        {
            if (!s_collectiveProcessInfo.ContainsKey(pid) && !s_processNetworkTraffic.ContainsKey(pid))
            {
                s_collectiveProcessInfo[pid] = new MonitoredProcess
                {
                    ImageName = executable,
                    CommandLine = commandLine
                };
                s_processNetworkTraffic[pid] = new HashSet<ConnectionRecord>(); // Add the main executable processname
            }
        }

        public static bool TrackExecutablesByName()
        {
            return s_argumentData.ExecutableNamesToMonitorProvided;
        }

       public static bool IsTrackedExecutableName(int pid)
        {
            string processFileName = ProcessManager.GetProcessFileName(pid);

            if (s_argumentData.ExecutableNamesToMonitor.Contains(processFileName))
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
             public static bool Debug()
        {
            return s_argumentData.Debug;
        }
        public static bool TrackChildProcesses()
        {
            return s_argumentData.TrackChildProcesses;
        }
    }
}