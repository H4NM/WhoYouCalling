﻿
using System.Timers;
using System.Net;
using System.Globalization;
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

        // Arguments
        private static int s_trackedProcessId = 0;
        private static double s_processRunTimer = 0;
        private static int s_networkInterfaceChoice = 0;
        private static string s_executablePath = "";
        private static string s_executableArguments = "";
        private static string s_outputDirectory = "";
        private static bool s_killProcesses = false;
        private static bool s_saveFullPcap = false;
        private static bool s_noPacketCapture = false;
        private static bool s_dumpResultsToJson = false;
        private static bool s_strictCommunicationEnabled = false;
        private static bool s_outputBPFFilter = false;
        private static bool s_outputWiresharkFilter = false;
        public static bool Debug = false;
        public static bool TrackChildProcesses = true;
        

        static void Main(string[] args)
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                ConsoleOutput.Print("Please run me as Administrator!", "warning");
                return;
            }

            if (!ValidateProvidedArguments(args)) {
                ConsoleOutput.PrintHeader();
                ConsoleOutput.PrintHelp();
                System.Environment.Exit(1);

            }
            var startTime = DateTime.Now;
            int combinedFilterProcId = 0;

            Console.CancelKeyPress += (sender, e) => // For manual cancellation of application
            {
                s_shutDownMonitoring = true;
                e.Cancel = true;
            };

            Console.Clear();
            ConsoleOutput.PrintHeader();
            ConsoleOutput.Print($"Starting.. Press CTRL+C to cancel process monitoring.", "infoTime");

            LivePacketCapture livePacketCapture = new LivePacketCapture();
            KernelListener etwKernelListener = new KernelListener();
            DNSClientListener etwDnsClientListener = new DNSClientListener();

            ConsoleOutput.Print("Retrieving executable filename", "debug");
            s_mainExecutableFileName = GetExecutableFileName(s_trackedProcessId, s_executablePath);


            string rootFolderName = Generic.GetRunInstanceFolderName(s_mainExecutableFileName);
            s_outputDirectory = Generic.NormalizePath(s_outputDirectory);

            if (!string.IsNullOrEmpty(s_outputDirectory)) // If catalog to save data is specified
            {
                rootFolderName = $"{s_outputDirectory}{rootFolderName}";
            }
            ConsoleOutput.Print($"Creating folder {rootFolderName}", "debug");
            FileAndFolders.CreateFolder(rootFolderName);

            string fullPcapFile = @$"{rootFolderName}\Full Network Packet Capture.pcap";
            string etwHistoryFile = @$"{rootFolderName}\ETW history.txt";
            string jsonResultsFile = @$"{rootFolderName}\Process details.json";
            string jsonDNSFile = @$"{rootFolderName}\DNS responses.json";

            // Retrieve network interface devices
            var devices = NetworkCaptureManagement.GetNetworkInterfaces(); // Returns a LibPcapLiveDeviceList
            if (devices.Count == 0)
            {
                ConsoleOutput.Print($"No network devices were found..", "fatal");
                System.Environment.Exit(1);
            }
            using var device = devices[s_networkInterfaceChoice];
            livePacketCapture.SetCaptureDevice(device);

            ConsoleOutput.Print($"Starting monitoring capabilities...", "info");
            // Create and start thread for capturing packets if enabled
            if (!s_noPacketCapture) { 
                Thread fpcThread = new Thread(() => livePacketCapture.StartCaptureToFile(fullPcapFile));
                ConsoleOutput.Print($"Starting packet capture saved to \"{fullPcapFile}\"", "debug");
                fpcThread.Start();
            }

            // Create and start threads for ETW. Had to make two separate functions for a dedicated thread for interoperability
            Thread etwKernelListenerThread = new Thread(() => etwKernelListener.Listen());
            Thread etwDNSClientListenerThread = new Thread(() => etwDnsClientListener.Listen());
            
            ConsoleOutput.Print("Starting ETW sessions", "debug");
            etwKernelListenerThread.Start();
            etwDNSClientListenerThread.Start();

            if (!string.IsNullOrEmpty(s_executablePath)) // An executable path has been provided and will be executed
            {
                Thread.Sleep(3000); //Sleep is required to ensure ETW Subscription is timed correctly to capture the execution
                try
                {
                    ConsoleOutput.Print($"Executing \"{s_executablePath}\" with args \"{s_executableArguments}\"", "debug");
                    ConsoleOutput.Print($"Executing \"{s_executablePath}\"", "info");
                    s_trackedProcessId = ProcessManager.StartProcessAndGetId(s_executablePath, s_executableArguments);
                    CatalogETWActivity(eventType: "process", executable: s_mainExecutableFileName, execType: "Main", execAction: "started", execPID: s_trackedProcessId);
                }
                catch (Exception ex)
                {
                    ConsoleOutput.Print($"An error occurred while starting the process: {ex.Message}", "fatal");
                    System.Environment.Exit(1);
                }
            }
            else // PID to an existing process is running
            {
                ConsoleOutput.Print($"Listening to PID \"{s_trackedProcessId}\"", "info");
                CatalogETWActivity(eventType: "process", executable: s_mainExecutableFileName, execType: "Main", execAction: "being listened to", execPID: s_trackedProcessId);
            }

            etwDnsClientListener.SetPIDAndImageToTrack(s_trackedProcessId, s_mainExecutableFileName);
            etwKernelListener.SetPIDAndImageToTrack(s_trackedProcessId, s_mainExecutableFileName);
            InstantiateProcessVariables(pid: s_trackedProcessId, executable: s_mainExecutableFileName);

            if (s_processRunTimer != 0)
            {
                double s_processRunTimerInMilliseconds = Generic.ConvertToMilliseconds(s_processRunTimer);
                System.Timers.Timer timer = new System.Timers.Timer(s_processRunTimerInMilliseconds);
                timer.Elapsed += TimerShutDownMonitoring;
                timer.AutoReset = false;
                ConsoleOutput.Print($"Starting timer set to {s_processRunTimer} seconds", "debug");
                timer.Start();
            }

            while (true) // Continue monitoring 
            {
                int capturedPacketCount = livePacketCapture.GetPacketCount();
                ConsoleOutput.Print($"Processes: {s_collectiveProcessInfo.Count()}. ETW Events: {s_etwActivityHistory.Count()}. Network Packets: {capturedPacketCount}", "runningStats");
                if (s_shutDownMonitoring) // If shutdown has been signaled
                {
                    Console.WriteLine(""); // Needed to adjust a linebreak since the runningStats print above uses Console.Write()
                    ConsoleOutput.Print($"Stopping monitoring", "info");
                    if (s_killProcesses) // If a timer was specified and that processes should be killed
                    {
                        ProcessManager.KillProcess(s_trackedProcessId);
                        foreach (int childPID in s_trackedChildProcessIds)
                        {
                            ConsoleOutput.Print($"Killing child process with PID {childPID}", "debug");
                            ProcessManager.KillProcess(childPID);
                        }
                    }
                    ConsoleOutput.Print($"Stopping ETW sessions", "debug");
                    etwKernelListener.StopSession();
                    etwDnsClientListener.StopSession();
                    if (etwKernelListener.GetSessionStatus())
                    {
                        ConsoleOutput.Print($"Kernel ETW session still running...", "warning");
                    }
                    else
                    {
                        ConsoleOutput.Print($"Successfully stopped Kernel ETW session", "debug");
                    }

                    if (etwDnsClientListener.GetSessionStatus())
                    {
                        ConsoleOutput.Print($"DNS Client ETW session still running...", "warning");
                    }
                    else
                    {
                        ConsoleOutput.Print($"Successfully stopped ETW DNS Client session", "debug");
                    }

                    Dictionary<int, string> computedBPFFilterByPID = new Dictionary<int, string>();
                    Dictionary<int, string> computedDFLFilterByPID = new Dictionary<int, string>();

                    if (!s_noPacketCapture)
                    {
                        ConsoleOutput.Print($"Stopping packet capture saved to \"{fullPcapFile}\"", "debug");
                        livePacketCapture.StopCapture();

                        ConsoleOutput.Print($"Producing filters", "debug");
                        computedBPFFilterByPID = NetworkFilter.GetNetworkFilter(s_processNetworkTraffic, s_strictCommunicationEnabled, NetworkFilterType.BPF); //BPFFilter.GetBPFFilter(s_processNetworkTraffic, s_strictCommunicationEnabled);
                        computedDFLFilterByPID = NetworkFilter.GetNetworkFilter(s_processNetworkTraffic, s_strictCommunicationEnabled, NetworkFilterType.DFL); //WiresharkFilter.GetDFLFilter(s_processNetworkTraffic, s_strictCommunicationEnabled);
                        
                        if (computedBPFFilterByPID.ContainsKey(combinedFilterProcId)) // 0 represents the combined BPF filter for all applications
                        {
                            string filteredPcapFile = @$"{rootFolderName}\All {computedBPFFilterByPID.Count} processes filter.pcap";
                            string processBPFFilterTextFile = @$"{rootFolderName}\All {computedBPFFilterByPID.Count} processes filter.txt";
                            ConsoleOutput.Print($"Filtering saved pcap \"{fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter \"{computedBPFFilterByPID[combinedFilterProcId]}\"", "debug");

                            FilePacketCapture filePacketCapture = new FilePacketCapture();
                            filePacketCapture.FilterCaptureFile(computedBPFFilterByPID[combinedFilterProcId], fullPcapFile, filteredPcapFile);
                            if (s_outputBPFFilter) // If BPF Filter is to be written to text file.
                            {
                                FileAndFolders.CreateTextFileString(processBPFFilterTextFile, computedBPFFilterByPID[combinedFilterProcId]); // Create textfile containing used BPF filter
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
                            ConsoleOutput.Print($"Not creating folder with results for PID {pid}. No activities found", "debug");
                            continue;
                        }

                        string executable = monitoredProcess.ImageName;
                        string executabelNameAndPID = $"{executable}-{pid}";
                        string processFolderInRootFolder = @$"{rootFolderName}\{executabelNameAndPID}";

                        ConsoleOutput.Print($"Creating folder {processFolderInRootFolder}", "debug");
                        FileAndFolders.CreateFolder(processFolderInRootFolder);

                        // DNS
                        if (monitoredProcess.DNSQueries.Count() > 0)
                        {
                            string dnsQueriesFile = @$"{processFolderInRootFolder}\DNS queries.txt";

                            List<string> dnsQueries = Generic.ConvertHashSetToSortedList(monitoredProcess.DNSQueries); // Convert to list from hashset to be able to pass to function
                            List<string> enrichedDNSQueries = EnrichDNSQueries(dnsQueries);
                            ConsoleOutput.Print($"Creating file {dnsQueriesFile} with all DNS queries", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(dnsQueriesFile, enrichedDNSQueries);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating DNS queries file, none found for {pid}", "debug");
                        }

                        // TCP IPv4
                        if (monitoredProcess.IPv4TCPEndpoint.Count > 0) 
                        {
                            string tcpIPv4File = @$"{processFolderInRootFolder}\IPv4 TCP Endpoints.txt";
                            List<string> tcpIPv4Endpoints = Generic.ConvertHashSetToSortedList(monitoredProcess.IPv4TCPEndpoint); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {tcpIPv4File} with TCP IPv4 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(tcpIPv4File, tcpIPv4Endpoints);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating TCP IPv4 communication file, none found for {pid}", "debug");
                        }

                        // TCP IPv6
                        if (monitoredProcess.IPv6TCPEndpoint.Count > 0)
                        {
                            string tcpIPv6File = @$"{processFolderInRootFolder}\IPv6 TCP Endpoints.txt";
                            List<string> tcpIPv6Endpoints = Generic.ConvertHashSetToSortedList(monitoredProcess.IPv6TCPEndpoint); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {tcpIPv6File} with TCP IPv6 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(tcpIPv6File, tcpIPv6Endpoints);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating TCP IPv6 communication file, none found for {pid}", "debug");
                        }

                        // UDP IPv4
                        if (monitoredProcess.IPv4UDPEndpoint.Count > 0)
                        {
                            string udpIPv4File = @$"{processFolderInRootFolder}\IPv4 UDP Endpoints.txt";
                            List<string> udpIPv4Endpoints = Generic.ConvertHashSetToSortedList(monitoredProcess.IPv4UDPEndpoint); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {udpIPv4File} with UDP IPv4 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(udpIPv4File, udpIPv4Endpoints);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating UDP IPv4 communication file, none found for {pid}", "debug");
                        }
                        // UDP IPv6
                        if (monitoredProcess.IPv6UDPEndpoint.Count > 0)
                        {
                            string udpIPv6File = @$"{processFolderInRootFolder}\IPv6 UDP Endpoints.txt";
                            List<string> udpIPv6Endpoints = Generic.ConvertHashSetToSortedList(monitoredProcess.IPv6UDPEndpoint); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {udpIPv6File} with UDP IPv6 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(udpIPv6File, udpIPv6Endpoints);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating UDP IPv6 communication file, none found for {pid}", "debug");
                        }
                        // Localhost IPv4 - Takes both TCP UDP
                        if (monitoredProcess.IPv4LocalhostEndpoint.Count > 0)
                        {
                            string localhostIPv4File = @$"{processFolderInRootFolder}\Localhost Endpoints.txt";
                            List<string> localhostIPv4Endpoints = Generic.ConvertHashSetToSortedList(monitoredProcess.IPv4LocalhostEndpoint); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {localhostIPv4File} with localhost IPv4 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(localhostIPv4File, localhostIPv4Endpoints);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating localhost IPv4 communication file, none found for {pid}", "debug");
                        }
                        // Localhost IPv6 - Takes both TCP UDP
                        if (monitoredProcess.IPv6LocalhostEndpoint.Count > 0)
                        {
                            string localhostIPv6File = @$"{processFolderInRootFolder}\Localhost Endpoints IPv6.txt";
                            List<string> localhostIPv6Endpoints = Generic.ConvertHashSetToSortedList(monitoredProcess.IPv6LocalhostEndpoint); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {localhostIPv6File} with localhost IPv6 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(localhostIPv6File, localhostIPv6Endpoints);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating localhost IPv6 communication file, none found for {pid}", "debug");
                        }

                        // Wireshark DFL Filter
                        if (s_outputWiresharkFilter)
                        {
                            if (computedDFLFilterByPID.ContainsKey(pid)) 
                            {
                                string processDFLFilterTextFile = @$"{processFolderInRootFolder}\Wireshark filter.txt";
                                FileAndFolders.CreateTextFileString(processDFLFilterTextFile, computedDFLFilterByPID[pid]); 
                            }
                            else if (computedDFLFilterByPID.ContainsKey(combinedFilterProcId)) 
                            {
                                string processDFLFilterTextFile = @$"{rootFolderName}\All {computedDFLFilterByPID.Count} processes filter.txt";
                                FileAndFolders.CreateTextFileString(processDFLFilterTextFile, computedDFLFilterByPID[combinedFilterProcId]); // Create textfile containing used BPF filter
                            }
                        }
                        

                        // FPC
                        if (computedBPFFilterByPID.ContainsKey(pid)) // Creating filtered FPC based on application activity
                        {
                            string filteredPcapFile = @$"{processFolderInRootFolder}\Network Packets.pcap";
                            string processBPFFilterTextFile = @$"{processFolderInRootFolder}\BPF filter.txt";

                            ConsoleOutput.Print($"Filtering saved pcap \"{fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter.", "debug");
                            FilePacketCapture filePacketCapture = new FilePacketCapture();
                            filePacketCapture.FilterCaptureFile(computedBPFFilterByPID[pid], fullPcapFile, filteredPcapFile);
                            if (s_outputBPFFilter) // If BPF Filter is to be written to text file.
                            {
                                FileAndFolders.CreateTextFileString(processBPFFilterTextFile, computedBPFFilterByPID[pid]); // Create textfile containing used BPF filter
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print($"Skipping creating dedicated PCAP file for {executable}. No recorded BPF filter", "debug");
                        }

                    }

                    // Cleanup 
                    if (!s_saveFullPcap && !s_noPacketCapture)
                    {
                        ConsoleOutput.Print($"Deleting full pcap file {fullPcapFile}", "debug");
                        FileAndFolders.DeleteFile(fullPcapFile);
                    }
                    

                    // Action
                    if (s_etwActivityHistory.Count > 0)
                    {
                        ConsoleOutput.Print($"Creating ETW history file \"{etwHistoryFile}\"", "debug");
                        FileAndFolders.CreateTextFileListOfStrings(etwHistoryFile, s_etwActivityHistory);
                    }
                    else
                    {
                        ConsoleOutput.Print("Not creating ETW history file since no activity was recorded", "warning");
                    }

                    if (s_dumpResultsToJson)
                    {
                        var options = new JsonSerializerOptions { WriteIndented = true };

                        ConsoleOutput.Print($"Creating json results file for process results \"{jsonResultsFile}\"", "debug");
                        string jsonProcessString = JsonSerializer.Serialize(s_collectiveProcessInfo, options);
                        File.WriteAllText(jsonResultsFile, jsonProcessString);

                        ConsoleOutput.Print($"Creating json results file for DNS responses \"{jsonDNSFile}\"", "debug");
                        string jsonDNSString = JsonSerializer.Serialize(s_dnsQueryResults, options);
                        File.WriteAllText(jsonDNSFile, jsonDNSString);
                    }
                    else
                    {
                        ConsoleOutput.Print($"Not creating json results file \"{jsonResultsFile}\"", "debug");
                    }
                    var endTime = DateTime.Now;
                    string monitorDuration = Generic.GetPresentableDuration(startTime, endTime);
                    ConsoleOutput.Print($"Finished! Monitor duration: {monitorDuration}. Results are in the folder {rootFolderName}.", "infoTime");
                    break;
                }
            }
        }

        private static List<string> EnrichDNSQueries(List<string> dnsQueries)
        {
            List<string> enrichedDNSQueries = new List<string>();

            foreach (string query in dnsQueries)
            {
                if (s_dnsQueryResults.ContainsKey(query))
                {
                    foreach (DNSResponse response in s_dnsQueryResults[query])
                    {
                        string enrichedQuery = $"{query} {response.RecordTypeText}({response.RecordTypeCode}) query, status {response.StatusText}({response.StatusCode}), Result {response.IP}";
                        enrichedDNSQueries.Add(enrichedQuery);
                    }
                }
                else
                {
                    enrichedDNSQueries.Add(query);
                }
            }

            enrichedDNSQueries.Sort();
            return enrichedDNSQueries;
        }

        private static bool ValidateProvidedArguments(string[] args){
            bool executableFlagSet = false;
            bool executableArgsFlagSet = false;
            bool PIDFlagSet = false;
            bool networkInterfaceDeviceFlagSet = false;
            bool noPCAPFlagSet = false;
            bool killProcessesFlagSet = false;

            // Check if no args are provided
            if (args.Length > 0)
            {
                // Iterate args
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i] == "-e" || args[i] == "--executable") // Executable flag
                    {
                        // Ensure there's a subsequent argument that represents the executable
                        if (i + 1 < args.Length)
                        {
                            s_executablePath = args[i + 1];
                            executableFlagSet = true;
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -e/--executable flag", "warning");
                        }
                    }
                    else if (args[i] == "-a" || args[i] == "--arguments") // Executable arguments flag
                    {
                        if (i + 1 < args.Length)
                        {
                            s_executableArguments = args[i + 1];
                            executableArgsFlagSet = true;
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -a/--arguments flag", "warning");
                            return false;
                        }
                    }
                    else if (args[i] == "-c" || args[i] == "--nochildprocs") // Track the network activity by child processes
                    {
                        TrackChildProcesses = false;
                    }
                    else if (args[i] == "-S" || args[i] == "--strictbpf")
                    {
                        s_strictCommunicationEnabled = true;
                    }
                    else if (args[i] == "-B" || args[i] == "--outputbpf")
                    {
                        s_outputBPFFilter = true;
                    }
                    else if (args[i] == "-D" || args[i] == "--outputdfl")
                    {
                        s_outputWiresharkFilter = true;
                    }
                    else if (args[i] == "-k" || args[i] == "--killprocesses") // Track the network activity by child processes
                    {
                        s_killProcesses = true;
                        killProcessesFlagSet = true;
                    }
                    else if (args[i] == "-s" || args[i] == "--savefullpcap") //Save the full pcap
                    {
                        s_saveFullPcap = true;
                    }
                    else if (args[i] == "-j" || args[i] == "--json") //Save the full pcap
                    {
                        s_dumpResultsToJson = true;
                    }
                    else if (args[i] == "-o" || args[i] == "--output") //Save the full pcap
                    {
                        if (i + 1 < args.Length)
                        {
                            string path = args[i + 1];

                            if (Path.IsPathRooted(path) && System.IO.Directory.Exists(path))
                            {
                                if (path.Substring(path.Length - 1) == @"\")
                                {
                                    s_outputDirectory = path;
                                }
                                else
                                {
                                    s_outputDirectory = path + @"\";
                                }
                            }
                            else
                            {
                                ConsoleOutput.Print("Provide full path to an existing catalog.", "warning");
                                return false;
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -o/--output flag", "warning");
                            return false;
                        }
                 
                    }
                    else if (args[i] == "-n" || args[i] == "--nopcap") // Don't collect pcap
                    {
                        s_noPacketCapture = true;
                        noPCAPFlagSet = true;
                    }
                    else if (args[i] == "-p" || args[i] == "--pid") // Running process id
                    {
                        if (i + 1 < args.Length)
                        {
                            if (int.TryParse(args[i + 1], out s_trackedProcessId))
                            {
                                PIDFlagSet = true;
                            }
                            else
                            {
                                Console.WriteLine($"The provided value for PID ({s_trackedProcessId}) is not a valid integer", "warning");
                                return false;
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -p/--pid flag", "warning");
                            return false;
                        }
                    }
                    else if (args[i] == "-t" || args[i] == "--timer") // Executable run timer
                    {
                        if (i + 1 < args.Length)
                        {
                            if (double.TryParse(args[i + 1], NumberStyles.Any, CultureInfo.InvariantCulture, out s_processRunTimer))
                            {
                            }
                            else
                            {
                                Console.WriteLine($"The provided value for timer ({s_processRunTimer}) is not a valid double", "warning");
                                return false;
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -t/--timer flag", "warning");
                            return false;
                        }
                    }
                    else if (args[i] == "-i" || args[i] == "--interface") // Network interface device flag
                    {
                        if (i + 1 < args.Length)
                        {
                            if (int.TryParse(args[i + 1], out s_networkInterfaceChoice))
                            {
                                networkInterfaceDeviceFlagSet = true;
                            }
                            else
                            {
                                Console.WriteLine($"The provided value for network device ({s_networkInterfaceChoice}) is not a valid integer", "warning");
                                return false;
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -i/--interface flag", "warning");
                            return false;
                        }
                    }

                    else if (args[i] == "-g" || args[i] == "--getinterfaces") //Print available interfaces
                    {
                        NetworkCaptureManagement.PrintNetworkInterfaces();
                        System.Environment.Exit(1);
                    }
                    else if (args[i] == "-d" || args[i] == "--debug") //Save the full pcap
                    {
                        Program.Debug = true;
                    }
                    else if (args[i] == "-h" || args[i] == "--help") //Output help instructions
                    {
                        ConsoleOutput.PrintHelp();
                        System.Environment.Exit(1);
                    }

                }
            }
            else
            {
                return false;
            }

            // Forbidden combination of flags
            if (executableFlagSet == PIDFlagSet) //Must specify PID or executable file and not both
            {
                ConsoleOutput.Print("One of -e or -p must be supplied, and not both", "error");
                return false;
            }
            else if (executableArgsFlagSet && !executableFlagSet)
            {
                ConsoleOutput.Print("You need to specify an executable when providing with arguments with -a", "error");
                return false;
            }
            else if (killProcessesFlagSet && PIDFlagSet)
            {
                ConsoleOutput.Print("You can only specify -k for killing process that's been started, and not via listening to a running process", "error");
                return false;
            }
            else if (networkInterfaceDeviceFlagSet == noPCAPFlagSet)
            {
                ConsoleOutput.Print("You need to specify a network device interface or specify -n/--nopcap to skip packet capture. Run again with -g to view available network devices", "error");
                return false;
            }

            return true;
        }



        public static void CatalogETWActivity(string executable = "N/A",
                                             string execType = "N/A", // Main or child process
                                             string execAction = "started",
                                             string execObject = "N/A",
                                             int execPID = 0,
                                             int parentExecPID = 0,
                                             string eventType = "network", // process, childprocess, network, dnsquery, dnsresponse
                                             NetworkPacket networkPacket = null!,
                                             DNSResponse dnsResponse = null!,
                                             DNSQuery dnsQuery = null!)
        {

            string timestamp = Generic.GetTimestampNow();
            string historyMsg = "";

            switch (eventType)
            {
                case "network": // If its a network related activity
                    {
                        historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) sent a {networkPacket.IPversion} {networkPacket.TransportProtocol} packet to {networkPacket.DestinationIP}:{networkPacket.DestinationPort}";
                        // Create BPF filter objects
                        string dstEndpoint = $"{networkPacket.DestinationIP}:{networkPacket.DestinationPort}";
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
                case "process": // If its a process related activity
                    {
                        historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) {execAction}";
                        break;
                    }
                case "childprocess": // If its a process starting another process
                    {
                        historyMsg = $"{timestamp} - {executable}[{parentExecPID}]({execType}) {execAction} {execObject}[{execPID}]";
                        s_collectiveProcessInfo[parentExecPID].ChildProcess.Add(execPID);
                        break;
                    }
                case "dnsquery": // If its a DNS query made 
                    {
                        s_collectiveProcessInfo[execPID].DNSQueries.Add(dnsQuery.DomainQueried);
                        
                        historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) made a DNS lookup for {dnsQuery.DomainQueried}";
                        break;
                    }
                case "dnsresponse": // If its a DNS response 
                    {
                        if (dnsResponse.StatusCode == 87) // DNS status code 87 is not an official status code of the DNS standard.
                        {                                 // Only something made up by Windows.
                                                          // Excluding these should not affect general analysis of the processes
                            break;
                        }

                        if (NetworkCaptureManagement.IsIPv4MappedToIPv6Address(dnsResponse.IP))
                        {
                            IPAddress address = IPAddress.Parse(dnsResponse.IP);
                            dnsResponse.IsIPv4MappedIPv6Address = true;
                            dnsResponse.IPv4MappedIPv6Address = address.MapToIPv4().ToString();
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

                        s_collectiveProcessInfo[execPID].DNSQueries.Add(dnsResponse.DomainQueried); // See comment above to why this is also here. 

                        historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) received {dnsResponse.RecordTypeText}({dnsResponse.RecordTypeCode}) DNS response {dnsResponse.StatusText}({dnsResponse.StatusCode}) for {dnsQuery} is {dnsResponse.IP}";
                        break;

                    }
            }
            ConsoleOutput.Print(historyMsg, "debug");
            s_etwActivityHistory.Add(historyMsg);
        }

        private static void TimerShutDownMonitoring(object source, ElapsedEventArgs e)
        {
            s_shutDownMonitoring = true;
            ConsoleOutput.Print($"Timer expired", "info");
        }

        private static string GetExecutableFileName(int s_trackedProcessId, string s_executablePath)
        {
            string executableFileName = "";
            if (s_trackedProcessId != 0) //When a PID was provided rather than the path to an executable
            {
                if (ProcessManager.IsProcessRunning(s_trackedProcessId)) {
                    executableFileName = ProcessManager.GetProcessFileName(s_trackedProcessId);
                }
                else
                {
                    ConsoleOutput.Print($"Unable to find active process with pid {s_trackedProcessId}", "fatal");
                    System.Environment.Exit(1);
                }
            }
            else // When the path to an executable was provided
            {
                executableFileName = Path.GetFileName(s_executablePath);
            }
            return executableFileName;
        }

        public static void InstantiateProcessVariables(int pid, string executable)
        {
            s_collectiveProcessInfo[pid] = new MonitoredProcess
            {
                ImageName = executable
            };
            s_processNetworkTraffic[pid] = new HashSet<NetworkPacket>(); // Add the main executable processname
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
    }
}