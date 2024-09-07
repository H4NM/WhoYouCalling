
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
using PacketDotNet.Utils;
using System.Security.Cryptography;

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

        private static int combinedFilterProcId = 0;

        private static DateTime startTime = DateTime.Now;

        // Arguments
        private static int s_trackedProcessId = 0;
        private static double s_processRunTimer = 0;
        private static bool s_processRunTimerWasProvided = false;
        private static int s_networkInterfaceChoice = 0;
        private static string s_executablePath = "";
        private static bool s_executablePathProvided = false;
        private static string s_executableArguments = "";
        private static string s_outputDirectory = "";
        private static bool s_providedOutputDirectory = false;
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
                ConsoleOutput.Print("Please run me as Administrator!", PrintType.Warning);
                return;
            }

            if (!ValidateProvidedArguments(args)) {
                ConsoleOutput.PrintHeader();
                ConsoleOutput.PrintHelp();
                System.Environment.Exit(1);

            }

            SetCancelKeyEvent();
            PrintStartMonitoringText();
            
            
            ConsoleOutput.Print("Retrieving executable filename", PrintType.Debug);
            s_mainExecutableFileName = GetExecutableFileName(s_trackedProcessId, s_executablePath);

            s_rootFolderName = Generic.NormalizePath(Generic.GetRunInstanceFolderName(s_mainExecutableFileName));
            s_outputDirectory = Generic.NormalizePath(s_outputDirectory);

            if (s_providedOutputDirectory) // If catalog to save data is specified
            {
                s_rootFolderName = $"{s_outputDirectory}{s_rootFolderName}";
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
            using var device = devices[s_networkInterfaceChoice];
            s_livePacketCapture.SetCaptureDevice(device);

            ConsoleOutput.Print($"Starting monitoring capabilities...", PrintType.Info);
            // Create and start thread for capturing packets if enabled
            if (!s_noPacketCapture) { 
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

            if (s_executablePathProvided)
            {
                Thread.Sleep(3000); //Sleep is required to ensure ETW Subscription is timed correctly to capture the execution
                try
                {
                    ConsoleOutput.Print($"Executing \"{s_executablePath}\" with args \"{s_executableArguments}\"", PrintType.Debug);
                    ConsoleOutput.Print($"Executing \"{s_executablePath}\"", PrintType.Info);
                    s_trackedProcessId = ProcessManager.StartProcessAndGetId(s_executablePath, s_executableArguments);
                    CatalogETWActivity(eventType: EventType.Process, executable: s_mainExecutableFileName, execType: "Main", execAction: "started", execPID: s_trackedProcessId);
                }
                catch (Exception ex)
                {
                    ConsoleOutput.Print($"An error occurred while starting the process: {ex.Message}", PrintType.Fatal);
                    System.Environment.Exit(1);
                }
            }
            else // PID to an existing process was provided
            {
                ConsoleOutput.Print($"Listening to PID \"{s_trackedProcessId}\"", PrintType.Info);
                CatalogETWActivity(eventType: EventType.Process, executable: s_mainExecutableFileName, execType: "Main", execAction: "being listened to", execPID: s_trackedProcessId);
            }

            s_etwDnsClientListener.SetPIDAndImageToTrack(s_trackedProcessId, s_mainExecutableFileName);
            s_etwKernelListener.SetPIDAndImageToTrack(s_trackedProcessId, s_mainExecutableFileName);
            InstantiateProcessVariables(pid: s_trackedProcessId, executable: s_mainExecutableFileName);

            if (s_processRunTimerWasProvided)
            {
                double s_processRunTimerInMilliseconds = Generic.ConvertToMilliseconds(s_processRunTimer);
                System.Timers.Timer timer = new System.Timers.Timer(s_processRunTimerInMilliseconds);
                timer.Elapsed += TimerShutDownMonitoring;
                timer.AutoReset = false;
                ConsoleOutput.Print($"Starting timer set to {s_processRunTimer} seconds", PrintType.Debug);
                timer.Start();
            }

            while (true) // Continue monitoring and output statistics
            {
                int capturedPacketCount = s_livePacketCapture.GetPacketCount();
                ConsoleOutput.Print($"Processes: {s_collectiveProcessInfo.Count()}. ETW Events: {s_etwActivityHistory.Count()}. Network Packets: {capturedPacketCount}", PrintType.RunningMetrics);
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
            if (s_killProcesses) // If a timer was specified and that processes should be killed
            {
                ProcessManager.KillProcess(s_trackedProcessId);
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

            if (!s_noPacketCapture)
            {
                ConsoleOutput.Print($"Stopping packet capture saved to \"{s_fullPcapFile}\"", PrintType.Debug);
                s_livePacketCapture.StopCapture();

                ConsoleOutput.Print($"Producing filters", PrintType.Debug);
                computedBPFFilterByPID = NetworkFilter.GetNetworkFilter(s_processNetworkTraffic, s_strictCommunicationEnabled, FilterType.BPF); //BPFFilter.GetBPFFilter(s_processNetworkTraffic, s_strictCommunicationEnabled);
                computedDFLFilterByPID = NetworkFilter.GetNetworkFilter(s_processNetworkTraffic, s_strictCommunicationEnabled, FilterType.DFL); //WiresharkFilter.GetDFLFilter(s_processNetworkTraffic, s_strictCommunicationEnabled);

                if (computedBPFFilterByPID.ContainsKey(combinedFilterProcId)) // 0 represents the combined BPF filter for all applications
                {
                    string filteredPcapFile = @$"{s_rootFolderName}\All {computedBPFFilterByPID.Count} processes filter.pcap";
                    string processBPFFilterTextFile = @$"{s_rootFolderName}\All {computedBPFFilterByPID.Count} processes filter.txt";
                    ConsoleOutput.Print($"Filtering saved pcap \"{s_fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter \"{computedBPFFilterByPID[combinedFilterProcId]}\"", PrintType.Debug);

                    FilePacketCapture filePacketCapture = new FilePacketCapture();
                    filePacketCapture.FilterCaptureFile(computedBPFFilterByPID[combinedFilterProcId], s_fullPcapFile, filteredPcapFile);
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
                    ConsoleOutput.Print($"Not creating folder with results for PID {pid}. No activities found", PrintType.Debug);
                    continue;
                }

                string executable = monitoredProcess.ImageName;
                string executabelNameAndPID = $"{executable}-{pid}";
                string processFolderInRootFolder = @$"{s_rootFolderName}\{executabelNameAndPID}";

                ConsoleOutput.Print($"Creating folder {processFolderInRootFolder}", PrintType.Debug);
                FileAndFolders.CreateFolder(processFolderInRootFolder);

                OutputProcessNetworkDetails(monitoredProcess.DNSQueries, 
                                            outputFile: @$"{processFolderInRootFolder}\DNS queries.txt",
                                            packetType: PacketType.DNS);

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
                if (s_outputWiresharkFilter)
                {
                    if (computedDFLFilterByPID.ContainsKey(pid))
                    {
                        string processDFLFilterTextFile = @$"{processFolderInRootFolder}\Wireshark filter.txt";
                        FileAndFolders.CreateTextFileString(processDFLFilterTextFile, computedDFLFilterByPID[pid]);
                    }
                    else if (computedDFLFilterByPID.ContainsKey(combinedFilterProcId))
                    {
                        string processDFLFilterTextFile = @$"{s_rootFolderName}\All {computedDFLFilterByPID.Count} processes filter.txt";
                        FileAndFolders.CreateTextFileString(processDFLFilterTextFile, computedDFLFilterByPID[combinedFilterProcId]); // Create textfile containing used BPF filter
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
                    if (s_outputBPFFilter) // If BPF Filter is to be written to text file.
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
            if (!s_saveFullPcap && !s_noPacketCapture)
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

            if (s_dumpResultsToJson)
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
            string monitorDuration = Generic.GetPresentableDuration(startTime, endTime);
            ConsoleOutput.Print($"Finished! Monitor duration: {monitorDuration}. Results are in the folder {s_rootFolderName}.", PrintType.InfoTime);
        }

        private static void SetCancelKeyEvent()
        {
            Console.CancelKeyPress += (sender, e) => // For manual cancellation of application
            {
                s_shutDownMonitoring = true;
                e.Cancel = true;
            };
        }

        private static void PrintStartMonitoringText()
        {
            Console.Clear();
            ConsoleOutput.PrintHeader();
            ConsoleOutput.Print($"Starting.. Press CTRL+C to cancel process monitoring.", PrintType.InfoTime);
        }

        private static void SetGeneralMonitoringFileNames()
        {
            s_fullPcapFile = @$"{s_rootFolderName}\Full Network Packet Capture.pcap";
            s_etwHistoryFile = @$"{s_rootFolderName}\ETW history.txt";
            s_jsonResultsFile = @$"{s_rootFolderName}\Process details.json";
            s_jsonDNSFile = @$"{s_rootFolderName}\DNS responses.json";
        }

        private static void OutputProcessNetworkDetails(HashSet<string> networkHashSet, string outputFile = "", PacketType packetType = PacketType.IPv4TCP)
        {
            if (networkHashSet.Count() > 0)
            {
                List<string> networkDetails = Generic.ConvertHashSetToSortedList(networkHashSet); // Convert to list from hashset to be able to pass to function
                if (packetType == PacketType.DNS)
                {
                    networkDetails = EnrichDNSQueries(networkDetails);
                }
                ConsoleOutput.Print($"Creating file {outputFile} with all {packetType} details", PrintType.Debug);
                FileAndFolders.CreateTextFileListOfStrings(outputFile, networkDetails);
            }
            else
            {
                ConsoleOutput.Print($"Not creating {packetType} file, none found for process", PrintType.Debug);
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
                            s_executablePathProvided = true;
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -e/--executable flag", PrintType.Warning);
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
                            ConsoleOutput.Print("No arguments specified after -a/--arguments flag", PrintType.Warning);
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
                                s_providedOutputDirectory = true;
                            }
                            else
                            {
                                ConsoleOutput.Print("Provide full path to an existing catalog.", PrintType.Warning);
                                return false;
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -o/--output flag", PrintType.Warning);
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
                                Console.WriteLine($"The provided value for PID ({s_trackedProcessId}) is not a valid integer", PrintType.Warning);
                                return false;
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -p/--pid flag", PrintType.Warning);
                            return false;
                        }
                    }
                    else if (args[i] == "-t" || args[i] == "--timer") // Executable run timer
                    {
                        if (i + 1 < args.Length)
                        {
                            if (double.TryParse(args[i + 1], NumberStyles.Any, CultureInfo.InvariantCulture, out s_processRunTimer))
                            {
                                s_processRunTimerWasProvided = true;
                            }
                            else
                            {
                                Console.WriteLine($"The provided value for timer ({s_processRunTimer}) is not a valid double", PrintType.Warning);
                                return false;
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -t/--timer flag", PrintType.Warning);
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
                                Console.WriteLine($"The provided value for network device ({s_networkInterfaceChoice}) is not a valid integer", PrintType.Warning);
                                return false;
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -i/--interface flag", PrintType.Warning);
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
                ConsoleOutput.Print("One of -e or -p must be supplied, and not both", PrintType.Error);
                return false;
            }
            else if (executableArgsFlagSet && !executableFlagSet)
            {
                ConsoleOutput.Print("You need to specify an executable when providing with arguments with -a", PrintType.Error);
                return false;
            }
            else if (killProcessesFlagSet && PIDFlagSet)
            {
                ConsoleOutput.Print("You can only specify -k for killing process that's been started, and not via listening to a running process", PrintType.Error);
                return false;
            }
            else if (networkInterfaceDeviceFlagSet == noPCAPFlagSet)
            {
                ConsoleOutput.Print("You need to specify a network device interface or specify -n/--nopcap to skip packet capture. Run again with -g to view available network devices", PrintType.Error);
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
                                             EventType eventType = EventType.Network, 
                                             NetworkPacket networkPacket = null!,
                                             DNSResponse dnsResponse = null!,
                                             DNSQuery dnsQuery = null!)
        {

            string timestamp = Generic.GetTimestampNow();
            string historyMsg = "";

            switch (eventType)
            {
                case EventType.Network: // If its a network related activity
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
                        s_collectiveProcessInfo[execPID].DNSQueries.Add(dnsQuery.DomainQueried);
                        
                        historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) made a DNS lookup for {dnsQuery.DomainQueried}";
                        break;
                    }
                case EventType.DNSResponse: // If its a DNS response 
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
            ConsoleOutput.Print(historyMsg, PrintType.Debug);
            s_etwActivityHistory.Add(historyMsg);
        }

        private static void TimerShutDownMonitoring(object source, ElapsedEventArgs e)
        {
            s_shutDownMonitoring = true;
            ConsoleOutput.Print($"Timer expired", PrintType.Info);
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
                    ConsoleOutput.Print($"Unable to find active process with pid {s_trackedProcessId}", PrintType.Fatal);
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