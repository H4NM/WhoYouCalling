
using System.Timers;
using System.Net;
using System.Globalization;
using System.Text.Json;

//ETW
using Microsoft.Diagnostics.Tracing.Session;

// CUSTOM
using WhoYouCalling.Utilities;


namespace WhoYouCalling
{
    class Program
    {
        private static List<int> trackedChildProcessIds = new List<int>(); // Used for tracking the corresponding executable name to the spawned processes
        private static List<string> etwActivityHistory = new List<string>(); // Summary of the network activities made
        private static Dictionary<int, HashSet<string>> bpfFilterBasedActivity = new Dictionary<int, HashSet<string>>();
        private static Dictionary<int, MonitoredProcess> collectiveProcessInfo = new Dictionary<int, MonitoredProcess>();

        private static bool shutDownMonitoring = false;
        private static string mainExecutableFileName = "";

        // Arguments
        private static int trackedProcessId = 0;
        private static double processRunTimer = 0;
        private static int networkInterfaceChoice = 0;
        private static string executablePath = "";
        private static string executableArguments = "";
        private static string outputDirectory = "";
        private static bool killProcesses = false;
        private static bool saveFullPcap = false;
        private static bool noPacketCapture = false;
        private static bool dumpResultsToJson = false;
        public static bool debug = false;
        public static bool trackChildProcesses = false;

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
            }

            Console.CancelKeyPress += (sender, e) => // For manual cancellation of application
            {
                shutDownMonitoring = true;
                e.Cancel = true;
            };

            Console.Clear();
            ConsoleOutput.PrintHeader();

            NetworkPackets networkPackets = new NetworkPackets();
            KernelListener etwKernelListener = new KernelListener();
            DNSClientListener etwDnsClientListener = new DNSClientListener();

            ConsoleOutput.Print("Retrieving executable filename", "debug");
            mainExecutableFileName = GetExecutableFileName(trackedProcessId, executablePath);


            string rootFolderName = Generic.GetRunInstanceFolderName(mainExecutableFileName);
            if (!string.IsNullOrEmpty(outputDirectory)) // If catalog to save data is specified
            {
                rootFolderName = $"{outputDirectory}{rootFolderName}";
            }
            ConsoleOutput.Print($"Creating folder {rootFolderName}", "debug");
            FileAndFolders.CreateFolder(rootFolderName);

            string fullPcapFile = @$"{rootFolderName}\{mainExecutableFileName}-Full.pcap";
            string etwHistoryFile = @$"{rootFolderName}\{mainExecutableFileName}-History.txt";
            string jsonResultsFile = @$"{rootFolderName}\{mainExecutableFileName}-Results.json";

            // Retrieve network interface devices
            var devices = networkPackets.GetNetworkInterfaces(); // Returns a LibPcapLiveDeviceList
            if (devices.Count == 0)
            {
                ConsoleOutput.Print($"No network devices were found..", "fatal");
                System.Environment.Exit(1);
            }
            using var device = devices[networkInterfaceChoice];
            networkPackets.SetCaptureDevice(device);

            // Create and start thread for capturing packets if enabled
            if (!noPacketCapture) { 
                Thread fpcThread = new Thread(() => networkPackets.CaptureNetworkPacketsToPcap(fullPcapFile));
                ConsoleOutput.Print($"Starting packet capture saved to \"{fullPcapFile}\"", "debug");
                fpcThread.Start();
            }

            // Create and start threads for ETW. Had to make two separate functions for a dedicated thread for interoperability
            Thread etwKernelListenerThread = new Thread(() => etwKernelListener.Listen());
            Thread etwDNSClientListenerThread = new Thread(() => etwDnsClientListener.Listen());
            

            ConsoleOutput.Print("Starting ETW sessions", "debug");
            etwKernelListenerThread.Start();
            etwDNSClientListenerThread.Start();

            if (!string.IsNullOrEmpty(executablePath)) // An executable path has been provided and will be executed
            {
                Thread.Sleep(3000); //Sleep is required to ensure ETW Subscription is timed correctly to capture the execution
                try
                {
                    ConsoleOutput.Print($"Starting executable \"{executablePath}\" with args \"{executableArguments}\"", "debug");
                    trackedProcessId = ProcessManager.StartProcessAndGetId(executablePath, executableArguments);
                    CatalogETWActivity(eventType: "process", executable: mainExecutableFileName, execType: "Main", execAction: "started", execPID: trackedProcessId);
                }
                catch (Exception ex)
                {
                    ConsoleOutput.Print($"An error occurred while starting the process: {ex.Message}", "fatal");
                    System.Environment.Exit(1);
                }
            }
            else // PID to an existing process is running
            {
                CatalogETWActivity(eventType: "process", executable: mainExecutableFileName, execType: "Main", execAction: "being listened to", execPID: trackedProcessId);
            }

            etwDnsClientListener.SetPIDAndImageToTrack(trackedProcessId, mainExecutableFileName);
            etwKernelListener.SetPIDAndImageToTrack(trackedProcessId, mainExecutableFileName);
            InstantiateProcessVariables(pid: trackedProcessId, executable: mainExecutableFileName);

            if (processRunTimer != 0)
            {
                double processRunTimerInMilliseconds = Generic.ConvertToMilliseconds(processRunTimer);
                System.Timers.Timer timer = new System.Timers.Timer(processRunTimerInMilliseconds);
                timer.Elapsed += TimerShutDownMonitoring;
                timer.AutoReset = false;
                ConsoleOutput.Print($"Starting timer set to {processRunTimer} seconds", "debug");
                timer.Start();
            }

            while (true) // Continue monitoring 
            {
                if (shutDownMonitoring) // If shutdown has been signaled
                {
                    ConsoleOutput.Print($"Monitoring was aborted. Finishing...", "debug");
                    if (killProcesses) // If a timer was specified and that processes should be killed
                    {
                        ProcessManager.KillProcess(trackedProcessId);
                        foreach (int childPID in trackedChildProcessIds)
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

                    if (!noPacketCapture)
                    {
                        ConsoleOutput.Print($"Stopping packet capture saved to \"{fullPcapFile}\"", "debug");
                        networkPackets.StopCapturingNetworkPackets();

                        ConsoleOutput.Print($"Producing BPF filter", "debug");
                        computedBPFFilterByPID = BPFFilter.GetBPFFilter(bpfFilterBasedActivity);
                    }

                    foreach (var kvp in collectiveProcessInfo)
                    {
                        int pid = kvp.Key;
                        MonitoredProcess monitoredProcess = kvp.Value;

                        string executable = monitoredProcess.imageName;
                        string executabelNameAndPID = $"{executable}-{pid}";
                        string processFolderInRootFolder = @$"{rootFolderName}\{executabelNameAndPID}";
                        int combinedBPFprocid = 0;

                        ConsoleOutput.Print($"Creating folder {processFolderInRootFolder}", "debug");
                        FileAndFolders.CreateFolder(processFolderInRootFolder);


                        // DNS
                        if (monitoredProcess.dnsQueries.Count() > 0)
                        {
                            string dnsQueriesFile = @$"{processFolderInRootFolder}\DNS queries.txt";

                            List<string> dnsQueries = monitoredProcess.dnsQueries.ToList(); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {dnsQueriesFile} with all DNS queries", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(dnsQueriesFile, dnsQueries);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating DNS queries file, none found for {pid}", "debug");
                        }

                        // TCP IPv4
                        if (monitoredProcess.ipv4TCPEndpoint.Count > 0) 
                        {
                            string tcpIPv4File = @$"{processFolderInRootFolder}\IPv4 TCP Endpoints.txt";
                            List<string> tcpIPv4Endpoints = monitoredProcess.ipv4TCPEndpoint.ToList(); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {tcpIPv4File} with TCP IPv4 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(tcpIPv4File, tcpIPv4Endpoints);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating TCP IPv4 communication file, none found for {pid}", "debug");
                        }

                        // TCP IPv6
                        if (monitoredProcess.ipv6TCPEndpoint.Count > 0)
                        {
                            string tcpIPv6File = @$"{processFolderInRootFolder}\IPv6 TCP Endpoints.txt";
                            List<string> tcpIPv6Endpoints = monitoredProcess.ipv6TCPEndpoint.ToList(); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {tcpIPv6File} with TCP IPv6 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(tcpIPv6File, tcpIPv6Endpoints);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating TCP IPv6 communication file, none found for {pid}", "debug");
                        }

                        // UDP IPv4
                        if (monitoredProcess.ipv4UDPEndpoint.Count > 0)
                        {
                            string udpIPv4File = @$"{processFolderInRootFolder}\IPv4 UDP Endpoints.txt";
                            List<string> udpIPv4Endpoints = monitoredProcess.ipv4UDPEndpoint.ToList(); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {udpIPv4File} with UDP IPv4 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(udpIPv4File, udpIPv4Endpoints);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating UDP IPv4 communication file, none found for {pid}", "debug");
                        }
                        // UDP IPv6
                        if (monitoredProcess.ipv6UDPEndpoint.Count > 0)
                        {
                            string udpIPv6File = @$"{processFolderInRootFolder}\IPv6 UDP Endpoints.txt";
                            List<string> udpIPv6Endpoints = monitoredProcess.ipv6UDPEndpoint.ToList(); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {udpIPv6File} with UDP IPv6 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(udpIPv6File, udpIPv6Endpoints);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating UDP IPv6 communication file, none found for {pid}", "debug");
                        }
                        // Localhost IPv4 - Takes both TCP UDP
                        if (monitoredProcess.ipv4LocalhostEndpoint.Count > 0)
                        {
                            string localhostIPv4File = @$"{processFolderInRootFolder}\Localhost Endpoints.txt";
                            List<string> localhostIPv4Endpoints = monitoredProcess.ipv4LocalhostEndpoint.ToList(); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {localhostIPv4File} with localhost IPv4 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(localhostIPv4File, localhostIPv4Endpoints);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating localhost IPv4 communication file, none found for {pid}", "debug");
                        }
                        // Localhost IPv6 - Takes both TCP UDP
                        if (monitoredProcess.ipv6LocalhostEndpoint.Count > 0)
                        {
                            string localhostIPv6File = @$"{processFolderInRootFolder}\Localhost Endpoints IPv6.txt";
                            List<string> localhostIPv6Endpoints = monitoredProcess.ipv6LocalhostEndpoint.ToList(); // Convert to list from hashset to be able to pass to function
                            ConsoleOutput.Print($"Creating file {localhostIPv6File} with localhost IPv6 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(localhostIPv6File, localhostIPv6Endpoints);
                        }
                        else
                        {
                            ConsoleOutput.Print($"Not creating localhost IPv6 communication file, none found for {pid}", "debug");
                        }

                        // FPC 
                        if (computedBPFFilterByPID.ContainsKey(pid)) // Creating filtered FPC based on application activity
                        {

                            string filteredPcapFile = @$"{processFolderInRootFolder}\{executabelNameAndPID}.pcap";
                            string processBPFFilterTextFile = @$"{processFolderInRootFolder}\{executabelNameAndPID} BPF-Filter.txt";

                            ConsoleOutput.Print($"Filtering saved pcap \"{fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter \"{computedBPFFilterByPID[pid]}\"", "debug");
                            networkPackets.FilterNetworkCaptureFile(computedBPFFilterByPID[pid], fullPcapFile, filteredPcapFile);
                            FileAndFolders.CreateTextFileString(processBPFFilterTextFile, computedBPFFilterByPID[pid]); // Create textfile containing used BPF filter
                        }
                        else if (computedBPFFilterByPID.ContainsKey(combinedBPFprocid)) // 0 represents the combined BPF filter for all applications
                        {
                            string filteredPcapFile = @$"{rootFolderName}\All {computedBPFFilterByPID.Count} processes filter.pcap";
                            string processBPFFilterTextFile = @$"{rootFolderName}\All {computedBPFFilterByPID.Count} processes filter.txt";

                            ConsoleOutput.Print($"Filtering saved pcap \"{fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter \"{computedBPFFilterByPID[combinedBPFprocid]}\"", "debug");

                            networkPackets.FilterNetworkCaptureFile(computedBPFFilterByPID[combinedBPFprocid], fullPcapFile, filteredPcapFile);
                            FileAndFolders.CreateTextFileString(processBPFFilterTextFile, computedBPFFilterByPID[combinedBPFprocid]); // Create textfile containing used BPF filter
                        }
                        else
                        {
                            ConsoleOutput.Print($"Skipping creating dedicated PCAP file for {executable}. No recorded BPF filter", "debug");
                        }

                    }

                    // Cleanup 
                    if (!saveFullPcap && !noPacketCapture)
                    {
                        ConsoleOutput.Print($"Deleting full pcap file {fullPcapFile}", "debug");
                        FileAndFolders.DeleteFile(fullPcapFile);
                    }
                    

                    // Action
                    if (etwActivityHistory.Count > 0)
                    {
                        ConsoleOutput.Print($"Creating ETW history file \"{etwHistoryFile}\"", "debug");
                        FileAndFolders.CreateTextFileListOfStrings(etwHistoryFile, etwActivityHistory);
                    }
                    else
                    {
                        ConsoleOutput.Print($"Not creating ETW history file since no activity was recorded", "warning");
                    }

                    if (dumpResultsToJson)
                    {
                        ConsoleOutput.Print($"Creating json results file \"{jsonResultsFile}\"", "debug");
                        var options = new JsonSerializerOptions { WriteIndented = true };
                        string jsonString = JsonSerializer.Serialize(collectiveProcessInfo, options);
                        File.WriteAllText(jsonResultsFile, jsonString);
                    }
                    else
                    {
                        ConsoleOutput.Print($"Not creating json results file \"{jsonResultsFile}\"", "debug");
                    }

                    ConsoleOutput.Print($"Done.", "debug");
                    break;
                }
            }
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
                            executablePath = args[i + 1];
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
                            executableArguments = args[i + 1];
                            executableArgsFlagSet = true;
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -a/--arguments flag", "warning");
                            return false;
                        }
                    }
                    else if (args[i] == "-f" || args[i] == "--fulltracking") // Track the network activity by child processes
                    {
                        trackChildProcesses = true;
                    }
                    else if (args[i] == "-k" || args[i] == "--killprocesses") // Track the network activity by child processes
                    {
                        killProcesses = true;
                        killProcessesFlagSet = true;
                    }
                    else if (args[i] == "-s" || args[i] == "--savefullpcap") //Save the full pcap
                    {
                        saveFullPcap = true;
                    }
                    else if (args[i] == "-j" || args[i] == "--json") //Save the full pcap
                    {
                        dumpResultsToJson = true;
                    }
                    else if (args[i] == "-o" || args[i] == "--output") //Save the full pcap
                    {
                        if (i + 1 < args.Length)
                        {
                            string path = args[i + 1];

                            if (Path.IsPathRooted(path) && System.IO.Directory.Exists(path))
                            {
                                if (path.Substring(path.Length - 2) == @"\\")
                                {
                                    outputDirectory = path;
                                }
                                else if (path.Substring(path.Length - 1) == @"\")
                                {
                                    outputDirectory = path + @"\";
                                }
                                else
                                {
                                    outputDirectory = path + @"\\";
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
                        noPacketCapture = true;
                        noPCAPFlagSet = true;
                    }
                    else if (args[i] == "-p" || args[i] == "--pid") // Running process id
                    {
                        if (i + 1 < args.Length)
                        {
                            if (int.TryParse(args[i + 1], out trackedProcessId))
                            {
                                PIDFlagSet = true;
                            }
                            else
                            {
                                Console.WriteLine($"The provided value for PID ({trackedProcessId}) is not a valid integer", "warning");
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
                            if (double.TryParse(args[i + 1], NumberStyles.Any, CultureInfo.InvariantCulture, out processRunTimer))
                            {
                            }
                            else
                            {
                                Console.WriteLine($"The provided value for timer ({processRunTimer}) is not a valid double", "warning");
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
                            if (int.TryParse(args[i + 1], out networkInterfaceChoice))
                            {
                                networkInterfaceDeviceFlagSet = true;
                            }
                            else
                            {
                                Console.WriteLine($"The provided value for network device ({networkInterfaceChoice}) is not a valid integer", "warning");
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
                        NetworkPackets.PrintNetworkInterfaces();
                        return false;
                    }
                    else if (args[i] == "-d" || args[i] == "--debug") //Save the full pcap
                    {
                        Program.debug = true;
                    }
                    else if (args[i] == "-h" || args[i] == "--help") //Output help instructions
                    {
                        ConsoleOutput.PrintHelp();
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
                                             string eventType = "network", // process, childprocess, network, dnsquery
                                             string ipVersion = "IPv4",
                                             string transportProto = "TCP",
                                             IPAddress srcAddr = null!,
                                             int srcPort = 0,
                                             IPAddress dstAddr = null!, 
                                             int dstPort = 0,
                                             string dnsQuery = "N/A")
        {

            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            
            string historyMsg = "";
            if (eventType == "network") // If its a network related actvitiy
            {
                historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) sent a {ipVersion} {transportProto} packet to {dstAddr}:{dstPort}";
                // Create BPF filter objects
                string bpfBasedProto = transportProto.ToLower();
                string bpfBasedIPVersion = "";
                string dstEndpoint = $"{dstAddr}:{dstPort}";
                if (ipVersion == "IPv4")
                {
                    bpfBasedIPVersion = "ip";
                    if (dstAddr.ToString() == "127.0.0.1")
                    {
                        collectiveProcessInfo[execPID].ipv4LocalhostEndpoint.Add(dstEndpoint);
                    }
                    else if (transportProto == "TCP")
                    {
                        collectiveProcessInfo[execPID].ipv4TCPEndpoint.Add(dstEndpoint);
                    }
                    else if (transportProto == "UDP")
                    {
                        collectiveProcessInfo[execPID].ipv4UDPEndpoint.Add(dstEndpoint);
                    }
                }
                else if (ipVersion == "IPv6")
                {
                    bpfBasedIPVersion = "ip6";
                    if (dstAddr.ToString() == "::1")
                    {
                        collectiveProcessInfo[execPID].ipv6LocalhostEndpoint.Add(dstEndpoint);
                    }
                    else if (transportProto == "TCP")
                    {
                        collectiveProcessInfo[execPID].ipv6TCPEndpoint.Add(dstEndpoint);
                    }
                    else if (transportProto == "UDP")
                    {
                        collectiveProcessInfo[execPID].ipv6UDPEndpoint.Add(dstEndpoint);
                    }
                }
                string packetAsCSV = $"{bpfBasedIPVersion},{bpfBasedProto},{srcAddr},{srcPort},{dstAddr},{dstPort}";

                bpfFilterBasedActivity[execPID].Add(packetAsCSV);
            }
            else if (eventType == "process") // If its a process related activity
            {
                historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) {execAction}";
            }else if (eventType == "childprocess") // If its a process starting another process
            {
                historyMsg = $"{timestamp} - {executable}[{parentExecPID}]({execType}) {execAction} {execObject}[{execPID}]";
                collectiveProcessInfo[parentExecPID].childprocess.Add(execPID);
            }
            else if (eventType == "dnsquery")
            {
                collectiveProcessInfo[execPID].dnsQueries.Add(dnsQuery);
                historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) made a DNS lookup for {dnsQuery}";
            }

            ConsoleOutput.Print(historyMsg, "debug");
            etwActivityHistory.Add(historyMsg);
        }

        private static void TimerShutDownMonitoring(object source, ElapsedEventArgs e)
        {
            shutDownMonitoring = true;
            ConsoleOutput.Print($"Timer finished!", "debug");
        }

        private static string GetExecutableFileName(int trackedProcessId, string executablePath)
        {
            string executableFileName = "";
            if (trackedProcessId != 0) //When a PID was provided rather than the path to an executable
            {
                if (ProcessManager.IsProcessRunning(trackedProcessId)) {
                    executableFileName = ProcessManager.GetProcessFileName(trackedProcessId);
                    Console.WriteLine("DEBUGING {0}", executableFileName);
                }
                else
                {
                    ConsoleOutput.Print($"Unable to find active process with pid {trackedProcessId}", "fatal");
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
            collectiveProcessInfo[pid] = new MonitoredProcess
            {
                imageName = executable
            };
            bpfFilterBasedActivity[pid] = new HashSet<string>(); // Add the main executable processname
        }

       public static bool IsTrackedChildPID(int pid)
        {
            if (trackedChildProcessIds.Contains(pid))
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
            trackedChildProcessIds.Remove(pid);
        }
        public static void AddChildPID(int pid)
        {
            trackedChildProcessIds.Add(pid);
        }

        public static string GetTrackedPIDImageName(int pid)
        {
            return collectiveProcessInfo[pid].imageName;
        }
    }
}