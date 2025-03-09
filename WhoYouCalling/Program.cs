
using System.Timers;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Concurrent;

// CUSTOM
using WhoYouCalling.Utilities;
using WhoYouCalling.Process;
using WhoYouCalling.Network;
using WhoYouCalling.Network.FPC;
using WhoYouCalling.Network.DNS;
using WhoYouCalling.ETW;
using WhoYouCalling.Summary;
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
        private static List<MonitoredProcess> s_monitoredProcesses = new();
        private static ConcurrentDictionary<string, int> s_uniqueMonitoredProcessIdentifiers = new();
        private static ConcurrentDictionary<int, List<int>> s_monitoredProcessIdentifiers = new();
        private static ConcurrentDictionary<int, string> s_monitoredProcessBackupProcessName = new();

        private static int s_uniqueDomainNamesQueried = new();
        private static int s_processDataOutputCounter = 0;

        private static int s_trackedMainPid = 0;
        private static List<int> s_trackedChildProcessIds = new();
        private static List<string> s_etwActivityHistory = new();

        private static bool s_shutDownMonitoring = false;
        private static bool s_timerExpired = false;
        private static string s_mainExecutableProcessName = "";

        private static LivePacketCapture s_livePacketCapture = new();
        private static KernelListener s_etwKernelListener = new();
        private static DNSClientListener s_etwDnsClientListener = new();

        private static string s_rootFolderName = "";
        private static string s_fullPcapFile = "";
        private static string s_etwHistoryFile = "";
        private static string s_processesSummaryFile = "";
        private static string s_jsonResultsFile = "";

        private static DateTime s_startTime;
        private static string s_presentableMonitorDuration = "";

        // Arguments
        public static WYCMainMode RunningMode;
        private static ArgumentData s_argumentData;

        static void Main(string[] args)
        {
            ArgumentManager argsManager = new();
            s_argumentData = argsManager.ParseArguments(args);

            if (s_argumentData.InvalidArgumentValueProvided || !argsManager.IsValidCombinationOfArguments(s_argumentData)) {
                string version = Utilities.Generic.GetVersion();
                ConsoleOutput.PrintHeader(version);
                ConsoleOutput.PrintHelp();
                System.Environment.Exit(1);
            }

            RunningMode = GetMainMode(s_argumentData);
            SetCancelKeyEvent();

            if (Debug())
            {
                ConsoleOutput.PrintArgumentValues(s_argumentData);
            }
            else
            {
                ConsoleOutput.PrintStartMonitoringText();
            }

            if (RunningMode == WYCMainMode.Illuminate)
            {
                s_rootFolderName = Generic.GetRunInstanceFolderName(RunningMode.ToString());
            }
            else
            {
                ConsoleOutput.Print("Retrieving executable filename", PrintType.Debug);
                string mainInstanceFolderName = GetMainInstanceNameWithPIDOrPath(s_argumentData.TrackedProcessId, s_argumentData.ExecutablePath);
                s_rootFolderName = Generic.NormalizePath(Generic.GetRunInstanceFolderName(mainInstanceFolderName));
            }

            if (s_argumentData.OutputDirectoryFlagSet)
            {
                s_argumentData.OutputDirectory = Generic.NormalizePath(s_argumentData.OutputDirectory);
                s_rootFolderName = $"{s_argumentData.OutputDirectory}{s_rootFolderName}";
            }

            ConsoleOutput.Print($"Creating folder {s_rootFolderName}", PrintType.Debug);
            FileAndFolders.CreateFolder(s_rootFolderName);
            s_fullPcapFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderEntirePcapFileName}";
            s_etwHistoryFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderETWHistoryFileName}";
            s_processesSummaryFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderSummaryProcessDetailsFileName}";
            s_jsonResultsFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderJSONProcessDetailsFileName}";

            ConsoleOutput.Print($"Starting monitoring", PrintType.Info);
            s_startTime = DateTime.Now;

            if (!s_argumentData.NoPacketCapture) {
                StartPacketCapture(networkInterfaceChoice: s_argumentData.NetworkInterfaceChoice, fullPcapFile: s_fullPcapFile);
            }

            StartETWMonitoring();

            switch (RunningMode)
            {
                case WYCMainMode.Execute:
                    {
                        ExecuteApplication(executablePath: s_argumentData.ExecutablePath,
                                           executableArguments: s_argumentData.ExecutableArguments,
                                           runWithHighPrivilege: s_argumentData.RunExecutableWithHighPrivilege,
                                           userNameWasProvided: s_argumentData.UserNameFlagSet,
                                           userPasswordWasProvided: s_argumentData.UserPasswordFlagSet,
                                           userName: s_argumentData.UserName,
                                           userPassword: s_argumentData.UserPassword);
                        break;
                    }
                case WYCMainMode.Listen:
                    {
                        MonitorRunningProcess(pid: s_argumentData.TrackedProcessId);
                        break;
                    }
                case WYCMainMode.Illuminate:
                    {
                        ConsoleOutput.Print($"Turning on the lights", PrintType.Info);
                        break;
                    }
            }

            if (s_argumentData.ProcessRunTimerFlagSet)
            {
                StartTimer(processMonitorTimer: s_argumentData.ProcessRunTimer);
            }

            CancellationTokenSource printMetricsCancelToken = new();
            Thread printMonitoringMetrics = new Thread(() => ConsoleOutput.PrintMetrics(printMetricsCancelToken.Token));
            printMonitoringMetrics.Start();

            while (true) // Continue monitoring and output statistics
            {
                if (s_shutDownMonitoring) // If shutdown has been signaled
                {
                    printMetricsCancelToken.Cancel();
                    Console.WriteLine(""); // Needed to adjust a linebreak since the runningStats print above uses Console.Write
                    if (s_timerExpired)
                    {
                        ConsoleOutput.Print($"Timer expired", PrintType.Info);
                    }
                    ConsoleOutput.Print($"Stopping monitoring", PrintType.Info);
                    ShutdownMonitoring();
                    s_presentableMonitorDuration = Generic.GetPresentableDuration(startTime: s_startTime, endTime: DateTime.Now);

                    if (UnmappedProcessesExists(s_monitoredProcesses))
                    {
                        ConsoleOutput.Print($"Attempting to resolve unmapped processes", PrintType.Info);
                        ResolveUnmappedActivity(s_monitoredProcesses);
                    }

                    ConsoleOutput.Print($"Creating result files", PrintType.Info);
                    OutputResults();
                    break;
                }
            }
        }

        private static void ResolveUnmappedActivity(List<MonitoredProcess> monitoredProcesses)
        {
            List<MonitoredProcess> unmappedProcesses = new();

            // Identify unmapped processes 
            foreach (MonitoredProcess monitoredProcess in monitoredProcesses)
            {
                if (monitoredProcess.MappedProcess == false) 
                {
                    unmappedProcesses.Add(monitoredProcess);
                }
            }

            // Iterate monitored processes and merge the unmapped processes to mapped processes
            foreach (MonitoredProcess monitoredProcess in monitoredProcesses.ToList())
            {
                if (monitoredProcess.MappedProcess == true)
                {
                    for (int i = unmappedProcesses.Count - 1; i >= 0; i--) // Iterating backwards to avoid index shifting
                    {
                        MonitoredProcess unmappedProcess = unmappedProcesses[i];
                        if (monitoredProcess.PID == unmappedProcess.PID)
                        {
                            if (Utilities.Generic.DateTimeIsInRangeBySeconds(referenceTime: monitoredProcess.ProcessAddedToMonitoringTime, 
                                                                             rangeTime: unmappedProcess.ProcessAddedToMonitoringTime,
                                                                             maxSecondRange: Constants.Miscellaneous.MaxSecondsUnmappedProcessRange))
                            {
                                Process.ProcessManager.MergeMonitoredProcesses(target: monitoredProcess, source: unmappedProcess);
                                monitoredProcesses.Remove(unmappedProcess);
                                unmappedProcesses.RemoveAt(i);
                                break;  
                            }
                        }
                    }
                }
            }
        }

        private static bool UnmappedProcessesExists(List<MonitoredProcess> monitoredProcesses)
        {
            foreach (MonitoredProcess monitoredProcess in monitoredProcesses)
            {
                if (monitoredProcess.MappedProcess == false)
                {
                    return true;
                }
            }
            return false;
        }

        private static void StartTimer(double processMonitorTimer)
        {
            double processRunTimerInMilliseconds = Generic.ConvertToMilliseconds(processMonitorTimer);
            System.Timers.Timer timer = new(processRunTimerInMilliseconds);
            timer.Elapsed += TimerShutDownMonitoring;
            timer.AutoReset = false;
            ConsoleOutput.Print($"Starting timer set to {processMonitorTimer} seconds", PrintType.Debug);
            timer.Start();
        }

        private static void StartETWMonitoring()
        {
            // Create and start threads for ETW. Had to make two separate functions for a dedicated thread for interoperability
            Thread etwKernelListenerThread = new(() => s_etwKernelListener.Listen());
            Thread etwDnsClientListenerThread = new(() => s_etwDnsClientListener.Listen());

            ConsoleOutput.Print("Starting ETW sessions", PrintType.Debug);
            etwKernelListenerThread.Start();
            etwDnsClientListenerThread.Start();
        }

        private static void StartPacketCapture(int networkInterfaceChoice, string fullPcapFile) 
        {
            // Retrieve network interface devices
            var devices = NetworkCaptureManagement.GetNetworkInterfaces();
            if (devices.Count == 0)
            {
                ConsoleOutput.Print($"No network devices were found..", PrintType.Fatal);
                System.Environment.Exit(1);
            }
            using var device = devices[networkInterfaceChoice];
            s_livePacketCapture.SetCaptureDevice(device);
            Thread fpcThread = new(() => s_livePacketCapture.StartCaptureToFile(fullPcapFile));
            ConsoleOutput.Print($"Starting packet capture saved to \"{fullPcapFile}\"", PrintType.Debug);
            fpcThread.Start();
        }

        private static void MonitorRunningProcess(int pid) 
        {
            s_trackedMainPid = pid;
            s_mainExecutableProcessName = System.Diagnostics.Process.GetProcessById(s_trackedMainPid).ProcessName;
            AddProcessToMonitor(pid: s_trackedMainPid, processName: s_mainExecutableProcessName);
            ConsoleOutput.Print($"Listening to PID {s_trackedMainPid}({s_mainExecutableProcessName})", PrintType.Info);
            CatalogETWActivity(eventType: EventType.ProcessMonitor, processName: s_mainExecutableProcessName, processID: s_trackedMainPid);
        }

        private static void ExecuteApplication(string executablePath, 
                                               string executableArguments, 
                                               bool runWithHighPrivilege,
                                               bool userNameWasProvided,
                                               bool userPasswordWasProvided,
                                               string userName,
                                               string userPassword)
        {
            Thread.Sleep(Constants.Timeouts.ETWSubscriptionTimingTime); //Sleep is required to ensure ETW Subscription is timed correctly to capture the execution
            try
            {
                string executionContext = "";
                if (runWithHighPrivilege)
                {
                    executionContext = "elevated";
                    s_trackedMainPid = ProcessManager.StartProcessAndGetId(executablePath: executablePath,
                                                                           arguments: executableArguments, 
                                                                           runPrivileged: true);
                }
                else
                {
                    executionContext = "unelevated"; 
                    if (userNameWasProvided && userPasswordWasProvided) 
                    {
                        s_trackedMainPid = ProcessManager.StartProcessAndGetId(executablePath: executablePath,
                                                                               arguments: executableArguments,
                                                                               username: userName,
                                                                               password: userPassword,
                                                                               runPrivileged: false);
                    }
                    else if (Win32.WinAPI.HasShellWindow())
                    {
                        s_trackedMainPid = ProcessManager.StarProcessAndGetPIDWithShellWindow(executablePath: executablePath, arguments: executableArguments);
                    }
                    else
                    {
                        ConsoleOutput.Print($"Weird state when starting process. Unprivileged execution, no user nor password provided, not interactive session. Aborting", PrintType.Fatal);
                        System.Environment.Exit(1);
                    }
                }

                ConsoleOutput.Print($"Executing \"{executablePath}\" with args \"{executableArguments}\" in {executionContext} context", PrintType.Debug);
                ConsoleOutput.Print($"Executing \"{executablePath}\"", PrintType.Info);
                s_mainExecutableProcessName = ProcessManager.GetPIDProcessName(s_trackedMainPid);
                AddProcessToMonitor(pid: s_trackedMainPid, processName: s_mainExecutableProcessName, commandLine: executableArguments);
                CatalogETWActivity(eventType: EventType.ProcessStart, processName: s_mainExecutableProcessName, processID: s_trackedMainPid, processCommandLine: executableArguments);
             }
             catch (Exception ex)
             {
                 ConsoleOutput.Print($"An error occurred while starting the process: {ex.Message}", PrintType.Fatal);
                 System.Environment.Exit(1);
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
            Thread.Sleep(Constants.Timeouts.ETWSubscriptionStopTime);
            if (!s_argumentData.NoPacketCapture)
            {
                ConsoleOutput.Print($"Stopping packet capture saved to \"{s_fullPcapFile}\"", PrintType.Debug);
                s_livePacketCapture.StopCapture();
            }
        }

        private static void OutputResults()
        {
            ConsoleOutput.Print($"Producing filters", PrintType.Debug);
            string computedCombinedBPFFilter = GetCombinedProcessNetworkFilter(s_monitoredProcesses, s_argumentData.StrictCommunicationEnabled, FilterType.BPF);
            string computedCombinedDFLFilter = GetCombinedProcessNetworkFilter(s_monitoredProcesses, s_argumentData.StrictCommunicationEnabled, FilterType.DFL);

            if (s_argumentData.OutputBPFFilter) 
            {
                if (!string.IsNullOrEmpty(computedCombinedBPFFilter))
                {
                    string processBPFFilterTextFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderBPFFilterFileName}";
                    FileAndFolders.CreateTextFileString(processBPFFilterTextFile, computedCombinedBPFFilter);
                }
            }

            int processesWithNetworkActivity = ProcessManager.GetNumberOfProcessesWithNetworkTraffic(s_monitoredProcesses);


            if (!s_argumentData.NoPacketCapture)
            {
                if (!string.IsNullOrEmpty(computedCombinedBPFFilter) && !MonitorEverything())
                {
                    string filteredPcapFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderAllProcessesFilteredPcapFileName}";

                    ConsoleOutput.Print($"Filtering saved pcap \"{s_fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter with length of {computedCombinedBPFFilter.Length}", PrintType.Debug);
                    FilePacketCapture filePacketCapture = new();

                    try
                    {
                        CancellationTokenSource printValidatingBPFFilterCancelToken = new();
                        Thread printValidatingBPFFilterMetrics = new Thread(() => ConsoleOutput.PrintBPFFilterValidation(printValidatingBPFFilterCancelToken.Token));
                        printValidatingBPFFilterMetrics.Start();

                        if (NetworkCaptureManagement.IsValidFilter(s_argumentData.NetworkInterfaceChoice, computedCombinedBPFFilter))
                        {
                            printValidatingBPFFilterCancelToken.Cancel();
                            filePacketCapture.FilterCaptureFile(computedCombinedBPFFilter, s_fullPcapFile, filteredPcapFile);
                        }
                        else
                        {
                            printValidatingBPFFilterCancelToken.Cancel();
                            ConsoleOutput.Print($"The combined BPF filter for all processes is invalid. Skipping the filter operation.", PrintType.Warning);
                        }
                    }
                    catch (Exception ex)
                    {
                        ConsoleOutput.Print($"Unable to filter the saved pcap with the combined BPF-filter of all processes: {ex.Message}", PrintType.Warning);
                    }
                }
                else
                {
                    ConsoleOutput.Print($"Not generating a combined process filter filtered pcap file", PrintType.Debug);
                }
            }

            if (s_argumentData.OutputWiresharkFilter && !string.IsNullOrEmpty(computedCombinedDFLFilter))
            {
                string processDFLFilterTextFile = @$"{s_rootFolderName}\{Constants.FileNames.RootFolderDFLFilterFileName}";
                FileAndFolders.CreateTextFileString(processDFLFilterTextFile, computedCombinedDFLFilter); // Create textfile containing used BPF filter
            }


            CancellationTokenSource printMonitoredProcessOutputCancelToken = new ();
            Thread printMonitoredProcessOutput = new Thread(() => ConsoleOutput.PrintMonitoredProcessOutputCounter(printMonitoredProcessOutputCancelToken.Token, processesWithNetworkActivity: processesWithNetworkActivity));
            printMonitoredProcessOutput.Start();

            foreach (MonitoredProcess monitoredProcess in s_monitoredProcesses)
            {

                if (ProcessManager.ProcessHasNoRecordedNetworkActivity(monitoredProcess)) // Check if the processes has any network activities recorded. If not, go to next process
                {
                    ConsoleOutput.Print($"Not outputting results for PID {monitoredProcess.PID}. No network activities recorded", PrintType.Debug);
                    continue;
                }

                s_processDataOutputCounter++; 
                int pid = monitoredProcess.PID;
                string processName = monitoredProcess.ProcessName;
                string uniqueProcessID = ProcessManager.GetUniqueProcessIdentifier(pid: pid, processName: processName);
                string processBPFFilter = "";
                string processDFLFilter = "";
                string executabelNameAndPID = $"{processName}-{pid}";
                string processFolderInRootFolder = @$"{s_rootFolderName}\{executabelNameAndPID}";

                if (!s_argumentData.NoPacketCapture)
                {
                    processBPFFilter = GetProcessNetworkFilter(monitoredProcess.TCPIPTelemetry, s_argumentData.StrictCommunicationEnabled, FilterType.BPF);
                }


                if (FileAndFolders.FolderExists(processFolderInRootFolder))
                {
                    string processFolderNameIncremented = FileAndFolders.GetProcessFolderNameIncremented(s_rootFolderName, executabelNameAndPID);
                    processFolderInRootFolder = @$"{s_rootFolderName}\{processFolderNameIncremented}";
                }

                ConsoleOutput.Print($"Creating folder {processFolderInRootFolder}", PrintType.Debug);
                FileAndFolders.CreateFolder(processFolderInRootFolder);

                // Network results text files
                OutputProcessDNSResponsesDetails(monitoredProcess.DNSResponses, 
                                        outputFile: @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderDNSQueryResponsesFileName}");

                OutputProcessDNSRQueriesDetails(monitoredProcess.DNSQueries,
                                                outputFile: @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderDNSQueriesFileName}");

                OutputDNSWiresharkFilters(strictComsEnabled: s_argumentData.StrictCommunicationEnabled,
                                          dnsResponses: monitoredProcess.DNSResponses,
                                          processFolder: processFolderInRootFolder);

                OutputProcessNetworkDetails(monitoredProcess.TCPIPTelemetry, processFolder: processFolderInRootFolder);

                // Wireshark DFL Filter
                if (s_argumentData.OutputWiresharkFilter)
                {

                    processDFLFilter = GetProcessNetworkFilter(monitoredProcess.TCPIPTelemetry, s_argumentData.StrictCommunicationEnabled, FilterType.BPF);
                    if (!string.IsNullOrEmpty(processDFLFilter))
                    {
                        string processDFLFilterTextFile = @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderDFLFilterFileName}";
                        FileAndFolders.CreateTextFileString(processDFLFilterTextFile, processDFLFilter);
                    }
                }

                // BPF Filter
                if (s_argumentData.OutputBPFFilter) 
                {
                    if (!string.IsNullOrEmpty(processBPFFilter)) 
                    {
                        string processBPFFilterTextFile = @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderBPFFilterFileName}";
                        FileAndFolders.CreateTextFileString(processBPFFilterTextFile, processBPFFilter); 
                    }
                }

                // Packet Capture 
                if (!s_argumentData.NoPacketCapture && !string.IsNullOrEmpty(processBPFFilter))
                {

                    string filteredPcapFile = @$"{processFolderInRootFolder}\{Constants.FileNames.ProcessFolderPcapFileName}";

                    ConsoleOutput.Print($"Filtering saved pcap \"{s_fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter.", PrintType.Debug);

                    FilePacketCapture filePacketCapture = new();
                    try
                    {
                        if (NetworkCaptureManagement.IsValidFilter(s_argumentData.NetworkInterfaceChoice, processBPFFilter))
                        {
                            filePacketCapture.FilterCaptureFile(processBPFFilter, s_fullPcapFile, filteredPcapFile);
                        }
                        else
                        {
                            ConsoleOutput.Print($"The BPF filter for the process {processName}[{pid}] is invalid. Not filtering a PCAP. This is often due to it being too large. The filter is {processBPFFilter.Length} characters long.", PrintType.Warning);
                        }
                    }
                    catch (Exception ex)
                    {
                        ConsoleOutput.Print($"Unable to filter a pcap for the process {processName}[{pid}]. Error: {ex.Message}", PrintType.Warning);
                    }
                }
                else
                {
                    ConsoleOutput.Print($"Skipping creating dedicated PCAP file for {processName}. No recorded BPF filter", PrintType.Debug);
                }
            }

            printMonitoredProcessOutputCancelToken.Cancel();
            Console.WriteLine(""); // Needed to adjust a linebreak since the function using the cancellation token uses Console.Write

            if (!s_argumentData.SaveFullPcap && !s_argumentData.NoPacketCapture)
            {
                ConsoleOutput.Print($"Deleting full pcap file {s_fullPcapFile}", PrintType.Debug);
                FileAndFolders.DeleteFile(file: s_fullPcapFile);
            }

            if (s_etwActivityHistory.Count > 0)
            {
                ConsoleOutput.Print($"Creating ETW history file \"{s_etwHistoryFile}\"", PrintType.Debug);
                FileAndFolders.CreateTextFileListOfStrings(filePath: s_etwHistoryFile, listWithStrings: s_etwActivityHistory);
            }

            OutputJSONFileFromResults(filePath: s_jsonResultsFile, monitoredProcesses: s_monitoredProcesses);
            OutputSummaryFile(filePath: s_processesSummaryFile, 
                              monitoredProcesses: s_monitoredProcesses, 
                              startTime: s_startTime, 
                              presentableMonitorDuration: s_presentableMonitorDuration,
                              processesWithnetworkActivity: processesWithNetworkActivity);
            ConsoleOutput.Print($"Finished! Monitor duration: {s_presentableMonitorDuration}. Results are in the folder {s_rootFolderName}", PrintType.InfoTime);
        }

        public static int GetProcessOutputCounter()
        {
            return s_processDataOutputCounter;
        }

        private static void SetCancelKeyEvent()
        {
            Console.CancelKeyPress += (sender, e) => // For manual cancellation of application
            {
                s_shutDownMonitoring = true;
                e.Cancel = true;
            };
        }

        private static void OutputSummaryFile(string filePath, List<MonitoredProcess> monitoredProcesses, DateTime startTime, string presentableMonitorDuration, int processesWithnetworkActivity)
        {
            List<string> textList = new();
            RuntimeSummary runtimeSummary = new RuntimeSummary(monitoredProcesses: monitoredProcesses, 
                                                               startTime: startTime, 
                                                               presentableMonitorDuration: presentableMonitorDuration, 
                                                               processesWithnetworkActivity: processesWithnetworkActivity);
            textList.Add(" ============================= ");
            textList.Add("|           Summary           |");
            textList.Add(" ============================= ");
            textList.Add($"# WhoYouCalling {runtimeSummary.WYCVersion} session initiated on \"{runtimeSummary.Hostname}\" at {runtimeSummary.StartTime} as: {runtimeSummary.WYCCommandline}");
            textList.Add($"The session lasted for {runtimeSummary.PresentableDuration} and monitored {runtimeSummary.NumberOfProcesses} processes where {runtimeSummary.NumberOfProcessesWithNetworkActivity} had recorded network activity.");
            textList.Add("");
            textList.Add(" ============================= ");
            textList.Add("|          Processes          |");
            textList.Add("|         with network        |");
            textList.Add("|           activity          |");
            textList.Add(" ============================= ");
            foreach (MonitoredProcess monitoredProcess in monitoredProcesses)
            {
                if (ProcessManager.ProcessHasNoRecordedNetworkActivity(monitoredProcess))
                {
                    continue;
                }
                textList.Add("  _______________________");
                textList.Add($"[ {monitoredProcess.ProcessName}-{monitoredProcess.PID}");
                textList.Add("  -----------------------");
                if (monitoredProcess.ExecutableFileName != null)
                {
                    textList.Add($"Executable: {monitoredProcess.ExecutableFileName}");
                }
                if (!string.IsNullOrEmpty(monitoredProcess.CommandLine))
                {
                    textList.Add($"Commandline: {monitoredProcess.CommandLine}");
                }
                if (monitoredProcess.IsolatedProcess != null)
                {
                    textList.Add($"Isolated process: {monitoredProcess.IsolatedProcess}");
                }
                if (monitoredProcess.ProcessStartTime != null)
                {
                    textList.Add($"Started: {monitoredProcess.ProcessStartTime}");
                }
                if (monitoredProcess.ProcessStopTime != null)
                {
                    textList.Add($"Stopped: {monitoredProcess.ProcessStopTime}");
                }

                textList.Add($"TCPIP events: {monitoredProcess.TCPIPTelemetry.Count}");
                if (monitoredProcess.TCPIPTelemetry.Count > 0)
                {
                    TCPIPSummary tcpipSummary = new TCPIPSummary(monitoredProcess);
                    textList.Add($" IP versions: {tcpipSummary.IPversionsText}");
                    textList.Add($" Protocols: {tcpipSummary.TransportProtocolsText}");
                    textList.Add($" IPs:");
                    foreach (string ip in tcpipSummary.UniqueIPs)
                    {
                        textList.Add($"  - {ip}");
                    }
                }
                textList.Add($"DNS queries: {monitoredProcess.DNSQueries.Count}");
                if (monitoredProcess.DNSQueries.Count > 0)
                {
                    DNSQueriesSummary dnsQueriesSummary = new DNSQueriesSummary(monitoredProcess);
                    textList.Add($" Domains:");
                    foreach (string domain in dnsQueriesSummary.UniqueDomains)
                    {
                        textList.Add($"  - {domain}");
                    }
                    textList.Add($" Record types: {dnsQueriesSummary.UniqueDNSRecordTypesText}");
                }
                textList.Add($"DNS responses: {monitoredProcess.DNSResponses.Count}");
                if (monitoredProcess.DNSResponses.Count > 0)
                {
                    DNSResponsesSummary dnsResponsesSummary = new DNSResponsesSummary(monitoredProcess);
                    if (!string.IsNullOrEmpty(dnsResponsesSummary.UniqueBundledRecordTypeText))
                    {
                        textList.Add($" Record types: {dnsResponsesSummary.UniqueBundledRecordTypeText}"); 
                    }
                    textList.Add($" IPs resolved: {dnsResponsesSummary.UniqueHostsResolvedCount}");
                }   
                textList.Add($"Child processes: {monitoredProcess.ChildProcesses.Count}");
                if (monitoredProcess.ChildProcesses.Count > 0)
                {
                    ChildProcessesSummary childProcessesSummary = new ChildProcessesSummary(monitoredProcess);
                    textList.Add($" Child processes: {childProcessesSummary.NumberOfChildProcesses}");
                    textList.Add($" Process names: {childProcessesSummary.NumberOfChildProcesses}");
                    foreach (string childProcessName in childProcessesSummary.ChildProcessesNames)
                    {
                        textList.Add($"  - {childProcessName}");
                    }
                }
                textList.Add("");
            }
            FileAndFolders.CreateTextFileListOfStrings(filePath: filePath, listWithStrings: textList);
        }

        private static void OutputJSONFileFromResults(string filePath, List<MonitoredProcess> monitoredProcesses)
        {
            var options = new JsonSerializerOptions
            {
                Converters = { new JsonStringEnumConverter() },
                WriteIndented = true
            };

            ConsoleOutput.Print($"Creating json results file for process results \"{filePath}\"", PrintType.Debug);
            string jsonProcessString = JsonSerializer.Serialize(monitoredProcesses, options);
            File.WriteAllText(filePath, jsonProcessString);
        }

        private static void OutputProcessNetworkDetails(HashSet<ConnectionRecord> tcpIPTelemetry, string processFolder = "")
        {
            if (tcpIPTelemetry.Count > 0)
            {
                Dictionary<ConnectionRecordType, HashSet<string>> networkDetails = NetworkUtils.FilterConnectionRecords(tcpIPTelemetry);
                Dictionary<ConnectionRecordType, List<string>> filteredNetworkDetails = NetworkUtils.GetPresentableConnectionRecordsFormat(networkDetails);

                foreach (KeyValuePair<ConnectionRecordType, List<string>> entry in filteredNetworkDetails)
                {
                    ConnectionRecordType connectionRecordType = entry.Key;
                    List<string> endpoints = entry.Value;

                    if (endpoints.Count > 0)
                    {
                        ConsoleOutput.Print($"Creating file with all {connectionRecordType} network details.", PrintType.Debug);
                        switch (connectionRecordType)
                        {
                            case ConnectionRecordType.IPv4TCP:
                                {
                                    FileAndFolders.CreateTextFileListOfStrings(@$"{processFolder}\{Constants.FileNames.ProcessFolderIPv4TCPEndpoints}", endpoints);
                                    break;
                                }
                            case ConnectionRecordType.IPv6TCP:
                                {
                                    FileAndFolders.CreateTextFileListOfStrings(@$"{processFolder}\{Constants.FileNames.ProcessFolderIPv6TCPEndpoints}", endpoints);
                                    break;
                                }
                            case ConnectionRecordType.IPv4UDP:
                                {
                                    FileAndFolders.CreateTextFileListOfStrings(@$"{processFolder}\{Constants.FileNames.ProcessFolderIPv4UDPEndpoints}", endpoints);
                                    break;
                                }
                            case ConnectionRecordType.IPv6UDP:
                                {
                                    FileAndFolders.CreateTextFileListOfStrings(@$"{processFolder}\{Constants.FileNames.ProcessFolderIPv6UDPEndpoints}", endpoints);
                                    break;
                                }
                            case ConnectionRecordType.IPv4Localhost:
                                {
                                    FileAndFolders.CreateTextFileListOfStrings(@$"{processFolder}\{Constants.FileNames.ProcessFolderIPv4LocalhostEndpoints}", endpoints);
                                    break;
                                }
                            case ConnectionRecordType.IPv6Localhost:
                                {
                                    FileAndFolders.CreateTextFileListOfStrings(@$"{processFolder}\{Constants.FileNames.ProcessFolderIPv6LocalhostEndpoints}", endpoints);
                                    break;
                                }
                        }
                    }
                    else
                    {
                        ConsoleOutput.Print($"Not creating any {connectionRecordType} file, none recorded traffic for process", PrintType.Debug);
                    }
                }
            }
            else
            {
                ConsoleOutput.Print($"Not creating any TCPIPTelemtry files, none recorded traffic for process", PrintType.Debug);
            }
        }
        
        private static void OutputProcessDNSRQueriesDetails(HashSet<DNSQuery> dnsQueries, string outputFile = "")
        {
            if (dnsQueries.Count > 0)
            {
                List<string> dnsDetails = ParseDNSQueries(dnsQueries); // Convert to list from hashset to be able to pass to function
                ConsoleOutput.Print($"Creating file {outputFile} with all DNS queries for process", PrintType.Debug);
                FileAndFolders.CreateTextFileListOfStrings(outputFile, dnsDetails);
            }
            else
            {
                ConsoleOutput.Print($"Not creating DNS file, none found for process", PrintType.Debug);
            }
        }
        private static void OutputProcessDNSResponsesDetails(HashSet<DNSResponse> dnsResponses, string outputFile = "")
        {
            if (dnsResponses.Count > 0)
            {
                List<string> dnsDetails = ParseDNSQueryResponses(dnsResponses); // Convert to list from hashset to be able to pass to function
                ConsoleOutput.Print($"Creating file {outputFile} with all DNS responses", PrintType.Debug);
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
                ConsoleOutput.Print($"Successfully stopped {etwListener.SourceName} ETW session", PrintType.Debug);
            }
        }


        private static void OutputDNSWiresharkFilters(bool strictComsEnabled, HashSet<DNSResponse> dnsResponses, string processFolder = "")
        {
            if ((dnsResponses.Count > 0) && NetworkUtils.DNSResponsesContainsAdresses(dnsResponses))
            {
                string processDNSFolder = $"{processFolder}/{Constants.FileNames.ProcessFolderDNSWiresharkFolderName}";
                FileAndFolders.CreateFolder(processDNSFolder);
                Dictionary<string, HashSet<ConnectionRecord>> domainsAndConnections = new();

                //Aggregate all returned results for all responses to the queried domain
                foreach (DNSResponse dnsResponse in dnsResponses)
                {
                    HashSet<ConnectionRecord> connectionRecords = NetworkUtils.GetNetworkAdressesFromDNSResponse(dnsResponse);
                    if (!domainsAndConnections.ContainsKey(dnsResponse.DomainQueried))
                    {
                        domainsAndConnections.Add(dnsResponse.DomainQueried, connectionRecords);
                    }
                    else
                    {
                        domainsAndConnections[dnsResponse.DomainQueried].UnionWith(connectionRecords);
                    }
                }

                //Output the results per domain
                foreach (string domain in domainsAndConnections.Keys)
                {
                    if (domainsAndConnections[domain].Count > 0)
                    {
                        string domainWiresharkFilterFileName = $"{processDNSFolder}/{domain}.txt";
                        string domainFilter = Network.NetworkFilter.GetCombinedNetworkFilter(strictComsEnabled: strictComsEnabled,
                                                                                               connectionRecords: domainsAndConnections[domain],
                                                                                               filterPorts: false,
                                                                                               onlyDestIP: true,
                                                                                               filter: FilterType.DFL);

                        FileAndFolders.CreateTextFileString(filePath: domainWiresharkFilterFileName, text: domainFilter);
                    }
                }
            }
        }

        private static List<string> ParseDNSQueries(HashSet<DNSQuery> dnsQueries)
        {
            List<string> presentableDNSQueryFormat = new();

            foreach (DNSQuery dnsQuery in dnsQueries)
            {
                string presentableQuery = $"{dnsQuery.RecordTypeText}({dnsQuery.RecordTypeCode}) for {dnsQuery.DomainQueried}";
                presentableDNSQueryFormat.Add(presentableQuery);
            }
            presentableDNSQueryFormat.Sort();
            return presentableDNSQueryFormat;
        }

        private static List<string> ParseDNSQueryResponses(HashSet<DNSResponse> dnsResponses)
        {
            HashSet<string> presentableDNSQueryResponseFormat = new();

            foreach (DNSResponse dnsResponse in dnsResponses)
            {
                HashSet<string> ipsForDomain = new();

                foreach (string ip in dnsResponse.QueryResult.IPs)
                {
                    string actualIP = NetworkUtils.GetActualIP(ip);
                    ipsForDomain.Add(actualIP);
                }
                string presentableQueryResponse = $"{dnsResponse.DomainQueried}   {string.Join(", ", ipsForDomain)}";
                presentableDNSQueryResponseFormat.Add(presentableQueryResponse);

            }

            List<string> presentableDNSResponseList = presentableDNSQueryResponseFormat.ToList();
            presentableDNSResponseList.Sort();
            return presentableDNSResponseList;
        }

        private static string GetCombinedProcessNetworkFilter(List<MonitoredProcess> monitoredProcesses, bool strictComsEnabled, FilterType filter, bool filterPorts = true)
        {
            HashSet<string> allProcessesFilter = new();
            string combinedProcessFilter = "";

            foreach (MonitoredProcess monitoredProcess in monitoredProcesses)
            {
                if (monitoredProcess.TCPIPTelemetry.Count == 0)
                {
                    ConsoleOutput.Print($"Not calculating {filter} filter for {monitoredProcess.ProcessName}({monitoredProcess.PID}). No recored network activity", PrintType.Debug);
                    continue;
                }

                string executableFilter = NetworkFilter.GetCombinedNetworkFilter(connectionRecords: monitoredProcess.TCPIPTelemetry,
                                                                                 filter: filter,
                                                                                 strictComsEnabled: strictComsEnabled);
                if (!allProcessesFilter.Contains(executableFilter))
                {
                    allProcessesFilter.Add(executableFilter);
                }
            }

            if (allProcessesFilter.Count > 0)
            {
                combinedProcessFilter = NetworkFilter.JoinFilterList(filter, allProcessesFilter);
            }
            return combinedProcessFilter;
        }

        private static string GetProcessNetworkFilter(HashSet<ConnectionRecord> tcpIPTelemetry, bool strictComsEnabled, FilterType filter, bool filterPorts = true)
        {
            return NetworkFilter.GetCombinedNetworkFilter(connectionRecords: tcpIPTelemetry,
                                                          filter: filter,
                                                          strictComsEnabled: strictComsEnabled);
        }
        public static void CatalogETWActivity(string processName = "N/A",
                                              string parentProcessName = "N/A",
                                              string processCommandLine = "",
                                              int processID = 0,
                                              int parentProcessID = 0,
                                              EventType eventType = EventType.Network,
                                              ConnectionRecord connectionRecord = new(),
                                              DNSResponse dnsResponse = new(),
                                              DNSQuery dnsQuery = new())
        {

            string timestamp = Generic.GetTimestampNow();
            string historyMsg = "";

            MonitoredProcess? monitoredProcess = GetMonitoredProcessWithProcessNameAndID(processID: processID, processName: processName); 
            if (monitoredProcess == null)
            {
                ConsoleOutput.Print($"Unable to catalog \"{eventType}\" activity for process \"{processName}\" with PID \"{processID}\"", PrintType.Warning);
                return; 
            }


            switch (eventType)
            {
                case EventType.Network:
                    {
                        historyMsg = $"{timestamp} - {processName}[{processID}] sent a {connectionRecord.IPversion} {connectionRecord.TransportProtocol} packet to {connectionRecord.DestinationIP}:{connectionRecord.DestinationPort}";

                        monitoredProcess.TCPIPTelemetry.Add(connectionRecord);
                        break;
                    }
                case EventType.ProcessStart:
                    {
                        historyMsg = $"{timestamp} - {processName}[{processID}] started";
                        if (!string.IsNullOrEmpty(processCommandLine))
                        {
                            historyMsg += $" with the arguments: {processCommandLine}";
                        }
                        break;
                    }
                case EventType.ProcessMonitor:
                    {
                        historyMsg = $"{timestamp} - {processName}[{processID}] being monitored";
                        break;
                    }
                case EventType.ProcessStop:
                    {
                        historyMsg = $"{timestamp} - {processName}[{processID}] stopped.";
                        monitoredProcess.ProcessStopTime = DateTime.Now;
                        DeleteProcessIDIndex(processID);
                        if (IsTrackedChildPID(processID)) // A redundant check to ensure that the PID is only removed after calling CatalogETWActivity to ensure any possible
                        {                                 // Lookups are not affected 
                            RemoveChildPID(processID);
                        }
                        break;
                    }
                case EventType.StartedChildProcess: 
                    {
                        historyMsg = $"{timestamp} - {parentProcessName}[{parentProcessID}] started {processName}[{processID}] with commandline: {processCommandLine}";
                        break;
                    }
                case EventType.DNSQuery:
                    {
                        monitoredProcess.DNSQueries.Add(dnsQuery);
                        Program.IncrementDNSQueries();
                        historyMsg = $"{timestamp} - {processName}[{processID}] made a DNS lookup for {dnsQuery.DomainQueried}";
                        break;
                    }
                case EventType.DNSResponse:  
                    {
                        if (dnsResponse.StatusCode == Constants.Miscellaneous.CustomWindowsDNSStatusCode) // DNS status code 87 is not an official status code of the DNS standard.
                                                                        {                                 // Only something made up by Windows.
                                                                                                          // Excluding these should not affect general analysis of the processes
                            return;
                        }

                        /* Normally i would prefer that the domain name queried is only entered 
                         * into this dict when its a query and not in the operation of 
                         * managing the response itself. However, in the use-case of listening to a running 
                         * process the query itself may have been missed, but the response is catched.
                         * is made within this part, even though it may seem redundant it's still registered proof that a process 
                         * made a DNS call. Furthermore, s_collectiveProcessInfo is a hashset so there will be no duplicates as well.
                         */

                        monitoredProcess.DNSQueries.Add(new DNSQuery
                        {
                            DomainQueried = dnsResponse.DomainQueried,
                            RecordTypeCode = dnsResponse.RecordTypeCode,
                            RecordTypeText = dnsResponse.RecordTypeText
                        }); // See comment above to why this is also here. 

                        monitoredProcess.DNSResponses.Add(dnsResponse);

                        if (dnsResponse.QueryResult.IPs.Any())
                        {
                            historyMsg = $"{timestamp} - {processName}[{processID}] received {dnsResponse.RecordTypeText}({dnsResponse.RecordTypeCode}) DNS response {dnsResponse.StatusText}({dnsResponse.StatusCode}) for {dnsResponse.DomainQueried} with IPs: {string.Join(", ", dnsResponse.QueryResult.IPs)}";
                        }
                        else
                        {
                            historyMsg = $"{timestamp} - {processName}[{processID}] received {dnsResponse.RecordTypeText}({dnsResponse.RecordTypeCode}) DNS response {dnsResponse.StatusText}({dnsResponse.StatusCode}) for {dnsResponse.DomainQueried}";
                        }
                        break;

                    }
            }
            ConsoleOutput.Print(historyMsg, PrintType.Debug);
            s_etwActivityHistory.Add(historyMsg);
        }

        private static WYCMainMode GetMainMode(ArgumentData s_argumentData)
        {
            if (s_argumentData.ExecutableFlagSet)
            {
                return WYCMainMode.Execute;
            }
            else if (s_argumentData.PIDFlagSet)
            {
                return WYCMainMode.Listen;
            }
            else 
            {
                return WYCMainMode.Illuminate;
            }
        }

        private static void TimerShutDownMonitoring(object? source, ElapsedEventArgs e)
        {
            s_timerExpired = true;
            s_shutDownMonitoring = true;
        }

        private static string GetMainInstanceNameWithPIDOrPath(int pid = 0, string executablePath = "")
        {
            string? instanceName = "";
            if (pid != 0)
            {
                if (ProcessManager.IsProcessRunning(pid)) {
                    instanceName = ProcessManager.GetPIDProcessName(pid);
                }
                else
                {
                    ConsoleOutput.Print($"Unable to find active process with pid {pid}", PrintType.Fatal);
                    System.Environment.Exit(1);
                }
            }
            else
            {
                instanceName = Path.GetFileName(executablePath);
            }

            if (instanceName == null)
            {
                instanceName = Constants.Miscellaneous.MainExecutableUnretrievableName;
            }
            return instanceName;
        }
        
        public static void AddProcessToMonitor(int pid, string processName = "", string? commandLine = null)
        {
            MonitoredProcess monitoredProcess = new MonitoredProcess
            {
                PID = pid,
                ProcessName = processName,
                CommandLine = commandLine,
                ProcessAddedToMonitoringTime = DateTime.Now
            };

            try
            {
                System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(pid);
                if (monitoredProcess.ProcessName == Constants.Miscellaneous.UnmappedProcessDefaultName)
                {
                    monitoredProcess.ProcessName = process.ProcessName;
                }

                if (ProcessManager.IsCorrectlyMatchingProcess(retrievedProcessName: process.ProcessName, providedProcessName: monitoredProcess.ProcessName))
                {
                    if (process.SessionId == 0)
                    {
                        monitoredProcess.IsolatedProcess = true;
                    }
                    else
                    {
                        monitoredProcess.IsolatedProcess = false;
                        monitoredProcess.ProcessStartTime = process.StartTime;
                    }
                }
            }
            catch
            {
            }

            if (string.IsNullOrEmpty(monitoredProcess.ProcessName))
            {
                monitoredProcess.ProcessName = Constants.Miscellaneous.UnmappedProcessDefaultName;
            }

            if (monitoredProcess.ProcessName == Constants.Miscellaneous.UnmappedProcessDefaultName)
            {
                monitoredProcess.MappedProcess = false;
                ConsoleOutput.Print($"Unable to correctly map PID {monitoredProcess.PID}", PrintType.Debug);
            }

            string uniqueProcessIdentifier = ProcessManager.GetUniqueProcessIdentifier(pid: monitoredProcess.PID, processName: monitoredProcess.ProcessName);
            if (s_uniqueMonitoredProcessIdentifiers.ContainsKey(uniqueProcessIdentifier)) // PID and Process collision has occured. Remove OLD uniqueProcessIdentifier value
            {
                s_uniqueMonitoredProcessIdentifiers.TryRemove(uniqueProcessIdentifier, out _);
            }

            if (!s_monitoredProcessBackupProcessName.ContainsKey(monitoredProcess.PID))
            {
                s_monitoredProcessBackupProcessName.TryAdd(monitoredProcess.PID, monitoredProcess.ProcessName);
            }
            monitoredProcess.ExecutableFileName = ProcessManager.GetProcessFileName(monitoredProcess.PID);
            s_monitoredProcesses.Add(monitoredProcess);
            int monitoredProcessesIndexPosition = s_monitoredProcesses.Count - 1;

            s_uniqueMonitoredProcessIdentifiers.TryAdd(uniqueProcessIdentifier, monitoredProcessesIndexPosition);

            if (s_monitoredProcessIdentifiers.ContainsKey(monitoredProcess.PID))
            {
                s_monitoredProcessIdentifiers[monitoredProcess.PID].Add(monitoredProcessesIndexPosition);
            }
            else
            {
                s_monitoredProcessIdentifiers.TryAdd(monitoredProcess.PID, new List<int> { monitoredProcessesIndexPosition });
            }
        }

        public static bool TrackProcessesByName()
        {
            return s_argumentData.ProcessesesNamesToMonitorFlagSet;
        }

       public static bool IsTrackedProcessByName(int pid, string processName = "")
        {
            /*
             * This function first checks if a processName has been provided
             * it checks for all provided patterns if any of them matches or is included in the provided process name  
             * with case insensitivity. Then an attempt is made to retrieve the actual file name and checks if the pattern is in there
             */
            string lookupProcessName = processName;
            if (string.IsNullOrEmpty(lookupProcessName))
            {
                try
                {
                    lookupProcessName = System.Diagnostics.Process.GetProcessById(pid).ProcessName;
                } 
                catch 
                {
                    ConsoleOutput.Print($"Unable to retrieve process name from PID {pid} when matching name pattern", PrintType.Debug);
                }
            }

            // Iterate provided process name patterns and check if the process name matches
            foreach (string processNamePattern in s_argumentData.ProcessesNamesToMonitor)
            {
                if (lookupProcessName.IndexOf(processNamePattern, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }


            // Attempt to retrieve the process executable file name to see if it matches
            string? processFileName = ProcessManager.GetProcessFileName(pid); 
            if (!string.IsNullOrEmpty(processFileName))
            {
                foreach (string processNamePattern in s_argumentData.ProcessesNamesToMonitor)
                {
                    if (processFileName.IndexOf(processNamePattern, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return true;
                    }
                }
            }

            return false;
        }

        public static bool MonitorEverything()
        {
            return s_argumentData.MonitorEverythingFlagSet;
        }

        public static bool IsMonitoredProcess(int pid, string processName = "")
        {
            if (string.IsNullOrEmpty(processName))
            {
                if (s_monitoredProcessIdentifiers.ContainsKey(pid))
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                string uniqueProcessIdentifier = ProcessManager.GetUniqueProcessIdentifier(pid: pid, processName: processName);
                if (UniqueProcessIDIsMonitored(uniqueProcessIdentifier))
                {
                    return true;
                }
                else
                {
                    return false;
                }
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

        public static bool MonitoredProcessCanBeRetrievedWithPID(int pid)
        {
            if (s_monitoredProcessIdentifiers[pid].Count == 1)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public static MonitoredProcess GetMonitoredProcessWithPID(int pid)
        {
            int index = s_monitoredProcessIdentifiers[pid][0];
            return s_monitoredProcesses[index];
        }

        public static bool UniqueProcessIDIsMonitored(string uniqueProcessID = "")
        {
            if (s_uniqueMonitoredProcessIdentifiers.ContainsKey(uniqueProcessID))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        public static MonitoredProcess? GetMonitoredProcessWithProcessNameAndID(int processID, string processName)
        {
            string uniqueProcessIdentifier = ProcessManager.GetUniqueProcessIdentifier(pid: processID, processName: processName);
            if (UniqueProcessIDIsMonitored(uniqueProcessIdentifier)) 
            {
                return GetMonitoredProcessWithUniqueProcessID(uniqueProcessIdentifier);
            }
            else
            {
                if (string.IsNullOrEmpty(processName))
                {
                    processName = ProcessManager.GetPIDProcessName(pid: processID);
                    if (processName == Constants.Miscellaneous.UnmappedProcessDefaultName)
                    {
                        processName = GetBackupProcessName(pid: processID);
                    }

                    uniqueProcessIdentifier = ProcessManager.GetUniqueProcessIdentifier(pid: processID, processName: processName);

                    if (UniqueProcessIDIsMonitored(uniqueProcessIdentifier))
                    {
                        return GetMonitoredProcessWithUniqueProcessID(uniqueProcessIdentifier);
                    }
                    else
                    {
                        return null;
                    }
                }
                else
                {
                    return null;
                }
            }
        }


        public static MonitoredProcess GetMonitoredProcessWithUniqueProcessID(string uniqueProcessID = "")
        {
            int index = s_uniqueMonitoredProcessIdentifiers[uniqueProcessID];
            return s_monitoredProcesses[index];
        }

        public static string GetNewProcessName(int pid, string processName)
        {

            if (string.IsNullOrEmpty(processName))
            {
                processName = ProcessManager.GetPIDProcessName(pid);
            }

            return processName;

        }

        public static string GetMonitoredProcessName(int pid, string processName = "")
        {
            if (string.IsNullOrEmpty(processName))
            {
                if (MonitoredProcessCanBeRetrievedWithPID(pid))
                {
                    processName = GetMonitoredProcessWithPID(pid).ProcessName;
                }
                else
                {
                    string initialProcessName = ProcessManager.GetPIDProcessName(pid);
                    processName = initialProcessName == Constants.Miscellaneous.UnmappedProcessDefaultName
                        ? GetBackupProcessName(pid)
                        : initialProcessName;
                }
            }

            return processName;
        }

        public static string GetBackupProcessName(int pid)
        {
            return s_monitoredProcessBackupProcessName[pid]; 
        }

        public static void DeleteOldBackupProcessName(int pid)
        {
            s_monitoredProcessBackupProcessName.TryRemove(pid, out _);
        }
        
        public static void DeleteProcessIDIndex(int pid)
        {
            int indexPos = s_monitoredProcessIdentifiers[pid][0];

            // Remove the PID list. First the first int in the list, then if its empty, clear it entirely
            s_monitoredProcessIdentifiers[pid].RemoveAt(0);
            if (s_monitoredProcessIdentifiers[pid].Count == 0) 
            {
                s_monitoredProcessIdentifiers.TryRemove(pid, out _);
            }

            // Remove the unique identifier to be able to manage PID and process name collisions
            string processName = s_monitoredProcesses[indexPos].ProcessName;
            string uniqueProcessIdentifier = ProcessManager.GetUniqueProcessIdentifier(pid: pid, processName: processName);
            s_uniqueMonitoredProcessIdentifiers.TryRemove(uniqueProcessIdentifier, out _);
        }

        public static void IncrementDNSQueries()
        {
            ++s_uniqueDomainNamesQueried;
        }
        
        public static int GetDNSActivityCount()
        {
            return s_uniqueDomainNamesQueried;
        }

        public static int GetETWActivityCount()
        {
            return s_etwActivityHistory.Count;
        }

        public static int GetLivePacketCount()
        {
            return s_livePacketCapture.GetPacketCount();
        }

        public static int GetProcessesCount()
        {
            return s_monitoredProcesses.Count;
        }
        public static bool Debug()
        {
            return s_argumentData.Debug;
        }

    }
}
