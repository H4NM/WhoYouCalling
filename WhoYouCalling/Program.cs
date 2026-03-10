
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

        private static List<ObservedProcess> s_observedProcesses = new(); 

        private static ConcurrentDictionary<int, string> s_monitoredProcessBackupProcessName = new();

        private static MainModes s_runningMode;
        private static bool s_collectFPC;

        private static int s_uniqueDomainNamesQueried = new();
        private static int s_processDataOutputCounter = 0;

        private static int s_trackedMainPid = 0;
        private static List<int> s_trackedChildProcessIds = new();
        private static List<string> s_etwActivityHistory = new();

        private static bool s_shutDownMonitoring = false;
        private static bool s_timerExpired = false;
        private static string s_mainExecutableProcessName = "";

        private static LivePacketCapture s_livePacketCapture = new();

        private static string s_fullOutputPath = "";
        private static string s_fullPcapFile = "";
        private static string s_etwHistoryFile = "";
        private static string s_jsonResultsFile = "";

        private static DateTime s_startTime;
        private static DateTime s_stopTime;
        private static string s_presentableMonitorDuration = "";

        // Arguments
        private static bool s_monitorEverythingIncludeLoopbackTraffic;
        private static bool s_monitorEverythingIncludeProcessStarted;

        static void Main(string[] args)
        {

            ArgumentManager argsManager = new();
            ArgumentData arguments = argsManager.ParseArguments(args);

            if (arguments.InvalidArgumentValueProvided || !argsManager.IsValidCombinationOfArguments(arguments)) {
                string version = Utilities.Generic.GetVersion();
                ConsoleOutput.PrintHeader(version);
                ConsoleOutput.PrintHelp();
                System.Environment.Exit(1);
            }

            MainModes RunningMode = GetMainModeFromArgument(arguments);
            s_runningMode = RunningMode;
            s_collectFPC = arguments.CollectFullPacketCapture;
            s_monitorEverythingIncludeLoopbackTraffic = arguments.MonitorEverythingLoopbackTrafficFlagSet;
            s_monitorEverythingIncludeProcessStarted = arguments.MonitorEverythingProcessStartsFlagSet;

            SetCancelKeyEvent();

            ConsoleOutput.PrintStartMonitoringText();

            // Retrieves the root folder name
            s_fullOutputPath = GetFullOutputPath(userSpecifiedOutputDirectory: arguments.OutputDirectoryFlagSet,
                                                 customOutputFolderProvided: arguments.OutputDirectoryCustomNameSet,
                                                 providedOutputDirectory: arguments.OutputDirectory,
                                                 runningMode: RunningMode,
                                                 trackedProcessID: arguments.TrackedProcessId,
                                                 executablePath: arguments.ExecutablePath);
            try
            {
                FileAndFolders.CreateFolder(s_fullOutputPath);
            }
            catch (Exception e)
            {
                ConsoleOutput.Print($"Unable to create folder {s_fullOutputPath}. Error: {e}", PrintType.Error);
                System.Environment.Exit(1);
            }

            s_fullPcapFile = @$"{s_fullOutputPath}\{FileNames.RootFolderEntirePcapFileName}";
            s_etwHistoryFile = @$"{s_fullOutputPath}\{FileNames.RootFolderETWHistoryFileName}";
            s_jsonResultsFile = @$"{s_fullOutputPath}\{FileNames.RootFolderJSONProcessDetailsFileName}";

            s_startTime = DateTime.Now;

            KernelListener etwKernelListener = new();
            DNSClientListener etwDnsClientListener = new(); 

            StartMonitoring(collectFullPacketCapture: arguments.CollectFullPacketCapture,
                            networkInterfaceChoice: arguments.NetworkInterfaceChoice,
                            fullPcapFilePath: s_fullPcapFile,
                            etwKernelListener: etwKernelListener,
                            etwDNSListener: etwDnsClientListener);


            switch (RunningMode)
            {
                case MainModes.Executable:
                    {
                        ExecuteApplication(executablePath: arguments.ExecutablePath,
                                           executableArguments: arguments.ExecutableArguments,
                                           runWithHighPrivilege: arguments.RunExecutableWithHighPrivilege,
                                           userNameWasProvided: arguments.UserNameFlagSet,
                                           userPasswordWasProvided: arguments.UserPasswordFlagSet,
                                           userName: arguments.UserName,
                                           userPassword: arguments.UserPassword);
                        break;
                    }
                case MainModes.PID:
                    {
                        Win32.WinAPI.AddEstablishedConnectionsToMonitoring(AF_INET: WhoYouCalling.Win32.AF_INET.IPv4, specificPID: arguments.TrackedProcessId);
                        Win32.WinAPI.AddEstablishedConnectionsToMonitoring(AF_INET: WhoYouCalling.Win32.AF_INET.IPv6, specificPID: arguments.TrackedProcessId);
                        MonitorRunningProcess(pid: arguments.TrackedProcessId);
                        break;
                    }
                case MainModes.Machine:
                    {
                        Win32.WinAPI.AddEstablishedConnectionsToMonitoring(AF_INET: WhoYouCalling.Win32.AF_INET.IPv4);
                        Win32.WinAPI.AddEstablishedConnectionsToMonitoring(AF_INET: WhoYouCalling.Win32.AF_INET.IPv6);
                        break;
                    }
            }

            if (arguments.ProcessRunTimerFlagSet)
            {
                StartTimer(processMonitorTimer: arguments.ProcessRunTimer);
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
                    ShutdownMonitoring(killProcesses: arguments.KillProcesses,
                                       collectFullPacketCapture: arguments.CollectFullPacketCapture, 
                                       etwKernelListener: etwKernelListener, 
                                       etwDNSListener: etwDnsClientListener);

                    s_stopTime = DateTime.Now;
                    s_presentableMonitorDuration = Generic.GetPresentableDuration(startTime: s_startTime, endTime: s_stopTime);

                    if (UnmappedProcessesExists(s_monitoredProcesses))
                    {
                        ConsoleOutput.Print($"Attempting to resolve unmapped processes", PrintType.Info);
                        ResolveUnmappedActivity(s_monitoredProcesses);
                    }
                    RetrieveProcessExecutableDetails(s_monitoredProcesses);

                    ConsoleOutput.Print($"Creating result files", PrintType.Info);
                    OutputResults(strictCommunicationsEnabled: arguments.StrictCommunicationEnabled,
                                  outputBPFFilter: arguments.OutputBPFFilter,
                                  collectFullPacketCapture: arguments.CollectFullPacketCapture,
                                  outputWiresharkFilter: arguments.OutputWiresharkFilter,
                                  saveFullPcap: arguments.SaveFullPcap,
                                  networkInterfaceChoice: arguments.NetworkInterfaceChoice);

                    string outputPath = s_fullOutputPath;
                    if (arguments.CompressOutputFolderFlagSet)
                    {
                        outputPath = $@"{s_fullOutputPath}.zip";
                        FileAndFolders.ZipOutputFolder(outputFolder: s_fullOutputPath, compressedFolderName: outputPath);
                        FileAndFolders.DeleteOutputFolder(folder: s_fullOutputPath);
                    }

                    ConsoleOutput.Print($"Results can be found in {outputPath}", PrintType.Info);
                    break;
                }
            }
        }

        public static void UpdateObservedProcessStopTime(int pid, DateTime stopTime)
        {
            ObservedProcess? match = null;

            foreach (var process in s_observedProcesses)
            {
                if (process.PID == pid)
                {
                    if (match != null)
                        return;
                    match = process;
                }
            }

            if (match != null)
            {
                match.StopTime = DateTime.Now;
            }
        }

        public static void AddObservedStartedProcess(int pid, string processName, string? commandLine, DateTime startTime)
        {
            ObservedProcess observedProcess = new ObservedProcess
            {
                PID = pid,
                ProcessName = processName,
                CommandLine = commandLine,
                StartTime = startTime
            };
            s_observedProcesses.Add(observedProcess);
        }

        public static ObservedProcess? GetObservedProcess(int pid)
        {
            bool foundProcess = false;
            ObservedProcess? observedProcess = null;

            foreach (var process in s_observedProcesses)
            {
                if (process.PID == pid)
                {
                    if (foundProcess)
                        return null;
                    foundProcess = true;

                    observedProcess = process;
                }
            }

            return observedProcess;
        }
        
        public static bool ObservedProcessCanBeRetrievedWithPID(int pid)
        {
            foreach (var process in s_observedProcesses)
            {
                if (process.PID == pid)
                {
                    return true;
                }
            }
            return false;
        }


        private static void StartMonitoring(bool collectFullPacketCapture, 
                                            int networkInterfaceChoice, 
                                            string fullPcapFilePath,
                                            KernelListener etwKernelListener,
                                            DNSClientListener etwDNSListener)
        {
            ConsoleOutput.Print($"Starting monitoring", PrintType.Info);
            if (collectFullPacketCapture) 
            {
                StartPacketCapture(networkInterfaceChoice: networkInterfaceChoice, fullPcapFile: fullPcapFilePath);
            }
            StartETWMonitoring(etwKernelListener: etwKernelListener, etwDNSListener: etwDNSListener);
        }

        public static string GetFinalFullOutputPath()
        {
            return s_fullOutputPath;
        }

        private static string GetFullOutputPath(bool userSpecifiedOutputDirectory, bool customOutputFolderProvided, string providedOutputDirectory, MainModes runningMode, int trackedProcessID, string executablePath)
        {
            string outputFolder = GetResultsFolderName(runningMode: runningMode,
                                                        trackedProcessID: trackedProcessID,
                                                        executablePath: executablePath);
            if (userSpecifiedOutputDirectory)
            {
                providedOutputDirectory = Generic.NormalizePath(providedOutputDirectory);
                if (customOutputFolderProvided)
                {
                    return providedOutputDirectory;
                }
                else
                {
                    return @$"{providedOutputDirectory}\{outputFolder}";
                }
            }
            else
            {
                string currentWorkingDirectory = Generic.NormalizePath(Directory.GetCurrentDirectory());
                return @$"{currentWorkingDirectory}\{outputFolder}";
            }
        }

        private static string GetResultsFolderName(MainModes runningMode, int trackedProcessID, string executablePath)
        {
            string outputDirectory = "";
            if (runningMode == MainModes.Executable || runningMode == MainModes.PID)
            {
                string mainInstanceFolderName = GetMainInstanceNameWithPIDOrPath(trackedProcessID, executablePath);
                outputDirectory = Generic.NormalizePath(Generic.GetRunInstanceName(mainInstanceFolderName));
            }
            else // Illuminate
            {
                outputDirectory = Generic.GetRunInstanceName(runningMode.ToString());
            }

            return outputDirectory;
        }
        private static void RetrieveProcessExecutableDetails(List<MonitoredProcess> monitoredProcesses)
        {
            Dictionary<string, ExecutableInformation> executablesHashes = new();

            foreach (MonitoredProcess monitoredProcess in monitoredProcesses)
            {
                if (!string.IsNullOrEmpty(monitoredProcess.Executable.FilePath) && !executablesHashes.ContainsKey(monitoredProcess.Executable.FilePath))
                {
                    long? fileSize = FileAndFolders.GetFileSize(monitoredProcess.Executable.FilePath);
                    double? fileEntropy = null;

                    if (fileSize != null && fileSize <= Miscellaneous.MaximumFileSizeForCalculatingEntropy)
                    {
                        fileEntropy = FileAndFolders.GetFileEntropy(monitoredProcess.Executable.FilePath);
                    }

                    var metadata = FileAndFolders.GetFileMetadata(monitoredProcess.Executable.FilePath);

                    executablesHashes[monitoredProcess.Executable.FilePath] = new ExecutableInformation
                    {
                        FilePath = monitoredProcess.Executable.FilePath,
                        FileSize = fileSize,
                        FileCompany = metadata.Vendor,
                        FileProductName = metadata.Product,
                        FileProductVersion = metadata.Version,
                        MD5 = FileAndFolders.GetFileMD5(monitoredProcess.Executable.FilePath),
                        SHA1 = FileAndFolders.GetFileSHA1(monitoredProcess.Executable.FilePath),
                        SHA256 = FileAndFolders.GetFileSHA256(monitoredProcess.Executable.FilePath),
                        FileEntropy = fileEntropy,
                        CreatedTimestamp = FileAndFolders.GetFileCreationTime(monitoredProcess.Executable.FilePath),
                        IsSigned = FileAndFolders.FileIsDigitallySigned(monitoredProcess.Executable.FilePath)
                    };
                }
            }

            foreach (MonitoredProcess monitoredProcess in monitoredProcesses)
            {
                if (!string.IsNullOrEmpty(monitoredProcess.Executable.FilePath) && executablesHashes.ContainsKey(monitoredProcess.Executable.FilePath))
                {
                    monitoredProcess.Executable = executablesHashes[monitoredProcess.Executable.FilePath];
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
                            if (Utilities.Generic.DateTimeIsInRangeBySeconds(referenceTime: monitoredProcess.AddedToMonitoringTime, 
                                                                             rangeTime: unmappedProcess.AddedToMonitoringTime,
                                                                             maxSecondRange: Miscellaneous.MaxSecondsUnmappedProcessRange))
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

            // Resolve remaining unmapped processes to observed started ones - these are often due to short lived processes that only perform DNS queries without TCPIP telemetry
            foreach (MonitoredProcess unmappedProcess in unmappedProcesses)
            {
                if (ObservedProcessCanBeRetrievedWithPID(pid: unmappedProcess.PID))
                {
                    ObservedProcess? observedStartedProcess = GetObservedProcess(pid: unmappedProcess.PID);
                    if (observedStartedProcess != null)
                    {
                        unmappedProcess.ProcessName = observedStartedProcess.ProcessName;
                        unmappedProcess.CommandLine = observedStartedProcess.CommandLine;
                        unmappedProcess.StartTime = observedStartedProcess.StartTime;
                        unmappedProcess.StopTime = observedStartedProcess.StopTime;
                        unmappedProcess.MappedProcess = true;
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
            timer.Start();
        }

        private static void StartETWMonitoring(KernelListener etwKernelListener, DNSClientListener etwDNSListener)
        {
            // Create and start threads for ETW. Had to make two separate functions for a dedicated thread for interoperability
            Thread etwKernelListenerThread = new(() => etwKernelListener.Listen());
            Thread etwDnsClientListenerThread = new(() => etwDNSListener.Listen());

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
            fpcThread.Start();
        }

        private static void MonitorRunningProcess(int pid) 
        {
            s_trackedMainPid = pid;
            s_mainExecutableProcessName = System.Diagnostics.Process.GetProcessById(s_trackedMainPid).ProcessName;
            if (!IsMonitoredProcess(pid: pid, processName: s_mainExecutableProcessName))
            {
                AddProcessToMonitor(pid: s_trackedMainPid, processName: s_mainExecutableProcessName);
            }
            ConsoleOutput.Print($"Listening to PID {s_trackedMainPid}({s_mainExecutableProcessName})", PrintType.Info);
            CatalogETWActivity(eventType: EventType.ProcessMonitor, processName: s_mainExecutableProcessName, pid: s_trackedMainPid);
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
                if (runWithHighPrivilege)
                {
                    s_trackedMainPid = ProcessManager.StartProcessAndGetId(executablePath: executablePath,
                                                                           arguments: executableArguments, 
                                                                           runPrivileged: true);
                }
                else
                {
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
                        s_trackedMainPid = ProcessManager.StartProcessAndGetPIDWithShellWindow(executablePath: executablePath, arguments: executableArguments);
                    }
                    else
                    {
                        ConsoleOutput.Print($"Weird state when starting process. Unprivileged execution, no user nor password provided, not interactive session. Aborting", PrintType.Fatal);
                        System.Environment.Exit(1);
                    }
                }

                ConsoleOutput.Print($"Executing \"{executablePath}\"", PrintType.Info);
                s_mainExecutableProcessName = ProcessManager.GetPIDProcessName(s_trackedMainPid);
                AddProcessToMonitor(pid: s_trackedMainPid, processName: s_mainExecutableProcessName, commandLine: executableArguments);
                CatalogETWActivity(eventType: EventType.ProcessStart, processName: s_mainExecutableProcessName, pid: s_trackedMainPid, processCommandLine: executableArguments);
             }
             catch (Exception ex)
             {
                 ConsoleOutput.Print($"An error occurred while starting the process: {ex.Message}", PrintType.Fatal);
                 System.Environment.Exit(1);
             }
        }

        private static void ShutdownMonitoring(bool killProcesses, bool collectFullPacketCapture, KernelListener etwKernelListener, DNSClientListener etwDNSListener)
        {
            if (killProcesses) // If spawned processes are to be killed
            {
                ProcessManager.KillProcess(s_trackedMainPid); // Kill main process
                foreach (int childPID in s_trackedChildProcessIds) // Kill child processes
                {
                    ProcessManager.KillProcess(childPID);
                }
            }
            StopETWSession(etwKernelListener);
            StopETWSession(etwDNSListener);
            Thread.Sleep(Constants.Timeouts.ETWSubscriptionStopTime);
            if (collectFullPacketCapture) 
            {
                s_livePacketCapture.StopCapture();
            }
        }

        private static void OutputResults(bool strictCommunicationsEnabled,
                                          bool outputBPFFilter,
                                          bool collectFullPacketCapture,
                                          bool outputWiresharkFilter,
                                          bool saveFullPcap,
                                          int networkInterfaceChoice)
        {
            string computedCombinedBPFFilter = GetCombinedProcessNetworkFilter(s_monitoredProcesses, strictCommunicationsEnabled, FilterType.BPF);
            string computedCombinedDFLFilter = GetCombinedProcessNetworkFilter(s_monitoredProcesses, strictCommunicationsEnabled, FilterType.DFL);

            if (outputBPFFilter) 
            {
                if (!string.IsNullOrEmpty(computedCombinedBPFFilter))
                {
                    string processBPFFilterTextFile = @$"{s_fullOutputPath}\{FileNames.RootFolderBPFFilterFileName}";
                    FileAndFolders.CreateTextFileString(processBPFFilterTextFile, computedCombinedBPFFilter);
                }
            }

            int processesWithNetworkActivity = ProcessManager.GetNumberOfProcessesWithNetworkTraffic(s_monitoredProcesses);


            if (collectFullPacketCapture)
            {
                if (!string.IsNullOrEmpty(computedCombinedBPFFilter) && !MonitorEverything())
                {
                    string filteredPcapFile = @$"{s_fullOutputPath}\{FileNames.RootFolderAllProcessesFilteredPcapFileName}";

                    FilePacketCapture filePacketCapture = new();

                    try
                    {
                        CancellationTokenSource printValidatingBPFFilterCancelToken = new();
                        Thread printValidatingBPFFilterMetrics = new Thread(() => ConsoleOutput.PrintBPFFilterValidation(printValidatingBPFFilterCancelToken.Token));
                        printValidatingBPFFilterMetrics.Start();

                        if (NetworkCaptureManagement.IsValidFilter(networkInterfaceChoice, computedCombinedBPFFilter))
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
            }

            if (outputWiresharkFilter && !string.IsNullOrEmpty(computedCombinedDFLFilter))
            {
                string processDFLFilterTextFile = @$"{s_fullOutputPath}\{FileNames.RootFolderDFLFilterFileName}";
                FileAndFolders.CreateTextFileString(processDFLFilterTextFile, computedCombinedDFLFilter); // Create textfile containing used BPF filter
            }

            CancellationTokenSource printMonitoredProcessOutputCancelToken = new ();
            Thread printMonitoredProcessOutput = new Thread(() => ConsoleOutput.PrintMonitoredProcessOutputCounter(printMonitoredProcessOutputCancelToken.Token, processesWithNetworkActivity: processesWithNetworkActivity));
            printMonitoredProcessOutput.Start();

            foreach (MonitoredProcess monitoredProcess in s_monitoredProcesses)
            {

                if (ProcessManager.ProcessHasNoRecordedNetworkActivity(monitoredProcess)) // Check if the processes has any network activities recorded. If not, go to next process
                {
                    continue;
                }

                s_processDataOutputCounter++; 
                int pid = monitoredProcess.PID;
                string processName = monitoredProcess.ProcessName;
                string uniqueProcessID = ProcessManager.GetUniqueProcessIdentifier(pid: pid, processName: processName);
                string processBPFFilter = "";
                string processDFLFilter = "";
                string executabelNameAndPID = $"{processName}-{pid}";
                string processFolderInRootFolder = @$"{s_fullOutputPath}\{executabelNameAndPID}";

                if (collectFullPacketCapture)
                {
                    processBPFFilter = GetProcessNetworkFilter(monitoredProcess.TCPIPTelemetry, strictCommunicationsEnabled, FilterType.BPF);
                }


                if (FileAndFolders.FolderExists(processFolderInRootFolder))
                {
                    string processFolderNameIncremented = FileAndFolders.GetProcessFolderNameIncremented(s_fullOutputPath, executabelNameAndPID);
                    processFolderInRootFolder = @$"{s_fullOutputPath}\{processFolderNameIncremented}";
                }

                FileAndFolders.CreateFolder(processFolderInRootFolder);

                // Per process details files
                OutputProcessInformation(monitoredProcess: monitoredProcess,
                                        outputFile: @$"{processFolderInRootFolder}\{FileNames.ProcessFolderProcessInformation}");

                OutputProcessDNSResponsesDetails(monitoredProcess.DNSResponses, 
                                        outputFile: @$"{processFolderInRootFolder}\{FileNames.ProcessFolderDNSQueryResponsesFileName}");

                OutputProcessDNSRQueriesDetails(monitoredProcess.DNSQueries,
                                                outputFile: @$"{processFolderInRootFolder}\{FileNames.ProcessFolderDNSQueriesFileName}");

                OutputDNSWiresharkFilters(strictComsEnabled: strictCommunicationsEnabled,
                                          dnsResponses: monitoredProcess.DNSResponses,
                                          processFolder: processFolderInRootFolder);

                OutputProcessNetworkDetails(monitoredProcess.TCPIPTelemetry, processFolder: processFolderInRootFolder);

                // Wireshark DFL Filter
                if (outputWiresharkFilter)
                {

                    processDFLFilter = GetProcessNetworkFilter(monitoredProcess.TCPIPTelemetry, strictCommunicationsEnabled, FilterType.DFL);
                    if (!string.IsNullOrEmpty(processDFLFilter))
                    {
                        string processDFLFilterTextFile = @$"{processFolderInRootFolder}\{FileNames.ProcessFolderDFLFilterFileName}";
                        FileAndFolders.CreateTextFileString(processDFLFilterTextFile, processDFLFilter);
                    }
                }

                // BPF Filter
                if (outputBPFFilter) 
                {
                    if (!string.IsNullOrEmpty(processBPFFilter)) 
                    {
                        string processBPFFilterTextFile = @$"{processFolderInRootFolder}\{FileNames.ProcessFolderBPFFilterFileName}";
                        FileAndFolders.CreateTextFileString(processBPFFilterTextFile, processBPFFilter); 
                    }
                }

                // Packet Capture 
                if (collectFullPacketCapture && !string.IsNullOrEmpty(processBPFFilter))
                {

                    string filteredPcapFile = @$"{processFolderInRootFolder}\{FileNames.ProcessFolderPcapFileName}";


                    FilePacketCapture filePacketCapture = new();
                    try
                    {
                        if (NetworkCaptureManagement.IsValidFilter(networkInterfaceChoice, processBPFFilter))
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
            }

            printMonitoredProcessOutputCancelToken.Cancel();
            Console.WriteLine(""); // Needed to adjust a linebreak since the function using the cancellation token uses Console.Write

            if (!saveFullPcap && collectFullPacketCapture)
            {
                FileAndFolders.DeleteFile(file: s_fullPcapFile);
            }

            if (s_etwActivityHistory.Count > 0)
            {
                FileAndFolders.CreateTextFileListOfStrings(filePath: s_etwHistoryFile, listWithStrings: s_etwActivityHistory);
            }

            OutputJSONFileFromResults(filePath: s_jsonResultsFile, monitoredProcesses: s_monitoredProcesses);

            ConsoleOutput.Print($"Finished! Monitor duration: {s_presentableMonitorDuration}.", PrintType.InfoTime);
        }

        public static DateTime GetStartTime()
        {
            return s_startTime;
        }

        public static DateTime GetStopTime()
        {
            return s_stopTime;
        }

        public static string GetPresentableMonitorDuration()
        {
            return s_presentableMonitorDuration;
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

        private static void OutputJSONFileFromResults(string filePath, List<MonitoredProcess> monitoredProcesses)
        {

            Dictionary<string, object> metadataAndMonitoredProcesses = new Dictionary<string, object>
            {
                { "Metadata", new Summary.RuntimeSummary(monitoredProcesses: monitoredProcesses) },
                { "MonitoredProcesses", monitoredProcesses }
            };

            var options = new JsonSerializerOptions
            {
                Converters = { new JsonStringEnumConverter() },
                WriteIndented = false
            };

            string jsonProcessString = JsonSerializer.Serialize(metadataAndMonitoredProcesses, options);
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
                        switch (connectionRecordType)
                        {
                            case ConnectionRecordType.IPv4TCP:
                                {
                                    FileAndFolders.CreateTextFileListOfStrings(@$"{processFolder}\{FileNames.ProcessFolderIPv4TCPEndpoints}", endpoints);
                                    break;
                                }
                            case ConnectionRecordType.IPv6TCP:
                                {
                                    FileAndFolders.CreateTextFileListOfStrings(@$"{processFolder}\{FileNames.ProcessFolderIPv6TCPEndpoints}", endpoints);
                                    break;
                                }
                            case ConnectionRecordType.IPv4UDP:
                                {
                                    FileAndFolders.CreateTextFileListOfStrings(@$"{processFolder}\{FileNames.ProcessFolderIPv4UDPEndpoints}", endpoints);
                                    break;
                                }
                            case ConnectionRecordType.IPv6UDP:
                                {
                                    FileAndFolders.CreateTextFileListOfStrings(@$"{processFolder}\{FileNames.ProcessFolderIPv6UDPEndpoints}", endpoints);
                                    break;
                                }
                            case ConnectionRecordType.IPv4Localhost:
                                {
                                    FileAndFolders.CreateTextFileListOfStrings(@$"{processFolder}\{FileNames.ProcessFolderIPv4LocalhostEndpoints}", endpoints);
                                    break;
                                }
                            case ConnectionRecordType.IPv6Localhost:
                                {
                                    FileAndFolders.CreateTextFileListOfStrings(@$"{processFolder}\{FileNames.ProcessFolderIPv6LocalhostEndpoints}", endpoints);
                                    break;
                                }
                        }
                    }
                }
            }
        }

        private static void OutputProcessInformation(MonitoredProcess monitoredProcess, string outputFile = "")
        {

            List<string> processDetails = [
                    $"Process Name: {monitoredProcess.ProcessName}",
                    $"PID: {monitoredProcess.PID}",
                    $"Commandline: {monitoredProcess.CommandLine}",
                    $"Running as: {monitoredProcess.ProcessUser}",
                    $"Protected process: {monitoredProcess.IsolatedProcess}",
                    $"Start time: {monitoredProcess.StartTime}",
                    $"Stop time: {monitoredProcess.StopTime}",
                    ""
            ];

            if (monitoredProcess.IsolatedProcess == false)
            {
                processDetails.Add("====== Executable ======");
                processDetails.Add($"File path: {monitoredProcess.Executable.FilePath}");
                processDetails.Add($"MD5: {monitoredProcess.Executable.MD5}");
                processDetails.Add($"SHA1: {monitoredProcess.Executable.SHA1}");
                processDetails.Add($"SHA256: {monitoredProcess.Executable.SHA256}");
                processDetails.Add($"Is signed: {monitoredProcess.Executable.IsSigned}");
                processDetails.Add($"Created: {monitoredProcess.Executable.CreatedTimestamp}");
            }
            FileAndFolders.CreateTextFileListOfStrings(outputFile, processDetails);
        }

        private static void OutputProcessDNSRQueriesDetails(HashSet<DNSQuery> dnsQueries, string outputFile = "")
        {
            if (dnsQueries.Count > 0)
            {
                List<string> dnsDetails = ParseDNSQueries(dnsQueries); // Convert to list from hashset to be able to pass to function
                FileAndFolders.CreateTextFileListOfStrings(outputFile, dnsDetails);
            }
        }
        private static void OutputProcessDNSResponsesDetails(HashSet<DNSResponse> dnsResponses, string outputFile = "")
        {
            if (dnsResponses.Count > 0)
            {
                List<string> dnsDetails = ParseDNSQueryResponses(dnsResponses); // Convert to list from hashset to be able to pass to function
                FileAndFolders.CreateTextFileListOfStrings(outputFile, dnsDetails);
            }
        }

        private static void StopETWSession(Listener etwListener)
        {
            etwListener.StopSession();
            if (etwListener.GetSessionStatus())
            {
                ConsoleOutput.Print($"{etwListener.SourceName} ETW session still running...", PrintType.Warning);
            }
        }


        private static void OutputDNSWiresharkFilters(bool strictComsEnabled, HashSet<DNSResponse> dnsResponses, string processFolder = "")
        {
            if ((dnsResponses.Count > 0) && NetworkUtils.DNSResponsesContainsAdresses(dnsResponses))
            {
                string processDNSFolder = $"{processFolder}/{FileNames.ProcessFolderDNSWiresharkFolderName}";
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
                                              int pid = 0,
                                              int parentProcessID = 0,
                                              EventType eventType = EventType.Network,
                                              ConnectionRecord connectionRecord = new(),
                                              DNSResponse dnsResponse = new(),
                                              DNSQuery dnsQuery = new(),
                                              DateTime processTime = new())
        {

            string timestamp = Generic.GetTimestampNow();
            string historyMsg = "";

            MonitoredProcess? monitoredProcess = GetMonitoredProcessWithProcessNameAndID(pid: pid, processName: processName); 
            if (monitoredProcess == null)
            {
                ConsoleOutput.Print($"Unable to catalog \"{eventType}\" activity for process \"{processName}\" with PID \"{pid}\"", PrintType.Warning);
                return; 
            }


            switch (eventType)
            {
                case EventType.Network:
                    {
                        historyMsg = $"{timestamp} - {processName}[{pid}] sent a {connectionRecord.IPversion} {connectionRecord.TransportProtocol} packet to {connectionRecord.DestinationIP}:{connectionRecord.DestinationPort}";

                        monitoredProcess.TCPIPTelemetry.Add(connectionRecord);
                        break;
                    }
                case EventType.ProcessStart:
                    {
                        historyMsg = $"{timestamp} - {processName}[{pid}] started";
                        if (!string.IsNullOrEmpty(processCommandLine))
                        {
                            historyMsg += $" with the arguments: {processCommandLine}";
                        }
                        break;
                    }
                case EventType.ProcessMonitor:
                    {
                        historyMsg = $"{timestamp} - {processName}[{pid}] being monitored";
                        break;
                    }
                case EventType.ProcessStop:
                    {
                        historyMsg = $"{timestamp} - {processName}[{pid}] stopped.";
                        monitoredProcess.StopTime = processTime;
                        DeleteProcessIDIndex(pid);
                        if (IsTrackedChildPID(pid)) // A redundant check to ensure that the PID is only removed after calling CatalogETWActivity to ensure any possible
                        {                                 // Lookups are not affected 
                            RemoveChildPID(pid);
                        }
                        break;
                    }
                case EventType.StartedChildProcess: 
                    {
                        historyMsg = $"{timestamp} - {parentProcessName}[{parentProcessID}] started {processName}[{pid}] with commandline: {processCommandLine}";
                        break;
                    }
                case EventType.DNSQuery:
                    {
                        monitoredProcess.DNSQueries.Add(dnsQuery);
                        Program.IncrementDNSQueries();
                        historyMsg = $"{timestamp} - {processName}[{pid}] made a DNS lookup for {dnsQuery.DomainQueried}";
                        break;
                    }
                case EventType.DNSResponse:  
                    {
                        if (dnsResponse.StatusCode == Miscellaneous.CustomWindowsDNSStatusCode) // DNS status code 87 is not an official status code of the DNS standard.
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
                            historyMsg = $"{timestamp} - {processName}[{pid}] received {dnsResponse.RecordTypeText}({dnsResponse.RecordTypeCode}) DNS response {dnsResponse.StatusText}({dnsResponse.StatusCode}) for {dnsResponse.DomainQueried} with IPs: {string.Join(", ", dnsResponse.QueryResult.IPs)}";
                        }
                        else
                        {
                            historyMsg = $"{timestamp} - {processName}[{pid}] received {dnsResponse.RecordTypeText}({dnsResponse.RecordTypeCode}) DNS response {dnsResponse.StatusText}({dnsResponse.StatusCode}) for {dnsResponse.DomainQueried}";
                        }
                        break;

                    }
            }
            s_etwActivityHistory.Add(historyMsg);
        }

        private static MainModes GetMainModeFromArgument(ArgumentData argumentData)
        {
            if (argumentData.ExecutableFlagSet)
            {
                return MainModes.Executable;
            }
            else if (argumentData.PIDFlagSet)
            {
                return MainModes.PID;
            }
            else // Illuminate 
            {
                return MainModes.Machine;
            }
        }
        public static MainModes GetRunningMainMode()
        {
            return s_runningMode;
        }
        public static bool FPCWasCollected()
        {
            return s_collectFPC;
        }

        public static bool IncludeLoopbackWhenMonitoringEverything()
        {
            return s_monitorEverythingIncludeLoopbackTraffic;
        }

        public static bool IncludeProcessStartsWhenMonitoringEverything()
        {
            return s_monitorEverythingIncludeProcessStarted;
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
                instanceName = Miscellaneous.MainExecutableUnretrievableName;
            }
            return instanceName;
        }

        public static void AddConnectionRecordToMonitoredProcess(int pid, IPVersion ipVersion, TransportProtocol transportProto, string sourceIP, int sourcePort, string destIP, int destPort)
        {
            ConnectionRecord connectionRecord = new ConnectionRecord
            {
                IPversion = ipVersion,
                TransportProtocol = transportProto,
                SourceIP = sourceIP,
                SourcePort = sourcePort,
                DestinationIP = destIP,
                DestinationPort = destPort
            };
            MonitoredProcess monitoredProcess = GetMonitoredProcessWithPID(pid: pid);
            monitoredProcess.TCPIPTelemetry.Add(connectionRecord);
        }

        public static void AddProcessToMonitor(int pid, string processName = "", string? commandLine = null)
        {
            MonitoredProcess monitoredProcess = new MonitoredProcess
            {
                PID = pid,
                ProcessName = processName,
                CommandLine = commandLine,
                AddedToMonitoringTime = DateTime.Now
            };

            monitoredProcess = ProcessManager.EnrichMonitoredProcessData(monitoredProcess, pid:pid, processName: processName);

            string uniqueProcessIdentifier = ProcessManager.GetUniqueProcessIdentifier(pid: monitoredProcess.PID, processName: monitoredProcess.ProcessName);

            CatalogProcess(uniqueProcessIdentifier: uniqueProcessIdentifier, monitoredProcess: monitoredProcess);
        }

        private static void CatalogProcess(string uniqueProcessIdentifier, MonitoredProcess monitoredProcess)
        {
            if (s_uniqueMonitoredProcessIdentifiers.ContainsKey(uniqueProcessIdentifier)) // PID and Process name collision has occured. Remove OLD uniqueProcessIdentifier value
            {
                s_uniqueMonitoredProcessIdentifiers.TryRemove(uniqueProcessIdentifier, out _);
            }

            if (!s_monitoredProcessBackupProcessName.ContainsKey(monitoredProcess.PID))
            {
                s_monitoredProcessBackupProcessName.TryAdd(monitoredProcess.PID, monitoredProcess.ProcessName);
            }

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

        public static bool MonitorEverything()
        {
            return s_runningMode == MainModes.Machine;
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


        public static string GetFullProgramCommandLine()
        {
            string[] commandLineArgs = Environment.GetCommandLineArgs();
            return $"wyc.exe {string.Join(" ", commandLineArgs, 1, commandLineArgs.Length - 1)}";
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
            return (s_monitoredProcessIdentifiers[pid].Count == 1);
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
        public static MonitoredProcess? GetMonitoredProcessWithProcessNameAndID(int pid, string processName)
        {
            string uniqueProcessIdentifier = ProcessManager.GetUniqueProcessIdentifier(pid: pid, processName: processName);

            if (UniqueProcessIDIsMonitored(uniqueProcessIdentifier)) 
            {
                return GetMonitoredProcessWithUniqueProcessID(uniqueProcessIdentifier);
            }
            else
            {
                if (string.IsNullOrEmpty(processName))
                {
                    processName = ProcessManager.GetPIDProcessName(pid: pid);
                    if (processName == Miscellaneous.UnmappedProcessDefaultName)
                    {
                        processName = GetBackupProcessName(pid: pid);
                    }

                    uniqueProcessIdentifier = ProcessManager.GetUniqueProcessIdentifier(pid: pid, processName: processName);

                    if (UniqueProcessIDIsMonitored(uniqueProcessIdentifier))
                    {
                        return GetMonitoredProcessWithUniqueProcessID(uniqueProcessIdentifier);
                    }
                }
                if (MonitoredProcessCanBeRetrievedWithPID(pid))
                {
                    return GetMonitoredProcessWithPID(pid: pid);
                }

                return null;
            }
        }

        public static MonitoredProcess GetMonitoredProcessWithUniqueProcessID(string uniqueProcessID = "")
        {
            int index = s_uniqueMonitoredProcessIdentifiers[uniqueProcessID];
            return s_monitoredProcesses[index];
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
                    processName = initialProcessName == Miscellaneous.UnmappedProcessDefaultName
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
    }
}
