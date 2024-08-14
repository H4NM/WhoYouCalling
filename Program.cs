
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Timers;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

//ETW
using Microsoft.Diagnostics.Symbols;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

//FPC
using SharpPcap;
using SharpPcap.LibPcap;
using PacketDotNet;
using WhoYouCalling.Utilities;
using System.Timers;
using System.Security.Cryptography;
using System.Runtime.Intrinsics.Arm;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Numerics;
using System.Globalization;
using System.IO;

namespace WhoYouCalling.Utilities
{
    public static class Output
    {
      
        public static void Print(string message, string type = "")
        {
            string prefix;
            switch (type)
            {
                case "info":
                    prefix = "[*]";
                    break;
                case "warning":
                    prefix = "[!]";
                    break;
                case "error":
                    prefix = "[?]";
                    break;
                case "fatal":
                    prefix = "[!!!]";
                    break;
                case "debug":
                    if (Program.debug) { 
                        prefix = $"[DEBUG]";
                    }
                    else
                    {
                        return;
                    }
                    break;
                default:
                    prefix = "";
                    break;
            }
            Console.WriteLine($"{prefix} {message}");
        }
    }

    public class FileAndFolders
    {
        public void CreateFolder(string folder)
        {
            System.IO.Directory.CreateDirectory(folder);
        }
        public void CreateTextFileListOfStrings(string filePath, List<string> listWithStrings)
        {
            File.WriteAllLines(filePath, listWithStrings);
        }
        public void CreateTextFileString(string filePath, string text)
        {
            File.WriteAllText(filePath, text);
        }
    }

    public class ProcessManager
    {
        public static bool IsProcessRunning(int pid)
        {
            Process[] processlist = Process.GetProcesses();
            foreach (Process activePID in processlist)
            {
                if (pid == activePID.Id)
                {
                    Output.Print($"Provided PID ({pid}) is active on the system", "debug");
                    return true;
                }
            }
            Output.Print($"Unable to find process with pid {pid}", "warning");
            return false;
        }
        public static string GetProcessFileName(int PID)
        {
            Process runningProcess = Process.GetProcessById(PID);
            return Path.GetFileName(runningProcess.MainModule.FileName);
        }
        public void KillProcess(int pid)
        {
            try
            {
                Process process = Process.GetProcessById(pid);

                if (!process.HasExited)
                {
                    Output.Print($"Timer elapsed. Killing the process with PID {pid}", "debug");
                    process.Kill();
                }
            }
            catch (ArgumentException)
            {
                Output.Print($"Process with PID {pid} has already exited.", "debug");
            }
            catch (Exception ex)
            {
                Output.Print($"An error occurred when stopping process when timer expired: {ex.Message}", "error");
            }
        }

        public int StartProcessAndGetId(string executablePath, string arguments = "")
        {
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo(executablePath);

                if (!string.IsNullOrEmpty(arguments))
                {
                    startInfo.Arguments = arguments;
                }

                startInfo.UseShellExecute = true;
                startInfo.Verb = "open";

                Process process = Process.Start(startInfo);

                if (process != null)
                {
                    // Retrieve the PID
                    return process.Id;
                }
                else
                {
                    throw new InvalidOperationException("Failed to start the process.");
                }
            }
            catch (Exception ex)
            {
                Output.Print($"An error occurred: {ex.Message}", "error");
                throw;
            }
        }
    }

    public class BPFFilter
    {
        public Dictionary<string, string> GetBPFFilter(Dictionary<int, HashSet<string>> bpfFilterBasedDict)
        {

            Dictionary<string, string> bpfFilterPerExecutable = new Dictionary<string, string>();

            foreach (KeyValuePair<int, HashSet<string>> entry in bpfFilterBasedDict) //For each Process 
            {
                string executableNameByPID = Program.executableByPIDTable[entry.Key]; //Lookup the executable name
                string executabelNameAndPID = $"{executableNameByPID}-{entry.Key}";
                if (entry.Value.Count == 0) // Check if the executable has any recorded network activity
                {
                    Output.Print($"Not calculating BPFFilter for {executabelNameAndPID}. No recored network activity", "debug");
                    continue;
                }
                List<string> FullBPFlistForProcess = new List<string>();
                foreach (string entryCSV in entry.Value) //For each recorded unique network activity
                {
                    string[] parts = entryCSV.Split(',');

                    string ipVersion = parts[0];
                    string transportProto = parts[1];
                    string dstAddr = parts[2];
                    string dstPort = parts[3];

                    string partialBPFstring = $"({ipVersion} and {transportProto} and dst host {dstAddr} and dst port {dstPort})"; 
                    FullBPFlistForProcess.Add(partialBPFstring);
                }
                string BPFFilter = string.Join(" or ", FullBPFlistForProcess);
                bpfFilterPerExecutable[executabelNameAndPID] = BPFFilter; // Add BPF filter for executable
            }

            if (bpfFilterPerExecutable.Count > 1)
            {
                List<string> tempBPFList = new List<string>();
                foreach (KeyValuePair<string, string> processBPFFilter in bpfFilterPerExecutable)
                {
                    tempBPFList.Add($"({processBPFFilter.Value})");
                }
                bpfFilterPerExecutable[$"All {bpfFilterPerExecutable.Count} processes"] = string.Join(" or ", tempBPFList);
            }

            return bpfFilterPerExecutable;
        }
    }

    public class NetworkPackets
    {

        private static int packetIndex = 0;
        private static int filterPacketIndex = 0;
        private static CaptureFileWriterDevice captureFileWriter;
        private static CaptureFileWriterDevice filteredFileWriter;
        private LibPcapLiveDevice captureDevice;

        public LibPcapLiveDeviceList GetNetworkInterfaces()
        {
            // Retrieve the device list
            var devices = LibPcapLiveDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Output.Print("No network interfaces were found on this machine.", "error");
                return null;
            }
            else
            {
                return devices;
            }
        }

        public static void PrintNetworkInterfaces()
        {
            var devices = LibPcapLiveDeviceList.Instance;
            if (devices.Count < 1)
            {
                Output.Print("No network interfaces were found on this machine.", "error");
                System.Environment.Exit(1);
            }

            int i = 0;
            string deviceMsg;
            foreach (var dev in devices)
            {
                deviceMsg = $"{i}) {dev.Name} {dev.Description}";
                Output.Print(deviceMsg);
                i++;
            }
        }

        public void SetCaptureDevice(LibPcapLiveDevice device)
        {
            captureDevice = device;
        }

        public void StopCapturingNetworkPackets()
        {
            captureDevice.StopCapture();
            captureFileWriter.Close();
        }

        public void CaptureNetworkPacketsToPcap(string pcapFile)
        {
            // Register our handler function to the 'packet arrival' event
            captureDevice.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            Output.Print($"Opening {captureDevice.Name} for reading packets with read timeout of {readTimeoutMilliseconds}", "debug");
            captureDevice.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);

            // open the output file
            Output.Print($"Opening {pcapFile} to write packets to", "debug");
            captureFileWriter = new CaptureFileWriterDevice(pcapFile);
            captureFileWriter.Open(captureDevice);

            Output.Print($"Starting capture process", "debug");
            captureDevice.StartCapture();
        }

        public void FilterNetworkCaptureFile(string BPFFilter, string fullPcapFile, string filteredPcapFile)
        {
            ICaptureDevice capturedDevice;

            try
            {
                Output.Print($"Opening saved packet capture file {fullPcapFile}", "debug");
                capturedDevice = new CaptureFileReaderDevice(fullPcapFile);
                capturedDevice.Open();
            }
            catch (Exception e)
            {
                Output.Print("Caught exception when opening file" + e.ToString(), "error");
                return;
            }

            try
            {
                Output.Print($"Opening new packet capture file {filteredPcapFile} to save filtered packets", "debug");
                filteredFileWriter = new CaptureFileWriterDevice(filteredPcapFile);
                filteredFileWriter.Open();
            }
            catch (Exception e)
            {
                Output.Print("Caught exception when writing to file" + e.ToString(), "error");
                return;
            }
            Output.Print($"Setting BPF filter for reading the saved packets: {BPFFilter}", "debug");
            capturedDevice.Filter = BPFFilter;
            capturedDevice.OnPacketArrival +=
                 new PacketArrivalEventHandler(filter_device_OnPacketArrival);

            var startTime = DateTime.Now;

            Output.Print($"Starting reading packets from {fullPcapFile}", "debug");
            capturedDevice.Capture();

            Output.Print($"Finished reading packets from {fullPcapFile}. Closing read", "debug");
            capturedDevice.Close();
            Output.Print($"Finished writing packets to {filteredPcapFile}", "debug");
            filteredFileWriter.Close();
            var endTime = DateTime.Now;

            var duration = endTime - startTime;
            string performanceMsg = $"Read {filterPacketIndex} packets in {duration.TotalSeconds}s";
            Output.Print(performanceMsg, "info");
        }
        private static void filter_device_OnPacketArrival(object sender, PacketCapture e)
        {
            filterPacketIndex++;
            var rawPacket = e.GetPacket();
            filteredFileWriter.Write(rawPacket);
            //Output.Print($"Captured packets: {filterPacketIndex}", "debug");

        }

        private static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            packetIndex++;
            var rawPacket = e.GetPacket();
            captureFileWriter.Write(rawPacket);
            //Output.Print($"Captured packets: {packetIndex}", "debug");
        }
    }
}

namespace WhoYouCalling
{
    class Program
    {

        private static List<int> trackedChildProcessIds = new List<int>(); // Used for tracking the corresponding executable name to the spawned processes
        public static Dictionary<int, string> executableByPIDTable = new Dictionary<int, string>();
        private static List<string> etwActivityHistory = new List<string>(); // Summary of the network activities made
        private static Dictionary<int, HashSet<string>> bpfFilterBasedActivity = new Dictionary<int, HashSet<string>>();
        private static TraceEventSession kernelSession;
        private static bool mainProcessEnded = false;
        private static bool shutDownMonitoring = false;
        private static string mainExecutableFileName;

        // Arguments
        private static int trackedProcessId;
        private static double processRunTimer;
        private static int networkInterfaceChoice;
        private static string executablePath;
        private static string executableArguments = "";
        private static string outputDirectory;
        private static bool killProcesses = false;
        private static bool trackChildProcesses = false;
        private static bool saveFullPcap = false;
        private static bool noPacketCapture = false;
        public static bool debug = false;

        static void Main(string[] args)
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Output.Print("Please run me as Administrator!", "warning");
                return;
            }

            if (!ValidateProvidedArguments(args)) {
                PrintHelp();
            }

            Console.CancelKeyPress += (sender, e) => // For manual cancellation of application
            {
                shutDownMonitoring = true;
                e.Cancel = true;
            };

            // Instanciate objects
            Utilities.ProcessManager processManager = new Utilities.ProcessManager();
            Utilities.NetworkPackets networkPackets = new Utilities.NetworkPackets();
            Utilities.FileAndFolders fileAndFolders = new Utilities.FileAndFolders();
            Utilities.BPFFilter bpfFIlter = new Utilities.BPFFilter();

            Output.Print("Retrieving executable filename", "debug");
            mainExecutableFileName = GetExecutableFileName(trackedProcessId, executablePath);

            string rootFolderName = GetRunInstanceFolderName(mainExecutableFileName);
            if (!string.IsNullOrEmpty(outputDirectory)) // If catalog to save data is specified
            {
                rootFolderName = $"{outputDirectory}{rootFolderName}";
            }
            Output.Print($"Creating folder {rootFolderName}", "debug");
            fileAndFolders.CreateFolder(rootFolderName);

            string fullPcapFile = @$"{rootFolderName}\{mainExecutableFileName}-Full.pcap";
            string etwHistoryFile = @$"{rootFolderName}\{mainExecutableFileName}-History.txt";

            // Retrieve network interface devices
            LibPcapLiveDeviceList devices = networkPackets.GetNetworkInterfaces();
            if (devices == null)
            {
                Output.Print($"No network devices were found..", "fatal");
                System.Environment.Exit(1);
            }
            using var device = devices[networkInterfaceChoice];
            networkPackets.SetCaptureDevice(device);

            // Create and start thread for capturing packets if enabled
            if (!noPacketCapture) { 
                Thread fpcThread = new Thread(() => networkPackets.CaptureNetworkPacketsToPcap(fullPcapFile));
                Output.Print($"Starting packet capture saved to \"{fullPcapFile}\"", "debug");
                fpcThread.Start();
            }

            // Create and start thread for ETW
            Thread etwThread = new Thread(() => ListenToETW());
            Output.Print("Starting ETW session", "debug");
            etwThread.Start();
   

            if (!string.IsNullOrEmpty(executablePath)) // An executable has been provided
            {
                Thread.Sleep(4000); //Sleep is required to ensure ETW Subscription is timed correctly to capture the execution
                try
                {
                    Output.Print($"Starting executable \"{executablePath}\" with args \"{executableArguments}\"", "debug");
                    trackedProcessId = processManager.StartProcessAndGetId(executablePath, executableArguments);
                    bpfFilterBasedActivity[trackedProcessId] = new HashSet<string> {}; // Add the main executable processname
                    executableByPIDTable.Add(trackedProcessId, mainExecutableFileName);
                    AddActivityToETWHistory(eventType: "process", executable: mainExecutableFileName, execType: "Main", execAction: "started", execPID: trackedProcessId);
                }
                catch (Exception ex)
                {
                    Output.Print($"An error occurred while starting the process: {ex.Message}", "fatal");
                    System.Environment.Exit(1);
                }
            }
            else // PID to an existing process is running
            {
                bpfFilterBasedActivity[trackedProcessId] = new HashSet<string> { }; // Add the main executable processname
                executableByPIDTable.Add(trackedProcessId, mainExecutableFileName);
                AddActivityToETWHistory(eventType: "process", executable: mainExecutableFileName, execType: "Main", execAction: "being listened to", execPID: trackedProcessId);
            }
            if (processRunTimer != 0)
            {
                double processRunTimerInMilliseconds = ConvertToMilliseconds(processRunTimer);
                System.Timers.Timer timer = new System.Timers.Timer(processRunTimerInMilliseconds);
                timer.Elapsed += (sender, e) => TimerShutDownMonitoring(sender, e);
                timer.AutoReset = false;
                Output.Print($"Starting timer set to {processRunTimer} seconds", "debug");
                timer.Start();
            }

            // Run until main proces has ended
            while (true)
            {
                if (shutDownMonitoring)
                {
                    Output.Print($"Monitoring was aborted. Finishing...", "debug");

                    if (processRunTimer != 0 && killProcesses) // If a timer was specified and that processes should be killed
                    {
                        Output.Print($"Killing main process with PID {trackedProcessId}", "debug");
                        processManager.KillProcess(trackedProcessId);
                        foreach (int childPID in trackedChildProcessIds)
                        {
                            Output.Print($"Killing child process with PID {childPID}", "debug");
                            processManager.KillProcess(childPID);
                        }
                    }
                    Output.Print($"Stopping ETW kernel session", "debug");
                    StopKernelSession();
                    if (kernelSession.IsActive)
                    {
                        Output.Print($"Kernel still running...", "warning");
                    }


                    if (!noPacketCapture)
                    {
                        Output.Print($"Stopping packet capture saved to \"{fullPcapFile}\"", "debug");
                        networkPackets.StopCapturingNetworkPackets();

                        Output.Print($"Producing BPF filter", "debug");
                        Dictionary<string, string> computedBPFFilter = bpfFIlter.GetBPFFilter(bpfFilterBasedActivity);

                        foreach (KeyValuePair<string, string> processAndBPFFilter in computedBPFFilter)
                        {
                            if (!string.IsNullOrEmpty(computedBPFFilter[processAndBPFFilter.Key]))
                            {
                                string processFolderInRootFolder = @$"{rootFolderName}\{processAndBPFFilter.Key}";
                                string filteredPcapFile = @$"{processFolderInRootFolder}\{processAndBPFFilter.Key}.pcap";
                                string processBPFFilterTextFile = @$"{processFolderInRootFolder}\{processAndBPFFilter.Key} BPF-Filter.txt";

                                Output.Print($"Creating folder {processFolderInRootFolder}", "debug");
                                fileAndFolders.CreateFolder(processFolderInRootFolder);

                                Output.Print($"Filtering saved pcap \"{fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter \"{computedBPFFilter[processAndBPFFilter.Key]}\"", "debug");
                                networkPackets.FilterNetworkCaptureFile(computedBPFFilter[processAndBPFFilter.Key], fullPcapFile, filteredPcapFile);
                                fileAndFolders.CreateTextFileString(processBPFFilterTextFile, computedBPFFilter[processAndBPFFilter.Key]);
                            }
                            else
                            {
                                Output.Print($"Skipping creating dedicated PCAP file for {processAndBPFFilter.Key}. No recorded BPF filter", "debug");
                            }
                        }

                        // Cleanup 
                        if (!saveFullPcap)
                        {
                            Output.Print($"Deleting full pcap file {fullPcapFile}", "debug");
                            DeleteFullPcapFile(fullPcapFile);
                        }
                    }

                    // Action
                    if (etwActivityHistory.Count > 0)
                    {
                        Output.Print($"Creating ETW history file \"{etwHistoryFile}\"", "debug");
                        fileAndFolders.CreateTextFileListOfStrings(etwHistoryFile, etwActivityHistory);
                    }
                    else
                    {
                        Output.Print($"Not creating ETW history file since no activity was recorded", "warning");
                    }
                    
                    Output.Print($"Done.", "debug");
                    break;
                }
            }
        }
        private static double ConvertToMilliseconds(double providedSeconds)
        {
            TimeSpan timeSpan = TimeSpan.FromSeconds(providedSeconds);
            double milliseconds = timeSpan.TotalMilliseconds;
            return milliseconds;
        }
        private static void PrintHelp()
        {
            string helpText = @"
Usage: WhoYouCalling.exe [options]
Options:
  -e, --executable    : Executes the specified executable.
  -a, --arguments     : Appends arguments contained within quotes to the executable file.
  -f, --fulltracking  : Monitors and tracks the network activity by child processes.
  -s, --savefullpcap  : Does not delete the full pcap thats not filtered.
  -p, --pid           : The running process id to track rather than executing the binary.
  -t, --timer         : The number of seconds the execute binary will run for. Is a double variable so can take floating-point values.
  -k, --killprocesses : Used in conjunction with the timer in which the main process is killed. 
                        If full tracking flag is set, childprocesses are also killed.
  -i, --interface     : The network interface number. Retrievable with the -g/--getinterfaces flag.
  -g, --getinterfaces : Prints the network interface devices with corresponding number (usually 0-10).
  -n, --nopcap        : Skips collecting full packet capture.
  -c, --catalog       : Output directory, full path.
  -h, --help          : Displays this help information.

Examples:
  WhoYouCalling.exe -e calc.exe -f -s --timer 10.5
  WhoYouCalling.exe -p 4351 -n 
";
            Console.WriteLine(helpText);
            System.Environment.Exit(1);
        }

        private static bool ValidateProvidedArguments(string[] args){
            bool executableFlagSet = false;
            bool executableArgsFlagSet = false;
            bool PIDFlagSet = false;
            bool timerFlagSet = false;
            bool networkInterfaceDeviceFlagSet = false;
            bool noPCAPFlagSet = false;
            bool fullTrackFlagSet = false;
            bool saveFullPcapFlagSet = false;
            bool killProcessesFlagSet = false;
            bool outputDirectoryFlagSet = false;

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
                            Output.Print("No arguments specified after -e/--executable flag", "warning");
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
                            Output.Print("No arguments specified after -a/--arguments flag", "warning");
                            return false;
                        }
                    }
                    else if (args[i] == "-f" || args[i] == "--fulltracking") // Track the network activity by child processes
                    {
                        trackChildProcesses = true;
                        fullTrackFlagSet = true;
                    }
                    else if (args[i] == "-k" || args[i] == "--killprocesses") // Track the network activity by child processes
                    {
                        killProcesses = true;
                        killProcessesFlagSet = true;
                    }
                    else if (args[i] == "-s" || args[i] == "--savefullpcap") //Save the full pcap
                    {
                        saveFullPcap = true;
                        saveFullPcapFlagSet = true;
                    }
                    else if (args[i] == "-c" || args[i] == "--catalog") //Save the full pcap
                    {
                        if (i + 1 < args.Length)
                        {
                            string path = args[i + 1];

                            if (Path.IsPathRooted(path) && System.IO.Directory.Exists(path))
                            {
                                outputDirectoryFlagSet = true;
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
                                Output.Print("Provide full path to an existing catalog.", "warning");
                                return false;
                            }
                        }
                        else
                        {
                            Output.Print("No arguments specified after -c/--catalog flag", "warning");
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
                            Output.Print("No arguments specified after -p/--pid flag", "warning");
                            return false;
                        }
                    }
                    else if (args[i] == "-t" || args[i] == "--timer") // Executable run timer
                    {
                        if (i + 1 < args.Length)
                        {
                            if (double.TryParse(args[i + 1], NumberStyles.Any, CultureInfo.InvariantCulture, out processRunTimer))
                            {
                                timerFlagSet = true;
                            }
                            else
                            {
                                Console.WriteLine($"The provided value for timer ({processRunTimer}) is not a valid double", "warning");
                                return false;
                            }
                        }
                        else
                        {
                            Output.Print("No arguments specified after -t/--timer flag", "warning");
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
                            Output.Print("No arguments specified after -i/--interface flag", "warning");
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
                        PrintHelp();
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
                Output.Print("One of -e or -p must be supplied, and not both", "error");
                return false;
            }
            else if (executableArgsFlagSet && !executableFlagSet)
            {
                Output.Print("You need to specify an executable when providing with arguments with -a", "error");
                return false;
            }
            else if (killProcessesFlagSet && !timerFlagSet)
            {
                Output.Print("You need to use the timer (-t/--timer) flag if you want to kill the process.", "error");
                return false;
            }
            else if (killProcessesFlagSet && PIDFlagSet)
            {
                Output.Print("You can only specify -k for killing process that's been started and in conjunction with the -t flag for setting a timer.", "error");
                return false;
            }
            else if (networkInterfaceDeviceFlagSet == noPCAPFlagSet)
            {
                Output.Print("You need to specify a network device interface or specify -n/--nopcap to skip packet capture. Run again with -g to view available network devices", "error");
                return false;
            }

            return true;
        }

        private static void AddActivityToETWHistory(string executable = "N/A",
                                             string execType = "N/A", // Main or child process
                                             string execAction = "started",
                                             string execObject = "N/A",
                                             int execPID = 0,
                                             int parentExecPID = 0,
                                             string eventType = "network",
                                             string ipVersion = "IPv4",
                                             string transportProto = "TCP",
                                             IPAddress dstAddr = null, 
                                             int dstPort = 0)
        {
            string timestamp = DateTime.Now.ToString("HH:mm:ss");
            
            string historyMsg = "";
            if (eventType == "network") // If its a network related actvitiy
            {
                historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) sent a {ipVersion} {transportProto} packet to {dstAddr}:{dstPort}";
                // Create BPF filter objects
                string bpfBasedProto = transportProto.ToLower();
                string bpfBasedIPVersion = "";
                if (ipVersion == "IPv4")
                {
                    bpfBasedIPVersion = "ip";
                }
                else
                {
                    bpfBasedIPVersion = "ip6";
                }
                bpfFilterBasedActivity[execPID].Add($"{bpfBasedIPVersion},{bpfBasedProto},{dstAddr},{dstPort}");
            }
            else if (eventType == "process") // If its a process related activity
            {
                historyMsg = $"{timestamp} - {executable}[{execPID}]({execType}) {execAction}";
            }else if (eventType == "childprocess") // If its a process starting another process
            {
                historyMsg = $"{timestamp} - {executable}[{parentExecPID}]({execType}) {execAction} {execObject}[{execPID}]";
            }
            Output.Print(historyMsg, "debug");
            etwActivityHistory.Add(historyMsg);
        }

        private static void TimerShutDownMonitoring(object source, ElapsedEventArgs e)
        {
            shutDownMonitoring = true;
        }


        

        private static void DeleteFullPcapFile(string fullPcapFile)
        {
            if (File.Exists(fullPcapFile))
            {
                File.Delete(fullPcapFile);
                Output.Print($"Deleted full pcap file {fullPcapFile}", "debug");
            }
            else
            {
                Output.Print("Unable to delete full pcap file. It doesnt exist", "warning");
            }
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
                    Output.Print($"Unable to find active process with pid {trackedProcessId}", "fatal");
                    System.Environment.Exit(1);
                }
            }
            else // When the path to an executable was provided
            {
                executableFileName = Path.GetFileName(executablePath);
            }
            return executableFileName;
        }

        private static string GetRunInstanceFolderName(string executableName)
        {
            string timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            string folderName = $"{executableName}-{timestamp}";
            return folderName;
        }

        private static void ListenToETW()
        {
            using (kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName)) //KernelTraceEventParser
            {
                kernelSession.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.NetworkTCPIP |
                    KernelTraceEventParser.Keywords.Process
                );

                // TcpIpConnect may be used. However, "send" is used to ensure capturing failed TCP handshakes
                kernelSession.Source.Kernel.TcpIpSend += Ipv4TcpStart;
                kernelSession.Source.Kernel.TcpIpSendIPV6 += Ipv6TcpStart;
                kernelSession.Source.Kernel.UdpIpSend += Ipv4UdpIpStart;
                kernelSession.Source.Kernel.UdpIpSendIPV6 += Ipv6UdpIpStart;

                kernelSession.Source.Kernel.ProcessStart += childProcessStarted;
                kernelSession.Source.Kernel.ProcessStop += processStopped;

                kernelSession.Source.Process();
            }
        }
        private static void StopKernelSession()
        {
            kernelSession.Dispose();
        }

        private static void Ipv4TcpStart(TcpIpSendTraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                AddActivityToETWHistory(eventType: "network", 
                                        executable: mainExecutableFileName, 
                                        execPID: data.ProcessID,
                                        execType: "Main", 
                                        ipVersion: "IPv4",
                                        transportProto: "TCP",
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
            else if (trackedChildProcessIds.Contains(data.ProcessID))
            {
                string childExecutable = executableByPIDTable[data.ProcessID];
                AddActivityToETWHistory(eventType: "network",
                                        executable: childExecutable,
                                        execPID: data.ProcessID,
                                        execType: "Child",
                                        ipVersion: "IPv4",
                                        transportProto: "TCP",
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
        }

        private static void Ipv6TcpStart(TcpIpV6SendTraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                AddActivityToETWHistory(eventType: "network",
                                        executable: mainExecutableFileName,
                                        execPID: data.ProcessID,
                                        execType: "Main",
                                        ipVersion: "IPv6",
                                        transportProto: "TCP",
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
            else if (trackedChildProcessIds.Contains(data.ProcessID))
            {
                string childExecutable = executableByPIDTable[data.ProcessID];
                AddActivityToETWHistory(eventType: "network",
                                        executable: childExecutable,
                                        execPID: data.ProcessID,
                                        execType: "Child",
                                        ipVersion: "IPv6",
                                        transportProto: "TCP",
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
        }

        private static void Ipv4UdpIpStart(UdpIpTraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                AddActivityToETWHistory(eventType: "network",
                                        executable: mainExecutableFileName,
                                        execPID: data.ProcessID,
                                        execType: "Main",
                                        ipVersion: "IPv4",
                                        transportProto: "UDP",
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
            else if (trackedChildProcessIds.Contains(data.ProcessID))
            {
                string childExecutable = executableByPIDTable[data.ProcessID];
                AddActivityToETWHistory(eventType: "network",
                                        executable: childExecutable,
                                        execPID: data.ProcessID,
                                        execType: "Child",
                                        ipVersion: "IPv4",
                                        transportProto: "UDP",
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
        }

        private static void Ipv6UdpIpStart(UpdIpV6TraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                AddActivityToETWHistory(eventType: "network",
                                        executable: mainExecutableFileName,
                                        execPID: data.ProcessID,
                                        execType: "Main",
                                        ipVersion: "IPv6",
                                        transportProto: "UDP",
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
            else if (trackedChildProcessIds.Contains(data.ProcessID))
            {
                string childExecutable = executableByPIDTable[data.ProcessID];
                AddActivityToETWHistory(eventType: "network",
                                        executable: childExecutable,
                                        execPID: data.ProcessID,
                                        execType: "Child",
                                        ipVersion: "IPv6",
                                        transportProto: "UDP",
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
        }

        private static void childProcessStarted(ProcessTraceData data) {

            if (trackedProcessId == data.ParentID) //Tracks child processes by main process
            {
                AddActivityToETWHistory(eventType: "childprocess",
                                        executable: mainExecutableFileName,
                                        execType: "Main",
                                        execAction: "started",
                                        execObject: data.ImageFileName,
                                        execPID: data.ProcessID,
                                        parentExecPID: data.ParentID);
                if (trackChildProcesses)
                {
                    trackedChildProcessIds.Add(data.ProcessID);
                    executableByPIDTable.Add(data.ProcessID, data.ImageFileName);

                    bpfFilterBasedActivity[data.ProcessID] = new HashSet<string> { }; // Add child processname

                }
            }
            else if (trackedChildProcessIds.Contains(data.ParentID)) //Tracks child processes by child processes
            {
                string childExecutable = executableByPIDTable[data.ParentID];
                AddActivityToETWHistory(eventType: "childprocess",
                                        executable: childExecutable,
                                        execType: "Child",
                                        execAction: "started",
                                        execObject: data.ImageFileName,
                                        execPID: data.ProcessID,
                                        parentExecPID: data.ParentID);
                if (trackChildProcesses)
                {
                    trackedChildProcessIds.Add(data.ProcessID);
                    executableByPIDTable.Add(data.ProcessID, data.ImageFileName);

                    bpfFilterBasedActivity[data.ProcessID] = new HashSet<string> { }; // Add child processname
                }
            }
        }

        private static void processStopped(ProcessTraceData data) {
            if (trackedProcessId == data.ProcessID) // Main process stopped
            {
                AddActivityToETWHistory(eventType: "process",
                                        executable: data.ImageFileName,
                                        execType: "Main",
                                        execAction: "stopped",
                                        execPID: data.ProcessID);
                mainProcessEnded = true;
            }else if (trackedChildProcessIds.Contains(data.ProcessID)) // Child process stopped
            {
                AddActivityToETWHistory(eventType: "process",
                                        executable: data.ImageFileName,
                                        execType: "Child",
                                        execAction: "stopped",
                                        execPID: data.ProcessID);
                trackedChildProcessIds.Remove(data.ProcessID);  
            }
        }
    }
}