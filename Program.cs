
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing;
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
using Microsoft.Diagnostics.Tracing.Parsers.ClrPrivate;
using System.Collections;
using System.Text.Json;

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
                    prefix = "[i]";
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

    public static class FileAndFolders
    {
        public static void CreateFolder(string folder)
        {
            System.IO.Directory.CreateDirectory(folder);
        }
        public static void CreateTextFileListOfStrings(string filePath, List<string> listWithStrings)
        {
            File.WriteAllLines(filePath, listWithStrings);
        }
        public static void CreateTextFileString(string filePath, string text)
        {
            File.WriteAllText(filePath, text);
        }
    }
    public class MonitoredProcess
    {
        public string imageName { get; set; }
        public List<int> childprocess { get; set; } = new List<int>();
        public HashSet<string> dnsQueries { get; set; } = new HashSet<string>();
        public HashSet<string> ipv4TCPEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> ipv6TCPEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> ipv4UDPEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> ipv6UDPEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> ipv4LocalhostEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> ipv6LocalhostEndpoint { get; set; } = new HashSet<string>();

    }

    public static class ProcessManager
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
        public static void KillProcess(int pid)
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

        public static int StartProcessAndGetId(string executablePath, string arguments = "")
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

    public static class BPFFilter
    {
        public static Dictionary<int, string> GetBPFFilter(Dictionary<int, HashSet<string>> bpfFilterBasedDict)
        {

            Dictionary<int, string> bpfFilterPerExecutable = new Dictionary<int, string>();

            foreach (KeyValuePair<int, HashSet<string>> entry in bpfFilterBasedDict) //For each Process 
            {
                if (entry.Value.Count == 0) // Check if the executable has any recorded network activity
                {
                    Output.Print($"Not calculating BPFFilter for PID {entry.Key}. No recored network activity", "debug");
                    continue;
                }
                List<string> FullBPFlistForProcess = new List<string>();
                foreach (string entryCSV in entry.Value) //For each recorded unique network activity
                {
                    string[] parts = entryCSV.Split(',');

                    string ipVersion = parts[0];
                    string transportProto = parts[1];
                    string srcAddr = parts[2];
                    string srcPort = parts[3];
                    string dstAddr = parts[4];
                    string dstPort = parts[5];

                    string partialBPFstring = $"({ipVersion} and {transportProto} and ((host {srcAddr} and host {dstAddr}) and ((dst port {dstPort} and src port {srcPort}) or (dst port {srcPort} and src port {dstPort}))))"; 
                    FullBPFlistForProcess.Add(partialBPFstring);
                }
                string BPFFilter = string.Join(" or ", FullBPFlistForProcess);
                bpfFilterPerExecutable[entry.Key] = BPFFilter; // Add BPF filter for executable
            }

            if (bpfFilterPerExecutable.Count > 1)
            {
                List<string> tempBPFList = new List<string>();
                foreach (KeyValuePair<int, string> processBPFFilter in bpfFilterPerExecutable)
                {
                    tempBPFList.Add($"({processBPFFilter.Value})");
                }
                bpfFilterPerExecutable[0] = string.Join(" or ", tempBPFList); //0 is the combined PID number for all
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
        private static List<string> etwActivityHistory = new List<string>(); // Summary of the network activities made
        private static Dictionary<int, HashSet<string>> bpfFilterBasedActivity = new Dictionary<int, HashSet<string>>();
        private static Dictionary<int, MonitoredProcess> collectiveProcessInfo = new Dictionary<int, MonitoredProcess>();

        private static TraceEventSession kernelSession;
        private static TraceEventSession dnsClientSession;
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
        private static bool dumpResultsToJson = false;
        public static bool debug = false;

        static void Main(string[] args)
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Output.Print("Please run me as Administrator!", "warning");
                return;
            }

            if (!ValidateProvidedArguments(args)) {
                PrintHeader();
                PrintHelp();
            }

            Console.CancelKeyPress += (sender, e) => // For manual cancellation of application
            {
                shutDownMonitoring = true;
                e.Cancel = true;
            };

            Console.Clear();
            PrintHeader();

            Utilities.NetworkPackets networkPackets = new Utilities.NetworkPackets();
       
            Output.Print("Retrieving executable filename", "debug");
            mainExecutableFileName = GetExecutableFileName(trackedProcessId, executablePath);

            string rootFolderName = GetRunInstanceFolderName(mainExecutableFileName);
            if (!string.IsNullOrEmpty(outputDirectory)) // If catalog to save data is specified
            {
                rootFolderName = $"{outputDirectory}{rootFolderName}";
            }
            Output.Print($"Creating folder {rootFolderName}", "debug");
            FileAndFolders.CreateFolder(rootFolderName);

            string fullPcapFile = @$"{rootFolderName}\{mainExecutableFileName}-Full.pcap";
            string etwHistoryFile = @$"{rootFolderName}\{mainExecutableFileName}-History.txt";
            string jsonResultsFile = @$"{rootFolderName}\{mainExecutableFileName}-Results.json";

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

            // Create and start threads for ETW. Had to make two separate functions for a dedicated thread for interoperability
            Thread etwKernelThread = new Thread(() => ListenToETWKernel());
            Thread etwDNSClientThread = new Thread(() => ListenToETWDNSClient());

            Output.Print("Starting ETW sessions", "debug");
            etwKernelThread.Start();
            etwDNSClientThread.Start();



            if (!string.IsNullOrEmpty(executablePath)) // An executable path has been provided and will be executed
            {
                Thread.Sleep(3000); //Sleep is required to ensure ETW Subscription is timed correctly to capture the execution
                try
                {
                    Output.Print($"Starting executable \"{executablePath}\" with args \"{executableArguments}\"", "debug");
                    trackedProcessId = ProcessManager.StartProcessAndGetId(executablePath, executableArguments);
                    CatalogETWActivity(eventType: "process", executable: mainExecutableFileName, execType: "Main", execAction: "started", execPID: trackedProcessId);
                }
                catch (Exception ex)
                {
                    Output.Print($"An error occurred while starting the process: {ex.Message}", "fatal");
                    System.Environment.Exit(1);
                }
            }
            else // PID to an existing process is running
            {
                CatalogETWActivity(eventType: "process", executable: mainExecutableFileName, execType: "Main", execAction: "being listened to", execPID: trackedProcessId);
            }

            InstantiateProcessVariables(pid: trackedProcessId, executable: mainExecutableFileName);

            if (processRunTimer != 0)
            {
                double processRunTimerInMilliseconds = ConvertToMilliseconds(processRunTimer);
                System.Timers.Timer timer = new System.Timers.Timer(processRunTimerInMilliseconds);
                timer.Elapsed += (sender, e) => TimerShutDownMonitoring(sender, e);
                timer.AutoReset = false;
                Output.Print($"Starting timer set to {processRunTimer} seconds", "debug");
                timer.Start();
            }



            while (true) // Continue monitoring 
            {
                if (shutDownMonitoring) // If shutdown monitoring is true, finish last actions with cleanup and generate data
                {
                    Output.Print($"Monitoring was aborted. Finishing...", "debug");
                    if (processRunTimer != 0 && killProcesses) // If a timer was specified and that processes should be killed
                    {
                        Output.Print($"Killing main process with PID {trackedProcessId}", "debug");
                        ProcessManager.KillProcess(trackedProcessId);
                        foreach (int childPID in trackedChildProcessIds)
                        {
                            Output.Print($"Killing child process with PID {childPID}", "debug");
                            ProcessManager.KillProcess(childPID);
                        }
                    }
                    Output.Print($"Stopping ETW sessions", "debug");
                    StopKernelETWSession();
                    StopDnsClientSession();
                    if (kernelSession.IsActive)
                    {
                        Output.Print($"Kernel ETW session still running...", "warning");
                    }else if (dnsClientSession.IsActive)
                    {
                        Output.Print($"DNS Client ETW session still running...", "warning");
                    }
                    else
                    {
                        Output.Print($"Successfully stopped ETW sessions", "debug");
                    }

                    Dictionary<int, string> computedBPFFilterByPID = new Dictionary<int, string>();

                    if (!noPacketCapture)
                    {
                        Output.Print($"Stopping packet capture saved to \"{fullPcapFile}\"", "debug");
                        networkPackets.StopCapturingNetworkPackets();

                        Output.Print($"Producing BPF filter", "debug");
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

                        Output.Print($"Creating folder {processFolderInRootFolder}", "debug");
                        FileAndFolders.CreateFolder(processFolderInRootFolder);


                        // DNS
                        if (monitoredProcess.dnsQueries.Count() > 0)
                        {
                            string dnsQueriesFile = @$"{processFolderInRootFolder}\DNS queries.txt";

                            List<string> dnsQueries = monitoredProcess.dnsQueries.ToList(); // Convert to list from hashset to be able to pass to function
                            Output.Print($"Creating file {dnsQueriesFile} with all DNS queries", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(dnsQueriesFile, dnsQueries);
                        }
                        else
                        {
                            Output.Print($"Not creating DNS queries file, none found for {pid}", "debug");
                        }

                        // TCP IPv4
                        if (monitoredProcess.ipv4TCPEndpoint.Count > 0) 
                        {
                            string tcpIPv4File = @$"{processFolderInRootFolder}\IPv4 TCP Endpoints.txt";
                            List<string> tcpIPv4Endpoints = monitoredProcess.ipv4TCPEndpoint.ToList(); // Convert to list from hashset to be able to pass to function
                            Output.Print($"Creating file {tcpIPv4File} with TCP IPv4 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(tcpIPv4File, tcpIPv4Endpoints);
                        }
                        else
                        {
                            Output.Print($"Not creating TCP IPv4 communication file, none found for {pid}", "debug");
                        }

                        // TCP IPv6
                        if (monitoredProcess.ipv6TCPEndpoint.Count > 0)
                        {
                            string tcpIPv6File = @$"{processFolderInRootFolder}\IPv6 TCP Endpoints.txt";
                            List<string> tcpIPv6Endpoints = monitoredProcess.ipv6TCPEndpoint.ToList(); // Convert to list from hashset to be able to pass to function
                            Output.Print($"Creating file {tcpIPv6File} with TCP IPv6 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(tcpIPv6File, tcpIPv6Endpoints);
                        }
                        else
                        {
                            Output.Print($"Not creating TCP IPv6 communication file, none found for {pid}", "debug");
                        }

                        // UDP IPv4
                        if (monitoredProcess.ipv4UDPEndpoint.Count > 0)
                        {
                            string udpIPv4File = @$"{processFolderInRootFolder}\IPv4 UDP Endpoints.txt";
                            List<string> udpIPv4Endpoints = monitoredProcess.ipv4UDPEndpoint.ToList(); // Convert to list from hashset to be able to pass to function
                            Output.Print($"Creating file {udpIPv4File} with UDP IPv4 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(udpIPv4File, udpIPv4Endpoints);
                        }
                        else
                        {
                            Output.Print($"Not creating UDP IPv4 communication file, none found for {pid}", "debug");
                        }
                        // UDP IPv6
                        if (monitoredProcess.ipv6UDPEndpoint.Count > 0)
                        {
                            string udpIPv6File = @$"{processFolderInRootFolder}\IPv6 UDP Endpoints.txt";
                            List<string> udpIPv6Endpoints = monitoredProcess.ipv6UDPEndpoint.ToList(); // Convert to list from hashset to be able to pass to function
                            Output.Print($"Creating file {udpIPv6File} with UDP IPv6 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(udpIPv6File, udpIPv6Endpoints);
                        }
                        else
                        {
                            Output.Print($"Not creating UDP IPv6 communication file, none found for {pid}", "debug");
                        }
                        // Localhost IPv4 - Takes both TCP UDP
                        if (monitoredProcess.ipv4LocalhostEndpoint.Count > 0)
                        {
                            string localhostIPv4File = @$"{processFolderInRootFolder}\Localhost Endpoints.txt";
                            List<string> localhostIPv4Endpoints = monitoredProcess.ipv4LocalhostEndpoint.ToList(); // Convert to list from hashset to be able to pass to function
                            Output.Print($"Creating file {localhostIPv4File} with localhost IPv4 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(localhostIPv4File, localhostIPv4Endpoints);
                        }
                        else
                        {
                            Output.Print($"Not creating localhost IPv4 communication file, none found for {pid}", "debug");
                        }
                        // Localhost IPv6 - Takes both TCP UDP
                        if (monitoredProcess.ipv6LocalhostEndpoint.Count > 0)
                        {
                            string localhostIPv6File = @$"{processFolderInRootFolder}\Localhost Endpoints IPv6.txt";
                            List<string> localhostIPv6Endpoints = monitoredProcess.ipv6LocalhostEndpoint.ToList(); // Convert to list from hashset to be able to pass to function
                            Output.Print($"Creating file {localhostIPv6File} with localhost IPv6 communication", "debug");
                            FileAndFolders.CreateTextFileListOfStrings(localhostIPv6File, localhostIPv6Endpoints);
                        }
                        else
                        {
                            Output.Print($"Not creating localhost IPv6 communication file, none found for {pid}", "debug");
                        }

                        // FPC 
                        if (computedBPFFilterByPID.ContainsKey(pid)) // Creating filtered FPC based on application activity
                        {

                            string filteredPcapFile = @$"{processFolderInRootFolder}\{executabelNameAndPID}.pcap";
                            string processBPFFilterTextFile = @$"{processFolderInRootFolder}\{executabelNameAndPID} BPF-Filter.txt";

                            Output.Print($"Filtering saved pcap \"{fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter \"{computedBPFFilterByPID[pid]}\"", "debug");
                            networkPackets.FilterNetworkCaptureFile(computedBPFFilterByPID[pid], fullPcapFile, filteredPcapFile);
                            FileAndFolders.CreateTextFileString(processBPFFilterTextFile, computedBPFFilterByPID[pid]); // Create textfile containing used BPF filter
                        }
                        else if (computedBPFFilterByPID.ContainsKey(combinedBPFprocid)) // 0 represents the combined BPF filter for all applications
                        {
                            string filteredPcapFile = @$"{rootFolderName}\All {computedBPFFilterByPID.Count} processes filter.pcap";
                            string processBPFFilterTextFile = @$"{rootFolderName}\All {computedBPFFilterByPID.Count} processes filter.txt";

                            Output.Print($"Filtering saved pcap \"{fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter \"{computedBPFFilterByPID[combinedBPFprocid]}\"", "debug");

                            networkPackets.FilterNetworkCaptureFile(computedBPFFilterByPID[combinedBPFprocid], fullPcapFile, filteredPcapFile);
                            FileAndFolders.CreateTextFileString(processBPFFilterTextFile, computedBPFFilterByPID[combinedBPFprocid]); // Create textfile containing used BPF filter
                        }
                        else
                        {
                            Output.Print($"Skipping creating dedicated PCAP file for {executable}. No recorded BPF filter", "debug");
                        }

                    }

                    // Cleanup 
                    if (!saveFullPcap)
                    {
                        Output.Print($"Deleting full pcap file {fullPcapFile}", "debug");
                        DeleteFullPcapFile(fullPcapFile);
                    }
                    

                    // Action
                    if (etwActivityHistory.Count > 0)
                    {
                        Output.Print($"Creating ETW history file \"{etwHistoryFile}\"", "debug");
                        FileAndFolders.CreateTextFileListOfStrings(etwHistoryFile, etwActivityHistory);
                    }
                    else
                    {
                        Output.Print($"Not creating ETW history file since no activity was recorded", "warning");
                    }

                    if (dumpResultsToJson)
                    {
                        Output.Print($"Creating json results file \"{jsonResultsFile}\"", "debug");
                        var options = new JsonSerializerOptions { WriteIndented = true };
                        string jsonString = JsonSerializer.Serialize(collectiveProcessInfo, options);
                        File.WriteAllText(jsonResultsFile, jsonString);
                    }
                    else
                    {
                        Output.Print($"Not creating json results file \"{jsonResultsFile}\"", "debug");
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

        private static void PrintHeader()
        {
            string headerText = @" 
                                                                   ?
                                                                   | 
  __      ___      __   __         ___      _ _ _              .===:
  \ \    / / |_  __\ \ / /__ _  _ / __|__ _| | (_)_ _  __ _    |[_]|
   \ \/\/ /| ' \/ _ \ V / _ \ || | (__/ _` | | | | ' \/ _` |   |:::|
    \_/\_/ |_||_\___/|_|\___/\_,_|\___\__,_|_|_|_|_||_\__, |   |:::|
                                                      |___/     \___\
";
            ConsoleColor initialForeground = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(headerText);
            Console.ForegroundColor = initialForeground;
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
  -o, --output        : Output directory, full path.
  -j, --json          : If the process information should be dumped to json file.
  -h, --help          : Displays this help information.

Examples:
  WhoYouCalling.exe -e C:\Windows\System32\calc.exe -f -t 10.5 -k -i 8 -o C:\Users\H4NM\Desktop 
  WhoYouCalling.exe --pid 4351 --nopcap --fulltracking --output C:\Windows\Temp 
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
            bool jsonFlagSet = false;

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
                    else if (args[i] == "-j" || args[i] == "--json") //Save the full pcap
                    {
                        dumpResultsToJson = true;
                        jsonFlagSet = true;
                    }
                    else if (args[i] == "-o" || args[i] == "--output") //Save the full pcap
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
                            Output.Print("No arguments specified after -o/--output flag", "warning");
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

        private static void CatalogETWActivity(string executable = "N/A",
                                             string execType = "N/A", // Main or child process
                                             string execAction = "started",
                                             string execObject = "N/A",
                                             int execPID = 0,
                                             int parentExecPID = 0,
                                             string eventType = "network", // process, childprocess, network, dnsquery
                                             string ipVersion = "IPv4",
                                             string transportProto = "TCP",
                                             IPAddress srcAddr = null,
                                             int srcPort = 0,
                                             IPAddress dstAddr = null, 
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

            Output.Print(historyMsg, "debug");
            etwActivityHistory.Add(historyMsg);
        }

        private static void TimerShutDownMonitoring(object source, ElapsedEventArgs e)
        {
            shutDownMonitoring = true;
            Output.Print($"Timer finished!", "debug");
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

        private static void InstantiateProcessVariables(int pid, string executable)
        {
            collectiveProcessInfo[pid] = new MonitoredProcess
            {
                imageName = executable
            };
            bpfFilterBasedActivity[pid] = new HashSet<string>(); // Add the main executable processname
        }

        private static void ListenToETWDNSClient()
        {
            using (dnsClientSession = new TraceEventSession("WhoYouCallingDNSClientSession"))
            {
                dnsClientSession.EnableProvider("Microsoft-Windows-DNS-Client");
                dnsClientSession.Source.Dynamic.All += DnsClientEvent;
                dnsClientSession.Source.Process();
            }

        }
        private static void ListenToETWKernel()
        {
            using (kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName)) //KernelTraceEventParser
            {
                kernelSession.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.NetworkTCPIP |
                    KernelTraceEventParser.Keywords.Process
                );

                // TCP/IP
                kernelSession.Source.Kernel.TcpIpSend += Ipv4TcpStart; // TcpIpConnect may be used. However, "send" is used to ensure capturing failed TCP handshakes
                kernelSession.Source.Kernel.TcpIpSendIPV6 += Ipv6TcpStart;
                kernelSession.Source.Kernel.UdpIpSend += Ipv4UdpIpStart;
                kernelSession.Source.Kernel.UdpIpSendIPV6 += Ipv6UdpIpStart;

                // Process
                kernelSession.Source.Kernel.ProcessStart += childProcessStarted;
                kernelSession.Source.Kernel.ProcessStop += processStopped;

                // Start Kernel ETW session
                kernelSession.Source.Process();
            }
        }
        private static void StopKernelETWSession()
        {
            kernelSession.Dispose();
        }

        private static void StopDnsClientSession()
        {
            dnsClientSession.Dispose();
        }

        private static void DnsClientEvent(TraceEvent data)
        {
            if (trackedProcessId == data.ProcessID && data.EventName == "EventID(3006)") // DNS Lookup made by main tracked PID
            {
                string dnsQuery = data.PayloadByName("QueryName").ToString();
                CatalogETWActivity(eventType: "dnsquery",
                    executable: mainExecutableFileName,
                    execPID: data.ProcessID,
                    execType: "Main",
                    dnsQuery: dnsQuery);
            }
            else if (trackedChildProcessIds.Contains(data.ProcessID) && data.EventName == "EventID(3006)") // DNS Lookup made by child tracked PID
            {
                string childExecutable = collectiveProcessInfo[data.ProcessID].imageName;
                string dnsQuery = data.PayloadByName("QueryName").ToString();

                CatalogETWActivity(eventType: "dnsquery",
                    executable: childExecutable,
                    execPID: data.ProcessID,
                    execType: "Child",
                    dnsQuery: dnsQuery);
            }

            // Data.ProcessID works! 
            // data.FormattedMessage semi works - is entire message - quite dull. Only require action, query and perhaps answer. 
            //Output.Print($"DNS {data.EventName} - {data.FormattedMessage}", "debug");
            //Output.Print($"PAYLOAD {data.PayloadByName("QueryName")}", "debug");
        }

        private static void Ipv4TcpStart(TcpIpSendTraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                CatalogETWActivity(eventType: "network", 
                                        executable: mainExecutableFileName, 
                                        execPID: data.ProcessID,
                                        execType: "Main", 
                                        ipVersion: "IPv4",
                                        transportProto: "TCP",
                                        srcAddr: data.saddr,
                                        srcPort: data.sport,
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
            else if (trackedChildProcessIds.Contains(data.ProcessID))
            {
                string childExecutable = collectiveProcessInfo[data.ProcessID].imageName;
                CatalogETWActivity(eventType: "network",
                                        executable: childExecutable,
                                        execPID: data.ProcessID,
                                        execType: "Child",
                                        ipVersion: "IPv4",
                                        transportProto: "TCP",
                                        srcAddr: data.saddr,
                                        srcPort: data.sport,
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
        }

        private static void Ipv6TcpStart(TcpIpV6SendTraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                CatalogETWActivity(eventType: "network",
                                        executable: mainExecutableFileName,
                                        execPID: data.ProcessID,
                                        execType: "Main",
                                        ipVersion: "IPv6",
                                        transportProto: "TCP",
                                        srcAddr: data.saddr,
                                        srcPort: data.sport,
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
            else if (trackedChildProcessIds.Contains(data.ProcessID))
            {
                string childExecutable = collectiveProcessInfo[data.ProcessID].imageName;
                CatalogETWActivity(eventType: "network",
                                        executable: childExecutable,
                                        execPID: data.ProcessID,
                                        execType: "Child",
                                        ipVersion: "IPv6",
                                        transportProto: "TCP",
                                        srcAddr: data.saddr,
                                        srcPort: data.sport,
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
        }

        private static void Ipv4UdpIpStart(UdpIpTraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                CatalogETWActivity(eventType: "network",
                                        executable: mainExecutableFileName,
                                        execPID: data.ProcessID,
                                        execType: "Main",
                                        ipVersion: "IPv4",
                                        transportProto: "UDP",
                                        srcAddr: data.saddr,
                                        srcPort: data.sport,
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
            else if (trackedChildProcessIds.Contains(data.ProcessID))
            {
                string childExecutable = collectiveProcessInfo[data.ProcessID].imageName;
                CatalogETWActivity(eventType: "network",
                                        executable: childExecutable,
                                        execPID: data.ProcessID,
                                        execType: "Child",
                                        ipVersion: "IPv4",
                                        transportProto: "UDP",
                                        srcAddr: data.saddr,
                                        srcPort: data.sport,
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
        }

        private static void Ipv6UdpIpStart(UpdIpV6TraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                CatalogETWActivity(eventType: "network",
                                        executable: mainExecutableFileName,
                                        execPID: data.ProcessID,
                                        execType: "Main",
                                        ipVersion: "IPv6",
                                        transportProto: "UDP",
                                        srcAddr: data.saddr,
                                        srcPort: data.sport,
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
            else if (trackedChildProcessIds.Contains(data.ProcessID))
            {
                string childExecutable = collectiveProcessInfo[data.ProcessID].imageName;
                CatalogETWActivity(eventType: "network",
                                        executable: childExecutable,
                                        execPID: data.ProcessID,
                                        execType: "Child",
                                        ipVersion: "IPv6",
                                        transportProto: "UDP",
                                        srcAddr: data.saddr,
                                        srcPort: data.sport,
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
        }

        private static void childProcessStarted(ProcessTraceData data) {

            if (trackedProcessId == data.ParentID) //Tracks child processes by main process
            {
                CatalogETWActivity(eventType: "childprocess",
                                        executable: mainExecutableFileName,
                                        execType: "Main",
                                        execAction: "started",
                                        execObject: data.ImageFileName,
                                        execPID: data.ProcessID,
                                        parentExecPID: data.ParentID);
                if (trackChildProcesses)
                {
                    trackedChildProcessIds.Add(data.ProcessID);
                    InstantiateProcessVariables(pid: data.ProcessID, executable: data.ImageFileName);
                }
            }
            else if (trackedChildProcessIds.Contains(data.ParentID)) //Tracks child processes by child processes
            {
                string childExecutable = collectiveProcessInfo[data.ParentID].imageName;
                CatalogETWActivity(eventType: "childprocess",
                                        executable: childExecutable,
                                        execType: "Child",
                                        execAction: "started",
                                        execObject: data.ImageFileName,
                                        execPID: data.ProcessID,
                                        parentExecPID: data.ParentID);
                if (trackChildProcesses)
                {
                    trackedChildProcessIds.Add(data.ProcessID);
                    InstantiateProcessVariables(pid: data.ProcessID, executable: data.ImageFileName);
                }
            }
        }

        private static void processStopped(ProcessTraceData data) {
            if (trackedProcessId == data.ProcessID) // Main process stopped
            {
                CatalogETWActivity(eventType: "process",
                                        executable: data.ImageFileName,
                                        execType: "Main",
                                        execAction: "stopped",
                                        execPID: data.ProcessID);
            }else if (trackedChildProcessIds.Contains(data.ProcessID)) // Child process stopped
            {
                CatalogETWActivity(eventType: "process",
                                        executable: data.ImageFileName,
                                        execType: "Child",
                                        execAction: "stopped",
                                        execPID: data.ProcessID);
                trackedChildProcessIds.Remove(data.ProcessID);  
            }
        }
    }
}