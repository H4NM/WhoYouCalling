
using System;
using System.Collections.Generic;
using System.Diagnostics;
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
                    prefix = "[!!!]";
                    break;
                case "debug":
                    if (Program.debug) { 
                        string timestamp = DateTime.Now.ToString("HH:mm:ss");
                        prefix = $"[DEBUG - {timestamp}]";
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
        public void CreateFile()
        {

        }
    }

    public class ProcessStarter
    {
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
        public String GetBPFFilter()
        {
            return "tcp and (dst port 80 or dst port 8080 or dst port 443)";
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
            //Output.Print(Program.debug, $"Filter packets: {filterPacketIndex}");
        }

        private static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            packetIndex++;
            var rawPacket = e.GetPacket();
            captureFileWriter.Write(rawPacket);
            //Output.Print(Program.debug, $"Captured packets: {packetIndex}");
        }
    }
}

namespace WhoYouCalling
{
    class Program
    {

        private static Dictionary<int, string> trackedChildProcessIds = new Dictionary<int, string>();
        private static TraceEventSession kernelSession;
        private static bool mainProcessEnded = false;

        // Arguments
        private static int trackedProcessId;
        private static int processRunTimer;
        private static int networkInterfaceChoice;
        private static string executablePath;
        private static string executableArguments = "";
        private static bool trackChildProcesses = false;
        private static bool saveFullPcap = false;
        public static bool debug = false;

        static void Main(string[] args)
        {
            Console.ReadLine();
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Output.Print("Please run me as Administrator!", "error");
                return;
            }
            if (!ValidateProvidedArguments(args)) {
                PrintHelp();
            }

            // Instanciate objects
            Utilities.ProcessStarter processStarter = new Utilities.ProcessStarter();
            Utilities.NetworkPackets networkPackets = new Utilities.NetworkPackets();
            Utilities.FileAndFolders fileAndFolders = new Utilities.FileAndFolders();
            Utilities.BPFFilter bpfFIlter = new Utilities.BPFFilter();

            string executableFileName = Path.GetFileName(executablePath);
            string rootFolderName = GetRunInstanceFolderName(executableFileName);

            Output.Print($"Creating folder {rootFolderName}", "debug");
            fileAndFolders.CreateFolder(rootFolderName);

            string fullPcapFile = $"{rootFolderName}\\{executableFileName}-Full.pcap";
            string filteredPcapFile = $"{rootFolderName}\\{executableFileName}-Filtered.pcap";

            LibPcapLiveDeviceList devices = networkPackets.GetNetworkInterfaces();
            if (devices == null)
            {
                System.Environment.Exit(1);
            }
            using var device = devices[networkInterfaceChoice];
            networkPackets.SetCaptureDevice(device);

            //Start capturing packets and start ETW listener
            Output.Print($"Starting packet capture saved to \"{fullPcapFile}\"", "debug");
            Thread fpcThread = new Thread(() => networkPackets.CaptureNetworkPacketsToPcap(fullPcapFile));
            Output.Print("Starting ETW session", "debug");
            Thread etwThread = new Thread(() => ListenToETW());
            etwThread.Start();
            fpcThread.Start();
            Thread.Sleep(2000); //Sleep is required to ensure ETW Subscription is timed correctly

            try
            {
                Output.Print($"Starting executable \"{executablePath}\" with args \"{executableArguments}\"", "info");
                trackedProcessId = processStarter.StartProcessAndGetId(executablePath, executableArguments);
            }
            catch (Exception ex)
            {
                Output.Print($"An error occurred while starting the process: {ex.Message}", "error");
                return;
            }

            while (true)
            {
                if (mainProcessEnded) {
                    Output.Print($"{executablePath} process with PID {trackedProcessId} stopped. Finishing...", "debug");
                    Output.Print($"Stopping ETW kernel session", "debug");
                    StopKernelSession();
                    if (kernelSession.IsActive)
                    {
                        Output.Print($"Kernel still running...", "warning");
                    }
                    Output.Print($"Stopping packet capture saved to \"{fullPcapFile}\"", "debug");
                    networkPackets.StopCapturingNetworkPackets();
                    Output.Print($"Producing BPF filter", "debug");
                    string computedBPFFilter = bpfFIlter.GetBPFFilter();
                    Output.Print($"Filtering saved pcap \"{fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter \"{computedBPFFilter}\"", "debug");
                    networkPackets.FilterNetworkCaptureFile(computedBPFFilter, fullPcapFile, filteredPcapFile);
                    Output.Print($"Done.", "debug");
                    break;
                }
            }


        }

        private static void PrintHelp()
        {
            string helpText = @"
Usage: WhoYouCalling.exe [options]
Options:
  -e, --executable    : Executes the specified executable.
  -a, --arguments     : Processes the provided number.
  -f, --fulltracking  : 
  -s, --savefullpcap  : 
  -p, --pid           : 
  -t, --timer         : 
  -i, --interface     : 
  -g, --getinterfaces : 
  -h, --help          : Displays this help information.

Examples:
  MyApp.exe -e calc.exe
  MyApp.exe -n 42
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
            bool fullTrackFlagSet = false;
            bool saveFullPcapFlagSet = false;

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
                            Output.Print("No arguments specified after -e/--executable flag", "error");
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
                            Output.Print("No arguments specified after -a/--arguments flag", "error");
                            return false;
                        }
                    }
                    else if (args[i] == "-f" || args[i] == "--fulltracking") // Track the network activity by child processes
                    {
                        trackChildProcesses = true;
                        fullTrackFlagSet = true;
                    }
                    else if (args[i] == "-s" || args[i] == "--savefullpcap") //Save the full pcap
                    {
                        saveFullPcap = true;
                        saveFullPcapFlagSet = true;
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
                                Console.WriteLine($"The provided value for PID ({trackedProcessId}) is not a valid integer", "error");
                                return false;
                            }
                        }
                        else
                        {
                            Output.Print("No arguments specified after -p/--pid flag", "error");
                            return false;
                        }
                    }
                    else if (args[i] == "-t" || args[i] == "--timer") // Executable run timer
                    {
                        if (i + 1 < args.Length)
                        {
                            if (int.TryParse(args[i + 1], out processRunTimer))
                            {
                                timerFlagSet = true;
                            }
                            else
                            {
                                Console.WriteLine($"The provided value for timer ({processRunTimer}) is not a valid integer", "error");
                                return false;
                            }
                        }
                        else
                        {
                            Output.Print("No arguments specified after -t/--timer flag", "error");
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
                                Console.WriteLine($"The provided value for network device ({networkInterfaceChoice}) is not a valid integer", "error");
                                return false;
                            }
                        }
                        else
                        {
                            Output.Print("No arguments specified after -i/--interface flag", "error");
                            return false;
                        }
                    }

                    else if (args[i] == "-g" || args[i] == "--getinterfaces") //Print available interfaces
                    {
                        NetworkPackets.PrintNetworkInterfaces();
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
                Output.Print("No arguments were provided.");
                return false;
            }

            // Review combination of flags
            return false;
        }

        private static string GetRunInstanceFolderName(string executableName)
        {
            string timestamp = DateTime.Now.ToString("HHmmss");
            string folderName = $"{executableName}-{timestamp}";
            return folderName;

        }

        private static void ListenToETW()
        {
            using (kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
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
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Output.Print($"{data.ProcessName} sent a IPv4 TCP packet {data.daddr}:{data.dport}", "debug"); //Replace with debug and use statistic print instead
            }
        }

        private static void Ipv6TcpStart(TcpIpV6SendTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Output.Print($"{data.ProcessName} sent a IPv6 TCP packet to {data.daddr}:{data.dport}", "debug"); //Replace with debug and use statistic print instead
            }
        }

        private static void Ipv4UdpIpStart(UdpIpTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Output.Print($"{data.ProcessName} sent a IPv4 UDP packet to {data.daddr}:{data.dport}", "debug"); //Replace with debug and use statistic print instead
            }
        }

        private static void Ipv6UdpIpStart(UpdIpV6TraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Output.Print($"{data.ProcessName} sent a IPv6 UDP packet to {data.daddr}:{data.dport}", "debug"); //Replace with debug and use statistic print instead
            }
        }

        private static void childProcessStarted(ProcessTraceData data) {
            if (trackedProcessId == data.ParentID || trackedChildProcessIds.ContainsKey(data.ParentID))
            {
                Output.Print($"Child process started: {data.ImageFileName} with PID {data.ProcessID} and arguments: {data.CommandLine}", "debug"); //Replace with debug and use statistic print instead
                if (trackChildProcesses) { 
                    trackedChildProcessIds.Add(data.ProcessID, data.ImageFileName);
                }
            }
        }

        private static void processStopped(ProcessTraceData data) {
            if (trackedProcessId == data.ProcessID)
            {
                Output.Print($"Stopped main process: {data.ImageFileName} with PID {data.ProcessID}", "debug"); //Replace with debug and use statistic print instead
                mainProcessEnded = true;
            }else if (trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Output.Print($"Stopped child process: {data.ImageFileName} with PID {data.ProcessID}", "debug"); //Replace with debug and use statistic print instead
                trackedChildProcessIds.Remove(data.ProcessID);  
            }
        }
    }
}