
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
using ApplicationReviewer.Utilities;

namespace ApplicationReviewer.Utilities
{
    public static class Output
    {
        public static void Debug(bool debug, string message)
        {
            if (debug) { 
                string timestamp = DateTime.Now.ToString("HH:mm:ss");
                Console.WriteLine($"[DEBUG - {timestamp}] {message}");
            }
        }
        public static void Print(string message, string type = "")
        {
            string prefix;
            switch (type)
            {
                case "info":
                    prefix = "[*]";
                    break;
                case "error":
                    prefix = "[!!!]";
                    break;
                default:
                    prefix = "";
                    break;
            }
            Console.WriteLine($"{prefix} {message}");
        }
    }

    public class ProcessStarter
    {
        public int StartProcessAndGetId(string binaryPath, string arguments = "")
        {
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo(binaryPath);

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

        public void PrintNetworkInterfaces(LibPcapLiveDeviceList devices)
        {
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
        }

        public void CaptureNetworkPacketsToPcap(string pcapFile)
        {
            // Register our handler function to the 'packet arrival' event
            captureDevice.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            Output.Debug(Program.debug, $"Opening {captureDevice.Name} for reading packets with read timeout of {readTimeoutMilliseconds}");
            captureDevice.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);

            // open the output file
            Output.Debug(Program.debug, $"Opening {pcapFile} to write packets to");
            captureFileWriter = new CaptureFileWriterDevice(pcapFile);
            captureFileWriter.Open(captureDevice);

            Output.Debug(Program.debug, $"Starting capture process");
            captureDevice.StartCapture();
        }

        public void FilterNetworkCaptureFile(string BPFFilter, string fullPcapFile, string filteredPcapFile)
        {
            ICaptureDevice capturedDevice;

            try
            {
                Output.Debug(Program.debug, $"Opening saved packet capture file {fullPcapFile}");
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
                Output.Debug(Program.debug, $"Opening new packet capture file {filteredPcapFile} to save filtered packets");
                filteredFileWriter = new CaptureFileWriterDevice(filteredPcapFile);
                filteredFileWriter.Open();
            }
            catch (Exception e)
            {
                Output.Print("Caught exception when writing to file" + e.ToString(), "error");
                return;
            }

            Output.Debug(Program.debug, $"Setting BPF filter for reading the saved packets: {BPFFilter}");
            capturedDevice.Filter = BPFFilter;
            capturedDevice.OnPacketArrival +=
                 new PacketArrivalEventHandler(filter_device_OnPacketArrival);

            var startTime = DateTime.Now;

            Output.Debug(Program.debug, $"Starting reading packets from {fullPcapFile}");
            capturedDevice.Capture();

            Output.Debug(Program.debug, $"Finished reading packets from {fullPcapFile}. Closing read");
            capturedDevice.Close();
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
            //Output.Debug(Program.debug, $"Filter packets: {filterPacketIndex}");
        }

        private static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            packetIndex++;
            var rawPacket = e.GetPacket();
            captureFileWriter.Write(rawPacket);
            //Output.Debug(Program.debug, $"Captured packets: {packetIndex}");
        }
    }
}

namespace ApplicationReviewer
{
    class Program
    {

        private static int trackedProcessId;
        private static bool trackChildProcesses = true;
        private static Dictionary<int, string> trackedChildProcessIds = new Dictionary<int, string>();
        private static string filteredPcapFile = "C:\\Users\\Hannes\\Documents\\Git\\WhoYouCalling\\Caps\\NetworkCapture-Filtered.pcap";
        private static string fullPcapFile = "C:\\Users\\Hannes\\Documents\\Git\\WhoYouCalling\\Caps\\NetworkCapture-Full.pcap";
        private static int networkInterfaceChoice = 4;
        private static bool mainProcessEnded = false;
        private static string binaryPath = @"C:\Users\Hannes\Documents\Git\WhoYouCalling\dist\TestApplication.exe";
        private static string arguments = ""; // Add any required arguments here
        private static TraceEventSession kernelSession;
        public static bool debug = true;

        static void Main(string[] args)
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Output.Print("Please run me as Administrator!", "info");
                return;
            }
            /*if (args.Length != 1)
            {
                Console.WriteLine("Uppge namn på process att övervaka");
                return;
            }
            Console.WriteLine("[{0}]", string.Join(", ", args));
            */

            //string binaryPath = @"C:\Program Files (x86)\Steam\steam.exe";
            //string binaryPath = @"C:\Program Files(x86)\Steam\steamapps\common\SongsOfConquest\SongsOfConquest.exe";

            // Instanciate objects
            Utilities.ProcessStarter processStarter = new Utilities.ProcessStarter();
            Utilities.NetworkPackets networkPackets = new Utilities.NetworkPackets();
            Utilities.BPFFilter bpfFIlter = new Utilities.BPFFilter();

            //Get network information
            LibPcapLiveDeviceList devices = networkPackets.GetNetworkInterfaces();
            //networkPackets.PrintNetworkInterfaces(devices);
            using var device = devices[networkInterfaceChoice];
            networkPackets.SetCaptureDevice(device);

            //Start capturing packets and start ETW listener
            Output.Debug(debug, $"Starting packet capture saved to \"{fullPcapFile}\"");
            Thread fpcThread = new Thread(() => networkPackets.CaptureNetworkPacketsToPcap(fullPcapFile));
            Output.Debug(debug, "Starting ETW session");
            Thread etwThread = new Thread(() => ListenToETW());
            etwThread.Start();
            fpcThread.Start();
            Thread.Sleep(2000); //Sleep is required to ensure ETW Subscription is timed correctly

            try
            {
                Output.Debug(debug, $"Starting executable \"{binaryPath}\" with args \"{arguments}\"");
                trackedProcessId = processStarter.StartProcessAndGetId(binaryPath, arguments);
                Output.Print($"Started {binaryPath}", "info");
            }
            catch (Exception ex)
            {
                Output.Print($"An error occurred while starting the process: {ex.Message}", "error");
                return;
            }

            while (true)
            {
                if (mainProcessEnded) {
                    Output.Debug(debug, $"{binaryPath} process with PID {trackedProcessId} stopped. Finishing...");
                    Output.Debug(debug, $"Stopping ETW kernel session");
                    StopKernelSession();
                    if (kernelSession.IsActive)
                    {
                        Output.Debug(debug, $"Kernel still running...");
                    }
                    Output.Debug(debug, $"Stopping packet capture saved to \"{fullPcapFile}\"");
                    networkPackets.StopCapturingNetworkPackets();
                    Output.Debug(debug, $"Producing BPF filter");
                    string computedBPFFilter = bpfFIlter.GetBPFFilter();
                    Output.Debug(debug, $"Filtering saved pcap \"{fullPcapFile}\" to \"{filteredPcapFile}\" using BPF filter \"{computedBPFFilter}\"");
                    networkPackets.FilterNetworkCaptureFile(computedBPFFilter, fullPcapFile, filteredPcapFile);
                    Output.Debug(debug, $"Done.");
                    break;
                }
            }

            
        }
        private static void StopKernelSession()
        {
            kernelSession.Dispose();
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

        /*
         
        NETWORK 
        
        */
        private static void Ipv4TcpStart(TcpIpSendTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Output.Debug(Program.debug, $"{data.ProcessName} sent a IPv4 TCP packet {data.daddr}:{data.dport}"); //Replace with debug and use statistic print instead
            }
        }

        private static void Ipv6TcpStart(TcpIpV6SendTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Output.Debug(Program.debug, $"{data.ProcessName} sent a IPv6 TCP packet to {data.daddr}:{data.dport}"); //Replace with debug and use statistic print instead
            }
        }

        private static void Ipv4UdpIpStart(UdpIpTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Output.Debug(Program.debug, $"{data.ProcessName} sent a IPv4 UDP packet to {data.daddr}:{data.dport}"); //Replace with debug and use statistic print instead
            }
        }

        private static void Ipv6UdpIpStart(UpdIpV6TraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Output.Debug(Program.debug, $"{data.ProcessName} sent a IPv6 UDP packet to {data.daddr}:{data.dport}"); //Replace with debug and use statistic print instead
            }
        }

        /*
         
        PROCESSES
        
        */
        private static void childProcessStarted(ProcessTraceData data) {
            if (trackedProcessId == data.ParentID || trackedChildProcessIds.ContainsKey(data.ParentID))
            {
                Output.Debug(Program.debug, $"Child process started: {data.ImageFileName} with PID {data.ProcessID} and arguments: {data.CommandLine}"); //Replace with debug and use statistic print instead
                if (trackChildProcesses) { 
                    trackedChildProcessIds.Add(data.ProcessID, data.ImageFileName);
                }
            }
        }

        private static void processStopped(ProcessTraceData data) {
            if (trackedProcessId == data.ProcessID)
            {
                Output.Debug(Program.debug, $"Stopped main process: {data.ImageFileName} with PID {data.ProcessID}"); //Replace with debug and use statistic print instead
                mainProcessEnded = true;
            }else if (trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Output.Debug(Program.debug, $"Stopped child process: {data.ImageFileName} with PID {data.ProcessID}"); //Replace with debug and use statistic print instead
                trackedChildProcessIds.Remove(data.ProcessID);  
            }
        }
    }
}