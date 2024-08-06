
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

namespace ApplicationReviewer.Utilities
{ 
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
                Console.WriteLine($"An error occurred: {ex.Message}");
                throw;
            }
        }
    }

    public class EBPFFilter
    {
        public String GetEBPFFilter()
        {
            return "ip";
        }
    }

    public class NetworkPackets
    {
        private static int packetIndex = 0;
        private static CaptureFileWriterDevice captureFileWriter;

        public LibPcapLiveDeviceList GetNetworkInterfaces()
        {
            // Retrieve the device list
            var devices = LibPcapLiveDeviceList.Instance;

            // If no devices were found print an error
            if (devices.Count < 1)
            {
                Console.WriteLine("No devices were found on this machine");
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
            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }
        }

        public void CaptureNetworkPacketsToPcap(LibPcapLiveDevice device, string pcapFile)
        {
            // Register our handler function to the 'packet arrival' event
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(device_OnPacketArrival);

            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;

            device.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, writing to {2}, hit 'Enter' to stop...",
                              device.Name, device.Description,
                              pcapFile);

            // open the output file
            captureFileWriter = new CaptureFileWriterDevice(pcapFile);
            captureFileWriter.Open(device);

            // Start the capturing process
            device.StartCapture();
            Console.ReadLine();

            // Stop the capturing process
            device.StopCapture();

        }

        public void ParseNetworkCaptureFile(string EBPFfilter, string pcapFile)
        {
            Console.WriteLine("Parsing: opening '{0}'", pcapFile);

            ICaptureDevice device;

            try
            {
                // Get an offline device
                device = new CaptureFileReaderDevice(pcapFile);

                // Open the device
                device.Open();
            }
            catch (Exception e)
            {
                Console.WriteLine("Caught exception when opening file" + e.ToString());
                return;
            }

            // Register our handler function to the 'packet arrival' event
            device.Filter = EBPFfilter;
            device.OnPacketArrival +=
                 new PacketArrivalEventHandler(parse_device_OnPacketArrival);

            Console.WriteLine();
            Console.WriteLine
                ("-- Capturing from '{0}', hit 'Ctrl-C' to exit...",
                pcapFile);

            var startTime = DateTime.Now;

            // Start capture 'INFINTE' number of packets
            // This method will return when EOF reached.
            device.Capture();

            // Close the pcap device
            device.Close();
            var endTime = DateTime.Now;
            Console.WriteLine("-- End of file reached.");

            var duration = endTime - startTime;
            Console.WriteLine("Read {0} packets in {1}s", packetIndex, duration.TotalSeconds);
        }
        private static int parsePacketIndex = 0;
        private static void parse_device_OnPacketArrival(object sender, PacketCapture e)
        {
            parsePacketIndex++;

            var rawPacket = e.GetPacket();
            var packet = PacketDotNet.Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

            var ethernetPacket = packet.Extract<EthernetPacket>();
            if (ethernetPacket != null)
            {
                Console.WriteLine("{0} At: {1}:{2}: MAC:{3} -> MAC:{4}",
                                  parsePacketIndex,
                                  e.Header.Timeval.Date.ToString(),
                                  e.Header.Timeval.Date.Millisecond,
                                  ethernetPacket.SourceHardwareAddress,
                                  ethernetPacket.DestinationHardwareAddress);
            }
        }

        private static void device_OnPacketArrival(object sender, PacketCapture e)
        {
            // write the packet to the file
            var rawPacket = e.GetPacket();
            captureFileWriter.Write(rawPacket);
            //Console.WriteLine("Packet dumped to file.");

            var time = e.Header.Timeval.Date;
            var len = e.Data.Length;
            Console.WriteLine("{0}:{1}:{2},{3} Len={4}",
            time.Hour, time.Minute, time.Second, time.Millisecond, len);
        }
    }
}

namespace ApplicationReviewer
{
    class Program
    {

        private static int trackedProcessId;
        private static bool trackChildProcesses = true;
        private static List<int> trackedChildProcessIds = new List<int>();
        private static string pcapFile = "NetworkCapture.pcap";
        private static int networkInterfaceChoice = 4;

        static void Main(string[] args)
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Console.WriteLine("Please run me as Administrator!");
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
            string binaryPath = @"C:\Users\Hannes\Documents\Git\AppReviewer\dist\TestApplication.exe";
            string arguments = ""; // Add any required arguments here


            Utilities.ProcessStarter processStarter = new Utilities.ProcessStarter();
            Utilities.NetworkPackets networkPackets = new Utilities.NetworkPackets();
            Utilities.EBPFFilter ebpfFilter = new Utilities.EBPFFilter();


            LibPcapLiveDeviceList devices = networkPackets.GetNetworkInterfaces();
            networkPackets.PrintNetworkInterfaces(devices);
            using var device = devices[networkInterfaceChoice];

            networkPackets.CaptureNetworkPacketsToPcap(device, pcapFile);

            string EBPFFilter = ebpfFilter.GetEBPFFilter();
            networkPackets.ParseNetworkCaptureFile(EBPFFilter, pcapFile);
            System.Environment.Exit(0);


            Thread etwThread = new Thread(() => ListenToETW());
            etwThread.Start();

            //Sleep is required to ensure ETW Subscription is timed correctly
            Thread.Sleep(2000);

            //Start Listening to ETW
            try
            {
                trackedProcessId = processStarter.StartProcessAndGetId(binaryPath, arguments);
                Console.WriteLine($"Started process with PID: {trackedProcessId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred while starting the process: {ex.Message}");
                return;
            }            
        }

        private static void ListenToETW()
        {
            using (var kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) { kernelSession.Dispose(); };

                kernelSession.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.NetworkTCPIP |
                    KernelTraceEventParser.Keywords.Process
                );

                // TcpIpConnect may be used. However, "send" is used to ensure capturing failed TCP handshakes
                kernelSession.Source.Kernel.TcpIpSend += Ipv4TcpConnectionStart;
                kernelSession.Source.Kernel.TcpIpSendIPV6 += Ipv6TcpConnectionStart;
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
        private static void Ipv4TcpConnectionStart(TcpIpSendTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.Contains(data.ProcessID))
            {
                Console.WriteLine("{0} made a IPv4 TCP connection to {1}:{2}", data.ProcessName, data.daddr, data.dport);
            }
        }

        private static void Ipv6TcpConnectionStart(TcpIpV6SendTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.Contains(data.ProcessID))
            {
                Console.WriteLine("{0} made a IPv6 TCP connection to {1}:{2}", data.ProcessName, data.daddr, data.dport);
            }
        }

        private static void Ipv4UdpIpStart(UdpIpTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.Contains(data.ProcessID))
            {
                Console.WriteLine("{0} sent a IPv4 UDP packet to {1}:{2} with OPCODE {3}", data.ProcessName, data.daddr, data.dport);
            }
        }

        private static void Ipv6UdpIpStart(UpdIpV6TraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.Contains(data.ProcessID))
            {
                Console.WriteLine("{0} sent a IPv6 UDP packet to {1}:{2} with OPCODE {3}", data.ProcessName, data.daddr, data.dport);
            }
        }

        /*
         
        PROCESSES
        
        */
        private static void childProcessStarted(ProcessTraceData data) {
            if (trackedProcessId == data.ParentID || trackedChildProcessIds.Contains(data.ParentID))
            {
                Console.WriteLine("Child process started: {0} with pid: {1}", data.ImageFileName, data.ProcessID);
                if (trackChildProcesses) { 
                    trackedChildProcessIds.Add(data.ProcessID);
                }
            }
            else
            {
                Console.WriteLine("?? process started: {0} with pid: {1}", data.ImageFileName, data.ProcessID);
            }
        }

        private static void processStopped(ProcessTraceData data) {
            if (trackedProcessId == data.ProcessID)
            {
                Console.WriteLine("Stopped main process: {0} with pid: {1}", data.ImageFileName, data.ProcessID);
                System.Environment.Exit(0);
            }else if (trackedChildProcessIds.Contains(data.ProcessID))
            {
                Console.WriteLine("Stopped child process: {0} with pid: {1}", data.ImageFileName, data.ProcessID);
                trackedChildProcessIds.Remove(data.ProcessID);  
            }
        }
    }
}