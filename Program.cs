
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

            captureDevice.Open(mode: DeviceModes.Promiscuous | DeviceModes.DataTransferUdp | DeviceModes.NoCaptureLocal, read_timeout: readTimeoutMilliseconds);

            Console.WriteLine();
            Console.WriteLine("-- Listening on {0} {1}, writing to {2}, hit 'Enter' to stop...",
                              captureDevice.Name, captureDevice.Description,
                              pcapFile);

            // open the output file
            captureFileWriter = new CaptureFileWriterDevice(pcapFile);
            captureFileWriter.Open(captureDevice);

            // Start the capturing process
            captureDevice.StartCapture();
            Console.ReadLine();

            // Stop the capturing process
            captureDevice.StopCapture();

        }

        public void FilterNetworkCaptureFile(string BPFFilter, string fullPcapFile, string filteredPcapFile)
        {
            Console.WriteLine("Opening '{0}'", fullPcapFile);

            ICaptureDevice capturedDevice;

            try
            {
                // Get an offline device
                capturedDevice = new CaptureFileReaderDevice(fullPcapFile);
                // Open the device
                capturedDevice.Open();
            }
            catch (Exception e)
            {
                Console.WriteLine("Caught exception when opening file" + e.ToString());
                return;
            }

            try
            {
                filteredFileWriter = new CaptureFileWriterDevice(filteredPcapFile);
                filteredFileWriter.Open();
            }
            catch (Exception e)
            {
                Console.WriteLine("Caught exception when writing to file" + e.ToString());
                return;
            }

            // Register our handler function to the 'packet arrival' event
            capturedDevice.Filter = BPFFilter;
            capturedDevice.OnPacketArrival +=
                 new PacketArrivalEventHandler(filter_device_OnPacketArrival);

            Console.WriteLine();
            Console.WriteLine
                ("-- Capturing from '{0}', hit 'Ctrl-C' to exit...",
                fullPcapFile);

            var startTime = DateTime.Now;

            // Start capture 'INFINTE' number of packets
            // This method will return when EOF reached.
            capturedDevice.Capture();

            // Close the pcap device
            capturedDevice.Close();
            var endTime = DateTime.Now;
            Console.WriteLine("-- End of file reached.");

            var duration = endTime - startTime;
            Console.WriteLine("Read {0} packets in {1}s", filterPacketIndex, duration.TotalSeconds);
        }
        private static void filter_device_OnPacketArrival(object sender, PacketCapture e)
        {
            filterPacketIndex++;

            // write the packet to the file
            var rawPacket = e.GetPacket();
            filteredFileWriter.Write(rawPacket);
            //Console.WriteLine("Packet dumped to file.");

            var time = e.Header.Timeval.Date;
            var len = e.Data.Length;
            Console.WriteLine("{0}:{1}:{2},{3} Len={4}",
            time.Hour, time.Minute, time.Second, time.Millisecond, len);
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
        private static Dictionary<int, string> trackedChildProcessIds = new Dictionary<int, string>();
        private static string filteredPcapFile = "C:\\Users\\Hannes\\Documents\\Git\\WhoYouCalling\\Caps\\NetworkCapture-Filtered.pcap";
        private static string fullPcapFile = "C:\\Users\\Hannes\\Documents\\Git\\WhoYouCalling\\Caps\\NetworkCapture-Full.pcap";
        private static int networkInterfaceChoice = 4;
        private static bool mainProcessEnded = false;
        private static string binaryPath = @"C:\Users\Hannes\Documents\Git\WhoYouCalling\dist\TestApplication.exe";
        private static string arguments = ""; // Add any required arguments here
        private static TraceEventSession kernelSession;

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
            Thread fpcThread = new Thread(() => networkPackets.CaptureNetworkPacketsToPcap(fullPcapFile));
            Thread etwThread = new Thread(() => ListenToETW());
            etwThread.Start();
            fpcThread.Start();
            Thread.Sleep(2000); //Sleep is required to ensure ETW Subscription is timed correctly

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

            while (true)
            {
                if (mainProcessEnded) {
                    StopKernelSession();
                    networkPackets.StopCapturingNetworkPackets();
                    string computedBPFFilter = bpfFIlter.GetBPFFilter();
                    networkPackets.FilterNetworkCaptureFile(computedBPFFilter, fullPcapFile, filteredPcapFile);
                    Console.WriteLine("Finished everything!");
                    break;
                }
            }

            
        }
        private static void StopKernelSession()
        {
            Console.WriteLine("Stopped kernel session!");
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
                
                Console.WriteLine("{0} made a IPv4 TCP connection to {1}:{2}", data.ProcessName, data.daddr, data.dport);
            }
            else
            {
                Console.WriteLine("STILL LISTENING {0} made a IPv4 TCP connection to {1}:{2}", data.ProcessName, data.daddr, data.dport);
            }
        }

        private static void Ipv6TcpStart(TcpIpV6SendTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Console.WriteLine("{0} made a IPv6 TCP connection to {1}:{2}", data.ProcessName, data.daddr, data.dport);
            }
        }

        private static void Ipv4UdpIpStart(UdpIpTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Console.WriteLine("{0} sent a IPv4 UDP packet to {1}:{2}", data.ProcessName, data.daddr, data.dport);
            }
        }

        private static void Ipv6UdpIpStart(UpdIpV6TraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Console.WriteLine("{0} sent a IPv6 UDP packet to {1}:{2}", data.ProcessName, data.daddr, data.dport);
            }
        }

        /*
         
        PROCESSES
        
        */
        private static void childProcessStarted(ProcessTraceData data) {
            if (trackedProcessId == data.ParentID || trackedChildProcessIds.ContainsKey(data.ParentID))
            {
                Console.WriteLine("Child process started: {0} with pid: {1} AND cmdline {2}", data.ImageFileName, data.ProcessID, data.CommandLine);
                if (trackChildProcesses) { 
                    trackedChildProcessIds.Add(data.ProcessID, data.ImageFileName);
                }
            }
        }

        private static void processStopped(ProcessTraceData data) {
            if (trackedProcessId == data.ProcessID)
            {
                Console.WriteLine("Stopped main process: {0} with pid: {1}", data.ImageFileName, data.ProcessID);
                mainProcessEnded = true;
            }else if (trackedChildProcessIds.ContainsKey(data.ProcessID))
            {
                Console.WriteLine("Stopped child process: {0} with pid: {1}", data.ImageFileName, data.ProcessID);
                trackedChildProcessIds.Remove(data.ProcessID);  
            }
        }
    }
}