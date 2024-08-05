
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Diagnostics.Symbols;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace ApplicationReviewer.Utilities
{ 
    public class ProcessStarter
    {
        public int StartProcessAndGetId(string binaryPath, string arguments = "")
        {
            try
            {
                // Create a new process start info
                ProcessStartInfo startInfo = new ProcessStartInfo(binaryPath);

                // Set the arguments if provided
                if (!string.IsNullOrEmpty(arguments))
                {
                    startInfo.Arguments = arguments;
                }

                startInfo.UseShellExecute = true;
                startInfo.Verb = "open";

                // Start the process
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

    public class ETWListener
    {
        public void ListenToETW()
        {
            using (var kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) { kernelSession.Dispose(); };

                kernelSession.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.NetworkTCPIP |
                    KernelTraceEventParser.Keywords.Process
                );

                kernelSession.Source.Kernel.TcpIpConnect += Program.Ipv4TcpConnectionStart;
                kernelSession.Source.Kernel.TcpIpConnectIPV6 += Program.Ipv6TcpConnectionStart;
                kernelSession.Source.Kernel.UdpIpSend += Program.Ipv4UdpIpStart;
                kernelSession.Source.Kernel.UdpIpSendIPV6 += Program.Ipv6UdpIpStart;

                kernelSession.Source.Kernel.ProcessStart += Program.childProcessStarted;
                kernelSession.Source.Kernel.ProcessStop += Program.processStopped;


                kernelSession.Source.Process();
            }
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
            Utilities.ETWListener etwListener = new Utilities.ETWListener();

            Thread etwThread = new Thread(() => etwListener.ListenToETW());
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

        /*
         
        NETWORK 
        
        */
        public static void Ipv4TcpConnectionStart(TcpIpConnectTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.Contains(data.ProcessID))
            {
                Console.WriteLine("{0} made a IPv4 TCP connection to {1}:{2}", data.ProcessName, data.daddr, data.dport);
            }
        }

        public static void Ipv6TcpConnectionStart(TcpIpV6ConnectTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.Contains(data.ProcessID))
            {
                Console.WriteLine("{0} made a IPv6 TCP connection to {1}:{2}", data.ProcessName, data.daddr, data.dport);
            }
        }

        public static void Ipv4UdpIpStart(UdpIpTraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.Contains(data.ProcessID))
            {
                Console.WriteLine("{0} sent a IPv4 UDP packet to {1}:{2} with OPCODE {3}", data.ProcessName, data.daddr, data.dport);
            }
        }

        public static void Ipv6UdpIpStart(UpdIpV6TraceData data)
        {
            if (trackedProcessId == data.ProcessID || trackedChildProcessIds.Contains(data.ProcessID))
            {
                Console.WriteLine("{0} sent a IPv6 UDP packet to {1}:{2} with OPCODE {3}", data.ProcessName, data.daddr, data.dport);
            }
        }

        /*
         
        PROCESSES
        
        */
        public static void childProcessStarted(ProcessTraceData data) {
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

        public static void processStopped(ProcessTraceData data) {
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