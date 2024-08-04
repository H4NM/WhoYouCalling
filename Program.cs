
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
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

                // Set UseShellExecute to true to use the shell to start the process
                startInfo.UseShellExecute = true;

                // Set the Verb to "open" to run the process with normal user privileges
                startInfo.Verb = "open";

                // Start the process
                Process process = Process.Start(startInfo);

                // Check if the process was started successfully
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
                // Handle exceptions
                Console.WriteLine($"An error occurred: {ex.Message}");
                throw;
            }
        }
    }
}

namespace ApplicationReviewer
{
    class Program
    {

        private static int trackedProcessId;
        static void Main(string[] args)
        {
            if (!(TraceEventSession.IsElevated() ?? false))
            {
                Console.WriteLine("Please run me as Administrator!");
                return;
            }
            if (args.Length != 1)
            {
                Console.WriteLine("Uppge namn på process att övervaka");
                return;
            }
            Console.WriteLine("[{0}]", string.Join(", ", args));


            Utilities.ProcessStarter processStarter = new Utilities.ProcessStarter();
            //string binaryPath = @"C:\Program Files (x86)\Steam\steam.exe";

            string binaryPath = @"C:\Program Files(x86)\Steam\steamapps\common\SongsOfConquest\SongsOfConquest.exe";
            string arguments = ""; // Add any required arguments here

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

            using (var kernelSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName))
            {
                Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e) { kernelSession.Dispose(); };

                kernelSession.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.ImageLoad |
                    KernelTraceEventParser.Keywords.NetworkTCPIP |
                    KernelTraceEventParser.Keywords.Process |
                    KernelTraceEventParser.Keywords.FileIO
                );

                kernelSession.Source.Kernel.ImageLoad += dllLoaded;
                kernelSession.Source.Kernel.TcpIpConnect += tcpConnectionStart;
                kernelSession.Source.Kernel.UdpIpSend += UdpIpStart;
                kernelSession.Source.Kernel.ProcessStart += childProcessStarted;
                kernelSession.Source.Kernel.ProcessStop += processStopped;

                kernelSession.Source.Kernel.FileIORead += readFile;
                kernelSession.Source.Kernel.FileIOCreate += createFile;
               // kernelSession.Source.Kernel.FileIOWrite += writeFile;

                kernelSession.Source.Process();
            }
        }


        /*
         
        FILES
        
        */
        private static void createFile(FileIOCreateTraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                Console.WriteLine("Created File {0}:{1}", data.FileName, data.FileAttributes);
            }
        }

        private static void readFile(FileIOReadWriteTraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                Console.WriteLine("ReadWrite File {0}:{1}", data.FileName, data.OpcodeName);
            }
        }

        /*
         
        NETWORK 
        
        */
        private static void tcpConnectionStart(TcpIpConnectTraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                Console.WriteLine("TCP connection to {0}:{1}", data.daddr, data.dport);
            }
        }
        private static void UdpIpStart(UdpIpTraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                Console.WriteLine("UDP packet sent To {0}:{1}", data.daddr, data.dport);
            }
        }

        /*
         
        PROCESSES
        
        */
        private static void childProcessStarted(ProcessTraceData data) {
            if (trackedProcessId == data.ParentID)
            {
                Console.WriteLine("Child process started: {0} with pid: {1}", data.ImageFileName, data.ProcessID);
            }       
        }

        private static void processStopped(ProcessTraceData data) {
            if (trackedProcessId == data.ProcessID)
            {
                Console.WriteLine("Stopped process: {0} with pid: {1}", data.ImageFileName, data.ProcessID);
                System.Environment.Exit(0);
            }
        }

        /*
         
        DLLS
        
        */
        private static void dllLoaded(ImageLoadTraceData data) {
            if (trackedProcessId == data.ProcessID)
            {
                //Console.WriteLine("Dll loaded: {0}", data.FileName);
            }
        }
       
    }
}