using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using System.Security.Cryptography;
using WhoYouCalling.Network;
using WhoYouCalling.Process;

namespace WhoYouCalling.ETW
{
    internal class KernelListener : Listener
    {
        public KernelListener()
        {
            SourceName = "Kernel";
        }

        public void Listen()
        {
            using (_session = new TraceEventSession(KernelTraceEventParser.KernelSessionName)) //KernelTraceEventParser
            {
                _session.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.NetworkTCPIP |
                    KernelTraceEventParser.Keywords.Process
                );

                // TCP/IP
                _session.Source.Kernel.TcpIpSend += Ipv4TcpStart; // TcpIpConnect may be used. However, "send" is used to ensure capturing failed TCP handshakes
                _session.Source.Kernel.TcpIpSendIPV6 += Ipv6TcpStart;
                _session.Source.Kernel.UdpIpSend += Ipv4UdpIpStart;
                _session.Source.Kernel.UdpIpSendIPV6 += Ipv6UdpIpStart;

                // Process
                _session.Source.Kernel.ProcessStart += childProcessStarted;
                _session.Source.Kernel.ProcessStop += processStopped;

                // Start Kernel ETW session
                _session.Source.Process();
            }
        }

        private void ProcessNetworkPacket(dynamic data, IPVersion ipVersion, TransportProtocol transportProto)
        {
            ConnectionRecord ipv4TCPConnRecord = new ConnectionRecord
            {
                IPversion = ipVersion,
                TransportProtocol = transportProto,
                SourceIP = data.saddr.ToString(),
                SourcePort = data.sport,
                DestinationIP = data.daddr.ToString(),
                DestinationPort = data.dport
            };
            string executable = Program.GetTrackedPIDImageName(data.ProcessID);

            Program.CatalogETWActivity(eventType: EventType.Network,
                                    executable: executable,
                                    execPID: data.ProcessID,
                                    connectionRecord: ipv4TCPConnRecord);
        }

        private void Ipv4TcpStart(TcpIpSendTraceData data)
        {
            if (IsAMonitoredProcess(data.ProcessID)) // If main or child monitored process
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.TCP);
            }
        }

        private void Ipv6TcpStart(TcpIpV6SendTraceData data)
        {
            if (IsAMonitoredProcess(data.ProcessID)) // If main or child monitored process
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.TCP);
            }
        }

        private void Ipv4UdpIpStart(UdpIpTraceData data)
        {
            if (IsAMonitoredProcess(data.ProcessID)) // If main or child monitored process
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.UDP);
            }
        }

        private void Ipv6UdpIpStart(UpdIpV6TraceData data)
        {
            if (IsAMonitoredProcess(data.ProcessID)) // If main or child monitored process
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.UDP);
            }
        }

        private void childProcessStarted(ProcessTraceData data)
        {

            if (IsAMonitoredProcess(data.ParentID)) //Tracks child processes by monitored process
            {
                string parentExectuable = Program.GetTrackedPIDImageName(data.ParentID);
                
                Program.CatalogETWActivity(eventType: EventType.Childprocess,
                                            executable: parentExectuable,
                                            execAction: "started",
                                            execObject: data.ImageFileName,
                                            execObjectCommandLine: data.CommandLine,
                                            execPID: data.ProcessID,
                                            parentExecPID: data.ParentID);
                if (Program.TrackChildProcesses())
                {
                    Program.AddChildPID(data.ProcessID);
                    Program.InstantiateProcessVariables(pid: data.ProcessID, executable: data.ImageFileName, commandLine: data.CommandLine);
                }
            }
            else if(Program.TrackExecutablesByName() && Program.IsTrackedExecutableName(data.ProcessID))
            {
                string parentExectuable = ProcessManager.GetProcessFileName(data.ParentID);

                Program.InstantiateProcessVariables(pid: data.ProcessID, executable: data.ImageFileName, commandLine: data.CommandLine);
                Program.CatalogETWActivity(eventType: EventType.Childprocess,
                            executable: parentExectuable,
                            execAction: "started by name",
                            execObject: data.ImageFileName,
                            execObjectCommandLine: data.CommandLine,
                            execPID: data.ProcessID,
                            parentExecPID: data.ParentID);
            }
        }

        private void processStopped(ProcessTraceData data)
        {
            if (IsAMonitoredProcess(data.ProcessID)) // Main or child process stopped
            {
                Program.CatalogETWActivity(eventType: EventType.Process,
                                        executable: data.ImageFileName,
                                        execAction: "stopped",
                                        execPID: data.ProcessID);

                if (Program.IsTrackedChildPID(data.ProcessID)) // A redundant check to ensure that the PID is only removed after calling CatalogETWActivity to ensure any possible
                {                                              // Lookups are not affected 
                    Program.RemoveChildPID(data.ProcessID);
                }
            }
        }
    }
}