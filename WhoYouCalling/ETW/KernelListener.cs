using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using WhoYouCalling.Network;

namespace WhoYouCalling.ETW
{
    internal class KernelListener : Listener
    {
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

        private bool IsAMonitoredProcess(int pid)
        {
            if (_trackedProcessId == pid || Program.IsTrackedChildPID(pid))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private void ProcessNetworkPacket(dynamic data, string ipVersion = "", string transportProto = "")
        {
            NetworkPacket ipv4TCPPacket = new NetworkPacket
            {
                IPversion = "IPv4",
                TransportProtocol = "TCP",
                SourceIP = data.saddr.ToString(),
                SourcePort = data.sport,
                DestinationIP = data.daddr.ToString(),
                DestinationPort = data.dport
            };
            string executable;
            string execType;

            if (_trackedProcessId == data.ProcessID) // Main monitored process
            {
                executable = _mainExecutableFileName;
                execType = "Main";
            }
            else // Child monitored process
            {
                executable = Program.GetTrackedPIDImageName(data.ProcessID);
                execType = "Child";
            }

            Program.CatalogETWActivity(eventType: "network",
                                    executable: executable,
                                    execPID: data.ProcessID,
                                    execType: execType,
                                    networkPacket: ipv4TCPPacket);
        }

        private void Ipv4TcpStart(TcpIpSendTraceData data)
        {
            if (IsAMonitoredProcess(data.ProcessID)) // If main or child monitored process
            {
                ProcessNetworkPacket(data, ipVersion: "IPv4", transportProto: "TCP");
            }
        }

        private void Ipv6TcpStart(TcpIpV6SendTraceData data)
        {
            if (IsAMonitoredProcess(data.ProcessID)) // If main or child monitored process
            {
                ProcessNetworkPacket(data, ipVersion: "IPv6", transportProto: "TCP");
            }
        }

        private void Ipv4UdpIpStart(UdpIpTraceData data)
        {
            if (IsAMonitoredProcess(data.ProcessID)) // If main or child monitored process
            {
                ProcessNetworkPacket(data, ipVersion: "IPv4", transportProto: "UDP");
            }
        }

        private void Ipv6UdpIpStart(UpdIpV6TraceData data)
        {
            if (IsAMonitoredProcess(data.ProcessID)) // If main or child monitored process
            {
                ProcessNetworkPacket(data, ipVersion: "IPv6", transportProto: "UDP");
            }
        }

        private void childProcessStarted(ProcessTraceData data)
        {
            if (IsAMonitoredProcess(data.ParentID)) //Tracks child processes by main process
            {
                string executable;
                string execType;

                if (_trackedProcessId == data.ParentID) // If spawned process is from main tracked process
                {
                    executable = _mainExecutableFileName;
                    execType = "Main";
                }
                else // else the parent process is from one of the children
                {
                    executable = Program.GetTrackedPIDImageName(data.ParentID);
                    execType = "Child";
                }
                Program.CatalogETWActivity(eventType: "childprocess",
                                            executable: executable,
                                            execType: execType,
                                            execAction: "started",
                                            execObject: data.ImageFileName,
                                            execPID: data.ProcessID,
                                            parentExecPID: data.ParentID);
                if (Program.TrackChildProcesses)
                {
                    Program.AddChildPID(data.ProcessID);
                    Program.InstantiateProcessVariables(pid: data.ProcessID, executable: data.ImageFileName);
                }
            }
        }

        private void processStopped(ProcessTraceData data)
        {
            if (IsAMonitoredProcess(data.ProcessID)) // Main or child process stopped
            {
                string execType;
                if (_trackedProcessId == data.ProcessID) // If main process stopped
                {
                    execType = "Main";
                }
                else // else a child process topped
                {
                    execType = "Child";
                }

                Program.CatalogETWActivity(eventType: "process",
                                        executable: data.ImageFileName,
                                        execType: execType,
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