using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;


namespace WhoYouCalling.ETW
{
    public class KernelListener : Listener
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

        private void Ipv4TcpStart(TcpIpSendTraceData data)
        {
            if (_trackedProcessId == data.ProcessID)
            {
                Program.CatalogETWActivity(eventType: "network",
                                        executable: _mainExecutableFileName,
                                        execPID: data.ProcessID,
                                        execType: "Main",
                                        ipVersion: "IPv4",
                                        transportProto: "TCP",
                                        srcAddr: data.saddr,
                                        srcPort: data.sport,
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
            else if (Program.IsTrackedChildPID(data.ProcessID))
            {
                string childExecutable = Program.GetTrackedPIDImageName(data.ProcessID);
                Program.CatalogETWActivity(eventType: "network",
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

        private void Ipv6TcpStart(TcpIpV6SendTraceData data)
        {
            if (_trackedProcessId == data.ProcessID)
            {
                Program.CatalogETWActivity(eventType: "network",
                                        executable: _mainExecutableFileName,
                                        execPID: data.ProcessID,
                                        execType: "Main",
                                        ipVersion: "IPv6",
                                        transportProto: "TCP",
                                        srcAddr: data.saddr,
                                        srcPort: data.sport,
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
            else if (Program.IsTrackedChildPID(data.ProcessID))
            {
                string childExecutable = Program.GetTrackedPIDImageName(data.ProcessID);
                Program.CatalogETWActivity(eventType: "network",
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

        private void Ipv4UdpIpStart(UdpIpTraceData data)
        {
            if (_trackedProcessId == data.ProcessID)
            {
                Program.CatalogETWActivity(eventType: "network",
                                        executable: _mainExecutableFileName,
                                        execPID: data.ProcessID,
                                        execType: "Main",
                                        ipVersion: "IPv4",
                                        transportProto: "UDP",
                                        srcAddr: data.saddr,
                                        srcPort: data.sport,
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
            else if (Program.IsTrackedChildPID(data.ProcessID))
            {
                string childExecutable = Program.GetTrackedPIDImageName(data.ProcessID);
                Program.CatalogETWActivity(eventType: "network",
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

        private void Ipv6UdpIpStart(UpdIpV6TraceData data)
        {
            if (_trackedProcessId == data.ProcessID)
            {
                Program.CatalogETWActivity(eventType: "network",
                                        executable: _mainExecutableFileName,
                                        execPID: data.ProcessID,
                                        execType: "Main",
                                        ipVersion: "IPv6",
                                        transportProto: "UDP",
                                        srcAddr: data.saddr,
                                        srcPort: data.sport,
                                        dstAddr: data.daddr,
                                        dstPort: data.dport);
            }
            else if (Program.IsTrackedChildPID(data.ProcessID))
            {
                string childExecutable = Program.GetTrackedPIDImageName(data.ProcessID);
                Program.CatalogETWActivity(eventType: "network",
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

        private void childProcessStarted(ProcessTraceData data)
        {

            if (_trackedProcessId == data.ParentID) //Tracks child processes by main process
            {
                Program.CatalogETWActivity(eventType: "childprocess",
                                        executable: _mainExecutableFileName,
                                        execType: "Main",
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
            else if (Program.IsTrackedChildPID(data.ParentID)) //Tracks child processes by child processes
            {
                string childExecutable = Program.GetTrackedPIDImageName(data.ParentID);

                Program.CatalogETWActivity(eventType: "childprocess",
                                        executable: childExecutable,
                                        execType: "Child",
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
            if (_trackedProcessId == data.ProcessID) // Main process stopped
            {
                Program.CatalogETWActivity(eventType: "process",
                                        executable: data.ImageFileName,
                                        execType: "Main",
                                        execAction: "stopped",
                                        execPID: data.ProcessID);
            }
            else if (Program.IsTrackedChildPID(data.ProcessID)) // Child process stopped
            {
                Program.CatalogETWActivity(eventType: "process",
                                        executable: data.ImageFileName,
                                        execType: "Child",
                                        execAction: "stopped",
                                        execPID: data.ProcessID);
                Program.RemoveChildPID(data.ProcessID);
            }
        }

    }
}