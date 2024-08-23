using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;


namespace WhoYouCalling.Utilities
{
    public class ETWListener
    {
        protected int trackedProcessId = 0;
        protected string mainExecutableFileName = "";
        protected TraceEventSession ETWSession;

        public void SetPIDAndImageToTrack(int pid, string executable)
        {

            mainExecutableFileName = executable;
            trackedProcessId = pid;
        }

        public void StopSession()
        {
            ETWSession.Dispose();
        }
        public bool GetSessionStatus()
        {
            return ETWSession.IsActive;
        }
    }

    public class DNSClientListener : ETWListener
    {
        public void Listen()
        {
            using (ETWSession = new TraceEventSession("WhoYouCallingDNSClientSession"))
            {
                ETWSession.EnableProvider("Microsoft-Windows-DNS-Client");
                ETWSession.Source.Dynamic.All += DnsClientEvent;
                ETWSession.Source.Process();
            }

        }

        private void DnsClientEvent(TraceEvent data)
        {
            if (trackedProcessId == data.ProcessID && data.EventName == "EventID(3006)") // DNS Lookup made by main tracked PID
            {
                string dnsQuery = data.PayloadByName("QueryName").ToString();
                dnsQuery ??= "N/A";
                Program.CatalogETWActivity(eventType: "dnsquery",
                    executable: mainExecutableFileName,
                    execPID: data.ProcessID,
                    execType: "Main",
                    dnsQuery: dnsQuery);
            }
            else if (Program.IsTrackedChildPID(data.ProcessID) && data.EventName == "EventID(3006)") // DNS Lookup made by child tracked PID
            {
                string childExecutable = Program.GetTrackedPIDImageName(data.ProcessID);
                string dnsQuery = data.PayloadByName("QueryName").ToString();
                dnsQuery ??= "N/A";
                Program.CatalogETWActivity(eventType: "dnsquery",
                    executable: childExecutable,
                    execPID: data.ProcessID,
                    execType: "Child",
                    dnsQuery: dnsQuery);
            }

            // data.FormattedMessage semi works - is entire message - quite dull. Only require action, query and perhaps answer. 
            //ConsoleOutput.Print($"DNS {data.EventName} - {data.FormattedMessage}", "debug");
            //ConsoleOutput.Print($"PAYLOAD {data.PayloadByName("QueryName")}", "debug");
        }

    }
	public class KernelListener : ETWListener
    {
        public void Listen()
        {
            using (ETWSession = new TraceEventSession(KernelTraceEventParser.KernelSessionName)) //KernelTraceEventParser
            {
                ETWSession.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.NetworkTCPIP |
                    KernelTraceEventParser.Keywords.Process
                );

                // TCP/IP
                ETWSession.Source.Kernel.TcpIpSend += Ipv4TcpStart; // TcpIpConnect may be used. However, "send" is used to ensure capturing failed TCP handshakes
                ETWSession.Source.Kernel.TcpIpSendIPV6 += Ipv6TcpStart;
                ETWSession.Source.Kernel.UdpIpSend += Ipv4UdpIpStart;
                ETWSession.Source.Kernel.UdpIpSendIPV6 += Ipv6UdpIpStart;

                // Process
                ETWSession.Source.Kernel.ProcessStart += childProcessStarted;
                ETWSession.Source.Kernel.ProcessStop += processStopped;

                // Start Kernel ETW session
                ETWSession.Source.Process();
            }
        }

        private void Ipv4TcpStart(TcpIpSendTraceData data)
        {
            if (trackedProcessId == data.ProcessID)
            {
                Program.CatalogETWActivity(eventType: "network",
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
            if (trackedProcessId == data.ProcessID)
            {
                Program.CatalogETWActivity(eventType: "network",
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
            if (trackedProcessId == data.ProcessID)
            {
                Program.CatalogETWActivity(eventType: "network",
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
            if (trackedProcessId == data.ProcessID)
            {
                Program.CatalogETWActivity(eventType: "network",
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

            if (trackedProcessId == data.ParentID) //Tracks child processes by main process
            {
                Program.CatalogETWActivity(eventType: "childprocess",
                                        executable: mainExecutableFileName,
                                        execType: "Main",
                                        execAction: "started",
                                        execObject: data.ImageFileName,
                                        execPID: data.ProcessID,
                                        parentExecPID: data.ParentID);
                if (Program.trackChildProcesses)
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
                if (Program.trackChildProcesses)
                {
                    Program.AddChildPID(data.ProcessID);
                    Program.InstantiateProcessVariables(pid: data.ProcessID, executable: data.ImageFileName);
                }
            }
        }

        private void processStopped(ProcessTraceData data)
        {
            if (trackedProcessId == data.ProcessID) // Main process stopped
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