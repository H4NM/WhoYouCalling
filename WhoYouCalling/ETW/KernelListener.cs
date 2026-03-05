using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
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
            _session = new TraceEventSession(KernelTraceEventParser.KernelSessionName);
            _session.EnableKernelProvider(
                KernelTraceEventParser.Keywords.NetworkTCPIP |
                KernelTraceEventParser.Keywords.Process
            );

            // TCP/IP
            _session.Source.Kernel.TcpIpSend += IPv4TCPSend; // TcpIpConnect may be used. However, "send" is used to ensure capturing failed TCP handshakes
            _session.Source.Kernel.TcpIpSendIPV6 += IPv6TCPSend;
            _session.Source.Kernel.UdpIpSend += IPv4UDPSend;
            _session.Source.Kernel.UdpIpSendIPV6 += IPv6UDPSend;

            // Process
            _session.Source.Kernel.ProcessStart += ProcessStart;
            _session.Source.Kernel.ProcessStop += ProcessStop;

            // Start Kernel ETW session
            _session.Source.Process();
        }

        private void ProcessNetworkPacket(dynamic data, IPVersion ipVersion, TransportProtocol transportProto)
        {
            ConnectionRecord connectionRecord = new()
            {
                IPversion = ipVersion,
                TransportProtocol = transportProto,
                SourceIP = data.saddr.ToString(),
                SourcePort = data.sport,
                DestinationIP = data.daddr.ToString(),
                DestinationPort = data.dport
            };


            string processName = data.ProcessName;
            if (string.IsNullOrEmpty(data.ProcessName))
            {
                processName = ProcessManager.GetPIDProcessName(data.ProcessID);
            }
            Program.CatalogETWActivity(eventType: EventType.Network,
                                       processName: processName,
                                       pid: data.ProcessID,
                                       connectionRecord: connectionRecord);
        }

        private void IPv4TCPSend(TcpIpSendTraceData data)
        {

            if (!Program.IncludeLoopbackWhenMonitoringEverything() && NetworkUtils.IsLocalhostIP(data.daddr.ToString()))
            {
                return;
            }
            else if (Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName))
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.TCP);
            }
            else if (Program.MonitorEverything())  // £ FAILSAFE
            {
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName);
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.TCP);
            }
        }

        private void IPv6TCPSend(TcpIpV6SendTraceData data)
        {
            if (!Program.IncludeLoopbackWhenMonitoringEverything() && NetworkUtils.IsLocalhostIP(data.daddr.ToString()))
            {
                return;
            }
            else if (Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName))
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.TCP);
            }
            else if (Program.MonitorEverything())  // £ FAILSAFE
            {
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName);
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.TCP);
            }
        }

        private void IPv4UDPSend(UdpIpTraceData data)
        {
            if (!Program.IncludeLoopbackWhenMonitoringEverything() && NetworkUtils.IsLocalhostIP(data.daddr.ToString()))
            {
                return;
            }
            else if (Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName))
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.UDP);
            }
            else if (Program.MonitorEverything())  // £ FAILSAFE
            {
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName);
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.UDP);
            }
        }

        private void IPv6UDPSend(UpdIpV6TraceData data)
        {
            if (!Program.IncludeLoopbackWhenMonitoringEverything() && NetworkUtils.IsLocalhostIP(data.daddr.ToString()))
            {
                return;
            }
            else if (Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName))
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.UDP);
            }
            else if (Program.MonitorEverything()) // £ FAILSAFE
            {
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName);
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.UDP);
            }
        }

        private void ProcessStart(ProcessTraceData data)
        {
            Program.AddObservedStartedProcess(pid:data.ProcessID, processName: data.ProcessName, commandLine: data.CommandLine, startTime: data.TimeStamp); // £ FAILSAFE - Added runningProcess

            if ((!Program.MonitorEverything() && Program.IsMonitoredProcess(pid: data.ParentID)) || (Program.IncludeProcessStartsWhenMonitoringEverything() && Program.IsMonitoredProcess(pid: data.ParentID))) //If current process is child process of already started process and is not in main mode to capture all
            {
                string parentProcessName;
                MonitoredProcess monitoredParentProcess;
                if (Program.MonitoredProcessCanBeRetrievedWithPID(data.ParentID))
                {
                    monitoredParentProcess = Program.GetMonitoredProcessWithPID(data.ParentID);
                    parentProcessName = monitoredParentProcess.ProcessName;
                }
                else
                {
                    string initialProcessName = ProcessManager.GetPIDProcessName(data.ParentID);
                    parentProcessName = initialProcessName == Miscellaneous.UnmappedProcessDefaultName
                        ? Program.GetBackupProcessName(data.ParentID)
                        : initialProcessName;

                    string uniqueProcessIdentifier = ProcessManager.GetUniqueProcessIdentifier(pid: data.ParentID, processName: parentProcessName);
                    if (Program.UniqueProcessIDIsMonitored(uniqueProcessIdentifier))
                    {
                        monitoredParentProcess = Program.GetMonitoredProcessWithUniqueProcessID(uniqueProcessIdentifier);
                    }
                    else
                    {
                        monitoredParentProcess = new(); // Redundant and is only used to catch when adding the child process. Otherwise this will be caught by gc
                    }
                }

                Program.AddChildPID(data.ProcessID); // Used for killing child processes
                if (!Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName)) // This is to deal with race conditions as the DNS ETW registers before process starts sometimes, where it is added before the actua
                {
                    Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName, commandLine: data.CommandLine); 
                }

                monitoredParentProcess.ChildProcesses.Add(new ChildProcessInfo
                {
                    PID = data.ProcessID,
                    ProcessName = data.ProcessName,
                    StartTime = data.TimeStamp
                });

                Program.CatalogETWActivity(eventType: EventType.StartedChildProcess,
                                            parentProcessName: parentProcessName,
                                            parentProcessID: data.ParentID,
                                            processName: data.ProcessName,
                                            pid: data.ProcessID,
                                            processCommandLine: data.CommandLine);
            }
        }

        private void ProcessStop(ProcessTraceData data)
        {
            Program.UpdateObservedProcessStopTime(pid: data.ProcessID, stopTime: data.TimeStamp);

            if (Program.IsMonitoredProcess(pid: data.ProcessID))
            {
                string processName = "";

                if (Program.MonitoredProcessCanBeRetrievedWithPID(pid: data.ProcessID))
                {
                    processName = Program.GetMonitoredProcessWithPID(pid: data.ProcessID).ProcessName;
                }
                else
                {
                    processName = Program.GetBackupProcessName(pid: data.ProcessID);
                    Program.DeleteOldBackupProcessName(pid:data.ProcessID); 
                }
                if (!Program.IsMonitoredProcess(pid:data.ProcessID, processName: processName)) // Required in the rare race condition instances where duplicate PIDs are registered but not cleared 
                {
                    return;
                }
                Program.CatalogETWActivity(eventType: EventType.ProcessStop,
                                           processName: processName,
                                           pid: data.ProcessID,
                                           processTime: data.TimeStamp);

            }
        }
    }
}