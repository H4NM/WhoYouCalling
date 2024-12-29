using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using WhoYouCalling.Network;
using WhoYouCalling.Process;
using WhoYouCalling.Utilities;

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
        }

        private void ProcessNetworkPacket(dynamic data, IPVersion ipVersion, TransportProtocol transportProto)
        {
            ConnectionRecord connectionRecord = new ConnectionRecord
            {
                IPversion = ipVersion,
                TransportProtocol = transportProto,
                SourceIP = data.saddr.ToString(),
                SourcePort = data.sport,
                DestinationIP = data.daddr.ToString(),
                DestinationPort = data.dport
            };

            Program.CatalogETWActivity(eventType: EventType.Network,
                                       processName: data.ProcessName,
                                       processID: data.ProcessID,
                                       connectionRecord: connectionRecord);
        }

        private void IPv4TCPSend(TcpIpSendTraceData data)
        {
            if (Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName))
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.TCP);
            }
            else if ((Program.TrackProcessesByName() && Program.IsTrackedProcessByName(pid: data.ProcessID, processName: data.ProcessName)) || Program.MonitorEverything())
            {
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName);
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.TCP);
            }
        }

        private void IPv6TCPSend(TcpIpV6SendTraceData data)
        {
            if (Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName))
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.TCP);
            }
            else if ((Program.TrackProcessesByName() && Program.IsTrackedProcessByName(pid: data.ProcessID, processName: data.ProcessName)) || Program.MonitorEverything())
            {
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName);
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.TCP);
            }
        }

        private void IPv4UDPSend(UdpIpTraceData data)
        {
            if (Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName))
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.UDP);
            }
            else if ((Program.TrackProcessesByName() && Program.IsTrackedProcessByName(pid: data.ProcessID, processName: data.ProcessName)) || Program.MonitorEverything())
            {
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName);
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.UDP);
            }
        }

        private void IPv6UDPSend(UpdIpV6TraceData data)
        {
            if (Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName))
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.UDP);
            }
            else if ((Program.TrackProcessesByName() && Program.IsTrackedProcessByName(pid: data.ProcessID, processName: data.ProcessName)) || Program.MonitorEverything())
            {
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName);
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.UDP);
            }
        }

        private void ProcessStart(ProcessTraceData data)
        {
            if (Program.IsMonitoredProcess(pid: data.ParentID)) //If current process is child process of already started process
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
                    parentProcessName = initialProcessName == Constants.Miscellaneous.ProcessDefaultNameAtError
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
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName, commandLine: data.CommandLine);
                
                monitoredParentProcess.ChildProcesses.Add(new ChildProcessInfo
                {
                    ProcessID = data.ProcessID,
                    ProcessName = data.ProcessName,
                    ETWRegisteredStartTime = DateTime.Now
                });

                Program.CatalogETWActivity(eventType: EventType.StartedChildProcess,
                                            parentProcessName: parentProcessName,
                                            parentProcessID: data.ParentID,
                                            processName: data.ProcessName,
                                            processID: data.ProcessID,
                                            processCommandLine: data.CommandLine);
            }
            else if (Program.MonitorEverything())
            {

                string parentProcessName = ProcessManager.GetProcessFileName(data.ParentID);
                Program.AddProcessToMonitor(pid: data.ParentID, processName: parentProcessName);
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName, commandLine: data.CommandLine);

                Program.CatalogETWActivity(eventType: EventType.StartedChildProcess,
                                           parentProcessName: parentProcessName,
                                           parentProcessID: data.ParentID,
                                           processName: data.ProcessName,
                                           processID: data.ProcessID,
                                           processCommandLine: data.CommandLine);
            }
            else if (Program.TrackProcessesByName() && Program.IsTrackedProcessByName(pid: data.ParentID))
            {
                string parentProcessName = "";
                if (Program.IsMonitoredProcess(data.ParentID))
                {
                    MonitoredProcess monitoredParentProcess;
                    if (Program.MonitoredProcessCanBeRetrievedWithPID(data.ParentID))
                    {
                        monitoredParentProcess = Program.GetMonitoredProcessWithPID(data.ParentID);
                        parentProcessName = monitoredParentProcess.ProcessName;
                    }
                    else
                    {
                        string initialProcessName = ProcessManager.GetPIDProcessName(data.ParentID);
                        parentProcessName = initialProcessName == Constants.Miscellaneous.ProcessDefaultNameAtError
                            ? Program.GetBackupProcessName(data.ProcessID)
                            : initialProcessName;

                        string uniqueProcessIdentifier = ProcessManager.GetUniqueProcessIdentifier(pid: data.ParentID, processName: parentProcessName);
                        if (Program.UniqueProcessIDIsMonitored(uniqueProcessIdentifier))
                        {
                            monitoredParentProcess = Program.GetMonitoredProcessWithUniqueProcessID(uniqueProcessIdentifier);
                        }
                        else
                        {
                            monitoredParentProcess = new(); // will be caught by gc
                        }
                    }
                }
                else
                {
                    parentProcessName = ProcessManager.GetPIDProcessName(data.ParentID);
                    Program.AddProcessToMonitor(pid: data.ParentID, processName: parentProcessName, commandLine: "");
                }
                Program.CatalogETWActivity(eventType: EventType.StartedChildProcess,
                                            parentProcessName: parentProcessName,
                                            parentProcessID: data.ParentID,
                                            processName: data.ProcessName,
                                            processID: data.ProcessID,
                                            processCommandLine: data.CommandLine);
            }
            else if(Program.TrackProcessesByName() && Program.IsTrackedProcessByName(pid: data.ProcessID, processName: data.ProcessName))
            {
                string parentProcessName = ProcessManager.GetProcessFileName(data.ParentID);
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName, commandLine: data.CommandLine);
                Program.CatalogETWActivity(eventType: EventType.StartedChildProcess,
                                            parentProcessName: parentProcessName,
                                            parentProcessID: data.ParentID,
                                            processName: data.ProcessName,
                                            processID: data.ProcessID,
                                            processCommandLine: data.CommandLine);
            }
        }

        private void ProcessStop(ProcessTraceData data)
        {
            if (Program.IsMonitoredProcess(data.ProcessID)) // Main or child process stopped
            {
                string processName = "";
         
                if (Program.MonitoredProcessCanBeRetrievedWithPID(data.ProcessID))
                {
                    processName = Program.GetMonitoredProcessWithPID(data.ProcessID).ProcessName;
                }
                else
                {
                    processName = Program.GetBackupProcessName(data.ProcessID);
                    Program.DeleteOldBackupProcessName(data.ProcessID);
                    Program.DeleteProcessIDIndex(data.ProcessID);
                }
                Program.CatalogETWActivity(eventType: EventType.ProcessStop,
                                           processName: processName,
                                           processID: data.ProcessID);

                if (Program.IsTrackedChildPID(data.ProcessID)) // A redundant check to ensure that the PID is only removed after calling CatalogETWActivity to ensure any possible
                {                                              // Lookups are not affected 
                    Program.RemoveChildPID(data.ProcessID);
                }
            }
        }
    }
}