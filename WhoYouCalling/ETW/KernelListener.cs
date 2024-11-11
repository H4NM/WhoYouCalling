﻿using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Diagnostics.Tracing.StackSources;
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
            if (Program.IsMonitoredProcess(data.ProcessID))
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.TCP);
            }
            else if ((Program.TrackExecutablesByName() && Program.IsTrackedExecutableName(data.ProcessID)) || Program.MonitorEverything())
            {
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName);
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.TCP);
            }
        }

        private void IPv6TCPSend(TcpIpV6SendTraceData data)
        {
            if (Program.IsMonitoredProcess(data.ProcessID))
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.TCP);
            }
            else if ((Program.TrackExecutablesByName() && Program.IsTrackedExecutableName(data.ProcessID)) || Program.MonitorEverything())
            {
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName);
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.TCP);
            }
        }

        private void IPv4UDPSend(UdpIpTraceData data)
        {
            if (Program.IsMonitoredProcess(data.ProcessID))
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.UDP);
            }
            else if ((Program.TrackExecutablesByName() && Program.IsTrackedExecutableName(data.ProcessID)) || Program.MonitorEverything())
            {
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName);
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv4, transportProto: Network.TransportProtocol.UDP);
            }
        }

        private void IPv6UDPSend(UpdIpV6TraceData data)
        {
            if (Program.IsMonitoredProcess(data.ProcessID))
            {
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.UDP);
            }
            else if ((Program.TrackExecutablesByName() && Program.IsTrackedExecutableName(data.ProcessID)) || Program.MonitorEverything())
            {
                Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName);
                ProcessNetworkPacket(data, ipVersion: Network.IPVersion.IPv6, transportProto: Network.TransportProtocol.UDP);
            }
        }

        private void ProcessStart(ProcessTraceData data)
        {

            if (Program.IsMonitoredProcess(data.ParentID)) //If current process is child process of already started process
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
                    parentProcessName = ProcessManager.GetPIDProcessName(data.ParentID);
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
                monitoredParentProcess.ChildProcesses.Add((data.ProcessID, data.ProcessName)); // Used for documenting child processes

                Program.CatalogETWActivity(eventType: EventType.Childprocess,
                                            parentProcessName: parentProcessName,
                                            parentProcessID: data.ParentID,
                                            processAction: "started",
                                            processName: data.ProcessName,
                                            processID: data.ProcessID,
                                            processCommandLine: data.CommandLine);
            }
            else if (Program.TrackExecutablesByName() && Program.IsTrackedExecutableName(data.ParentID))
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
                        parentProcessName = ProcessManager.GetPIDProcessName(data.ParentID);
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

                Program.CatalogETWActivity(eventType: EventType.Childprocess,
                                            parentProcessName: parentProcessName,
                                            parentProcessID: data.ParentID,
                                            processAction: "started",
                                            processName: data.ProcessName,
                                            processID: data.ProcessID,
                                            processCommandLine: data.CommandLine);
            }
            else if(Program.TrackExecutablesByName() && Program.IsTrackedExecutableName(data.ProcessID))
            {
                string parentProcessName = ProcessManager.GetProcessFileName(data.ParentID);
                Program.AddProcessToMonitor(pid: data.ProcessID, commandLine: data.CommandLine);
                Program.CatalogETWActivity(eventType: EventType.Childprocess,
                                            parentProcessName: parentProcessName,
                                            parentProcessID: data.ParentID,
                                            processAction: "started",
                                            processName: data.ProcessName,
                                            processID: data.ProcessID,
                                            processCommandLine: data.CommandLine);
            }
            else if (Program.MonitorEverything())
            {
                
                string parentProcessName = ProcessManager.GetProcessFileName(data.ParentID);
                Program.AddProcessToMonitor(pid: data.ParentID, processName: parentProcessName);

                if (!Program.IsMonitoredProcess(data.ProcessID))
                {
                    Program.AddProcessToMonitor(pid: data.ProcessID, processName: data.ProcessName, commandLine: data.CommandLine);
                }
                Program.CatalogETWActivity(eventType: EventType.Childprocess,
                                           parentProcessName: parentProcessName,
                                           parentProcessID: data.ParentID,
                                           processAction: "started",
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
                if (string.IsNullOrEmpty(data.ProcessName))
                {
                    if (Program.MonitoredProcessCanBeRetrievedWithPID(data.ProcessID))
                    {
                        processName = Program.GetMonitoredProcessWithPID(data.ProcessID).ProcessName;
                    }
                    else
                    {
                        processName = ProcessManager.GetPIDProcessName(data.ProcessID);
                    }
                }
                Program.CatalogETWActivity(eventType: EventType.Process,
                                           processName: processName,
                                           processID: data.ProcessID,
                                           processAction: "stopped");

                if (Program.IsTrackedChildPID(data.ProcessID)) // A redundant check to ensure that the PID is only removed after calling CatalogETWActivity to ensure any possible
                {                                              // Lookups are not affected 
                    Program.RemoveChildPID(data.ProcessID);
                }
            }
        }
    }
}