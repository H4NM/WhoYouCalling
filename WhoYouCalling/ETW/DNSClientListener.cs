﻿using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using System.Net;
using WhoYouCalling.Network.FPC;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.ETW
{
    internal class DNSClientListener : Listener
    {
        public void Listen()
        {
            using (_session = new TraceEventSession("WhoYouCallingDNSClientSession"))
            {
                _session.EnableProvider("Microsoft-Windows-DNS-Client");
                _session.Source.Dynamic.All += DnsClientEvent;
                _session.Source.Process();
            }

        }

        private void DnsClientEvent(TraceEvent data)
        {
            switch (data.EventName)
            {
                case "EventID(3006)":
                    {
                        if (_trackedProcessId == data.ProcessID || Program.IsTrackedChildPID(data.ProcessID))
                        {
                            string retrievedQuery = data.PayloadByName("QueryName").ToString();
                            string dnsQuery = string.IsNullOrWhiteSpace(retrievedQuery) ? "N/A" : retrievedQuery;
                            string executable;
                            string execType;

                            if (_trackedProcessId == data.ProcessID) // DNS Lookup made by main process 
                            {
                                executable = _mainExecutableFileName;
                                execType = "Main";
                            }
                            else // DNS Lookup made by child process
                            {
                                executable = Program.GetTrackedPIDImageName(data.ProcessID);
                                execType = "Child";
                            }
                            Program.CatalogETWActivity(eventType: "dnsquery",
                                  executable: _mainExecutableFileName,
                                  execPID: data.ProcessID,
                                  execType: "Main",
                                  dnsQuery: dnsQuery);
                        }
                        break;
                    }
                case "EventID(3008)":
                    {
                        if (_trackedProcessId == data.ProcessID || Program.IsTrackedChildPID(data.ProcessID))
                        {
                            string retrievedQuery = data.PayloadByName("QueryName").ToString();
                            string dnsQuery = string.IsNullOrWhiteSpace(retrievedQuery) ? "N/A" : retrievedQuery;

                            string retrievedQueryResults = data.PayloadByName("QueryResults").ToString();
                            IPAddress dnsResult = NetworkUtils.CleanIPv4AndIPv6Address(retrievedQueryResults);

                            int dnsType;
                            int dnsQueryStatus;
                            string executable;
                            string execType;

                            if (!int.TryParse(data.PayloadByName("QueryStatus").ToString(), out dnsQueryStatus))
                            {
                                ConsoleOutput.Print($"Attempted to parse retrieved DNS Query status. Failed to parse it", "debug");
                                dnsQueryStatus = 999999; // Non-existing DNS status value. Is later looked up
                            }
                            if (!int.TryParse(data.PayloadByName("QueryType").ToString(), out dnsType))
                            {
                                ConsoleOutput.Print($"Attempted to parse retrieved DNS Query type. Failed to parse it", "debug");
                                dnsType = 999999; // Non-existing DNS type value. Is later looked up
                            }

                            if (_trackedProcessId == data.ProcessID) // DNS response to by main process 
                            {
                                executable = _mainExecutableFileName;
                                execType = "Main";
                            }
                            else  // DNS response to child process 
                            {
                                executable = Program.GetTrackedPIDImageName(data.ProcessID); 
                                execType = "Child";
                            }

                            Program.CatalogETWActivity(eventType: "dnsresponse",
                                    executable: executable,
                                    execPID: data.ProcessID,
                                    execType: execType,
                                    dnsQuery: dnsQuery,
                                    dnsRecordTypeCode: dnsType,
                                    dnsResult: dnsResult,
                                    dnsQueryStatusCode: dnsQueryStatus);
                        }
                        break;
                }
            }
        }
    }
}
