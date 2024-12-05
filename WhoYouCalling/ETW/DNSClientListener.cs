using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using WhoYouCalling.Network.DNS;
using WhoYouCalling.Utilities;
using WhoYouCalling.Network;
using WhoYouCalling.Process;
using System.Security.Cryptography;

namespace WhoYouCalling.ETW
{
    internal class DNSClientListener : Listener
    {

        public DNSClientListener()
        {
            SourceName = "DNS"; 
        }

        public void Listen()
        {
            using (_session = new TraceEventSession("WhoYouCallingDNSClientSession"))
            {
                _session.EnableProvider("Microsoft-Windows-DNS-Client");
                _session.Source.Dynamic.All += DnsClientEvent;
                _session.Source.Process();
            }

        }

        private void ProcessDnsQuery(dynamic data, string processName)
        {
            string retrievedQuery = data.PayloadByName("QueryName").ToString().Trim();
            string dnsDomainQueried = string.IsNullOrWhiteSpace(retrievedQuery) ? "N/A" : retrievedQuery;
            int queryTypeCode = 0;
            if (!int.TryParse(data.PayloadByName("QueryType").ToString(), out queryTypeCode))
            {
                ConsoleOutput.Print($"Attempted to parse retrieved DNS Query type. Failed to parse it", PrintType.Debug);
                queryTypeCode = 999999; // Non-existing DNS type value. Is later looked up
            }
            string dnsRecordTypeCodeName = DnsCodeLookup.GetDnsTypeName(queryTypeCode); // Retrieve the DNS type code name

            DNSQuery dnsQuery = new DNSQuery
            {
                DomainQueried = dnsDomainQueried,
                RecordTypeCode = queryTypeCode,
                RecordTypeText = dnsRecordTypeCodeName
            };

            Program.CatalogETWActivity(eventType: EventType.DNSQuery,
                  processName: processName,
                  processID: data.ProcessID,
                  dnsQuery: dnsQuery);
        }

        private void ProcessDnsResponse(dynamic data, string processName)
        {
            string retrievedQuery = data.PayloadByName("QueryName").ToString().Trim();
            string dnsQuery = string.IsNullOrWhiteSpace(retrievedQuery) ? "N/A" : retrievedQuery;
            string retrievedQueryResults = data.PayloadByName("QueryResults").ToString().Trim();

            int queryTypeCode;
            int queryStatusCode;

            if (!int.TryParse(data.PayloadByName("QueryStatus").ToString(), out queryStatusCode))
            {
                ConsoleOutput.Print($"Attempted to parse retrieved DNS Query status. Failed to parse it", PrintType.Debug);
                queryStatusCode = Constants.Miscellaneous.NotApplicableStatusNumber; // Non-existing DNS status value. Is later looked up
            }
            if (!int.TryParse(data.PayloadByName("QueryType").ToString(), out queryTypeCode))
            {
                ConsoleOutput.Print($"Attempted to parse retrieved DNS Query type. Failed to parse it", PrintType.Debug);
                queryTypeCode = Constants.Miscellaneous.NotApplicableStatusNumber; // Non-existing DNS type value. Is later looked up
            }

            string dnsRecordTypeCodeName = DnsCodeLookup.GetDnsTypeName(queryTypeCode); // Retrieve the DNS type code name
            string dnsResponseStatusCodeName = DnsCodeLookup.GetDnsStatusName(queryStatusCode); // Retrieve the DNS response status code name

            DNSResponse dnsResponseQuery = new DNSResponse
            {
                DomainQueried = retrievedQuery,
                RecordTypeCode = queryTypeCode,
                RecordTypeText = dnsRecordTypeCodeName,
                StatusCode = queryStatusCode,
                StatusText = dnsResponseStatusCodeName,
                QueryResult = NetworkUtils.ParseDNSResult(retrievedQueryResults)
            };

            Program.CatalogETWActivity(eventType: EventType.DNSResponse,
                    processName: processName,
                    processID: data.ProcessID,
                    dnsResponse: dnsResponseQuery);
        }

        private void DnsClientEvent(TraceEvent data)
        {
            switch (data.EventName)
            {
                case "EventID(3006)":
                    {
                        if (Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName))
                        {
                            string processName = Program.GetMonitoredProcessName(pid: data.ProcessID, processName: data.ProcessName);
                            ProcessDnsQuery(data, processName);
                        }
                        else if ((Program.TrackProcessesByName() && Program.IsTrackedProcessByName(pid: data.ProcessID, processName: data.ProcessName)) || Program.MonitorEverything())
                        {
                            string processName = Program.GetNewProcessName(pid: data.ProcessID, processName: data.ProcessName);

                            Program.AddProcessToMonitor(pid: data.ProcessID, processName: processName);

                            if (string.IsNullOrEmpty(processName) || processName == Constants.Miscellaneous.ProcessDefaultNameAtError)
                            {
                                processName = Program.GetBackupProcessName(data.ProcessID);
                            }

                            ProcessDnsQuery(data, processName);
                        }
                        break;
                    }
                case "EventID(3008)":
                    {
                        if (Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName))
                        {
                            string processName = Program.GetMonitoredProcessName(pid: data.ProcessID, processName: data.ProcessName);
                            ProcessDnsResponse(data, processName);
                        }
                        else if ((Program.TrackProcessesByName() && Program.IsTrackedProcessByName(pid: data.ProcessID, processName: data.ProcessName)) || Program.MonitorEverything())
                        {

                            string processName = Program.GetNewProcessName(pid: data.ProcessID, processName: data.ProcessName);

                            Program.AddProcessToMonitor(pid: data.ProcessID, processName: processName);

                            if (string.IsNullOrEmpty(processName) || processName == Constants.Miscellaneous.ProcessDefaultNameAtError)
                            {
                                processName = Program.GetBackupProcessName(data.ProcessID);
                            }

                            ProcessDnsResponse(data, processName);
                        }
                        break;
                }
                default:
                    {
                        break;
                    }
            }
        }
    }
}
