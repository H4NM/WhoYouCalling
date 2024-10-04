using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using WhoYouCalling.Network.DNS;
using WhoYouCalling.Utilities;
using WhoYouCalling.WhoYouCalling.Network;

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

        private void DnsClientEvent(TraceEvent data)
        {
            switch (data.EventName)
            {
                case "EventID(3006)":
                    {
                        if (IsAMonitoredProcess(data.ProcessID))
                        {
                            string retrievedQuery = data.PayloadByName("QueryName").ToString().Trim();
                            string dnsDomainQueried = string.IsNullOrWhiteSpace(retrievedQuery) ? "N/A" : retrievedQuery;
                            int queryTypeCode = 0;
                            if (!int.TryParse(data.PayloadByName("QueryType").ToString(), out queryTypeCode))
                            {
                                ConsoleOutput.Print($"Attempted to parse retrieved DNS Query type. Failed to parse it", PrintType.Debug);
                                queryTypeCode = 999999; // Non-existing DNS type value. Is later looked up
                            }
                            string dnsRecordTypeCodeName = DnsTypeLookup.GetName(queryTypeCode); // Retrieve the DNS type code name

                            DNSQuery dnsQuery = new DNSQuery
                            {
                                DomainQueried = dnsDomainQueried,
                                RecordTypeCode = queryTypeCode,
                                RecordTypeText = dnsRecordTypeCodeName
                            };

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
                            Program.CatalogETWActivity(eventType: EventType.DNSQuery,
                                  executable: executable,
                                  execPID: data.ProcessID,
                                  execType: execType,
                                  dnsQuery: dnsQuery);
                        }
                        break;
                    }
                case "EventID(3008)":
                    {
                        if (IsAMonitoredProcess(data.ProcessID))
                        {
                            string retrievedQuery = data.PayloadByName("QueryName").ToString().Trim();
                            string dnsQuery = string.IsNullOrWhiteSpace(retrievedQuery) ? "N/A" : retrievedQuery;
                            string retrievedQueryResults = data.PayloadByName("QueryResults").ToString().Trim();

                            int queryTypeCode;
                            int queryStatusCode;
                            string executable;
                            string execType;

                            if (!int.TryParse(data.PayloadByName("QueryStatus").ToString(), out queryStatusCode))
                            {
                                ConsoleOutput.Print($"Attempted to parse retrieved DNS Query status. Failed to parse it", PrintType.Debug);
                                queryStatusCode = 999999; // Non-existing DNS status value. Is later looked up
                            }
                            if (!int.TryParse(data.PayloadByName("QueryType").ToString(), out queryTypeCode))
                            {
                                ConsoleOutput.Print($"Attempted to parse retrieved DNS Query type. Failed to parse it", PrintType.Debug);
                                queryTypeCode = 999999; // Non-existing DNS type value. Is later looked up
                            }

                            string dnsRecordTypeCodeName = DnsTypeLookup.GetName(queryTypeCode); // Retrieve the DNS type code name
                            string dnsResponseStatusCodeName = DnsStatusLookup.GetName(queryStatusCode); // Retrieve the DNS response status code name

                            DNSResponse dnsResponseQuery = new DNSResponse
                            {
                                DomainQueried = retrievedQuery,
                                RecordTypeCode = queryTypeCode,
                                RecordTypeText = dnsRecordTypeCodeName,
                                StatusCode = queryStatusCode,
                                StatusText = dnsResponseStatusCodeName,
                                QueryResult = NetworkUtils.ParseDNSResult(retrievedQueryResults)
                            };

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

                            Program.CatalogETWActivity(eventType: EventType.DNSResponse,
                                    executable: executable,
                                    execPID: data.ProcessID,
                                    execType: execType,
                                    dnsResponse: dnsResponseQuery);
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
