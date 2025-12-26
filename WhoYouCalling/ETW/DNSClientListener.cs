using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using WhoYouCalling.Network.DNS;
using WhoYouCalling.Utilities;
using WhoYouCalling.Network;

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
            _session = new TraceEventSession("WhoYouCallingDNSClientSession");
            _session.EnableProvider("Microsoft-Windows-DNS-Client");
            _session.Source.Dynamic.All += DnsClientEvent;
            _session.Source.Process();
        }

        private void ProcessDnsQuery(dynamic data, string processName)
        {
            string retrievedQuery = data.PayloadByName("QueryName").ToString().Trim();
            string dnsDomainQueried = string.IsNullOrWhiteSpace(retrievedQuery) ? "N/A" : retrievedQuery;

            int queryTypeCode = 0;
            if (!int.TryParse(data.PayloadByName("QueryType").ToString(), out queryTypeCode))
            {
                queryTypeCode = Constants.Miscellaneous.NotApplicableStatusNumber; // Non-existing DNS type value. Is later looked up
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
                queryStatusCode = Constants.Miscellaneous.NotApplicableStatusNumber; // Non-existing DNS status value. Is later looked up
            }
            if (!int.TryParse(data.PayloadByName("QueryType").ToString(), out queryTypeCode))
            {
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
                case "EventID(3006)": // DNS Query
                    {
                        
                        if (Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName))
                        {
                            string processName = Program.GetMonitoredProcessName(pid: data.ProcessID, processName: data.ProcessName);
                            ProcessDnsQuery(data, processName);
                        }
                        else if (Program.MonitorEverything())
                        {
                            string processName = Program.GetNewProcessName(pid: data.ProcessID, processName: data.ProcessName);

                            if (!Program.IsMonitoredProcess(pid: data.ProcessID, processName: processName)) // This is to deal with race conditions as the DNS ETW registers before process starts sometimes, where it is added before the actual process is started
                            {
                                Program.AddProcessToMonitor(pid: data.ProcessID, processName: processName);
                            }

                            ProcessDnsQuery(data, processName);
                        }
                        break;
                    }
                case "EventID(3008)": // DNS Response
                    {

                        if (Program.IsMonitoredProcess(pid: data.ProcessID, processName: data.ProcessName))
                        {
                            string processName = Program.GetMonitoredProcessName(pid: data.ProcessID, processName: data.ProcessName);
                            ProcessDnsResponse(data, processName);
                        }
                        else if (Program.MonitorEverything())
                        {
                            string processName = Program.GetNewProcessName(pid: data.ProcessID, processName: data.ProcessName);

                            if (!Program.IsMonitoredProcess(pid: data.ProcessID, processName: processName)) // This is to deal with race conditions as the DNS ETW registers before process starts sometimes, where it is added before the actual process is started
                            {
                                Program.AddProcessToMonitor(pid: data.ProcessID, processName: processName);
                            }

                            ProcessDnsResponse(data, processName);
                        }
                        break;
                }
            }
            /*
            == Other Events for when eventuelly enriching if responses were cached or remote == 
            EventID(3009) - Initial event requesting DNS lookup
            EventID(3010) - DNS query sent to specific DNS server for provided domain name
            EventID(3011) - A DNS response was received from DNS server for requested domain name 
            EventID(3016) - DNS Cache query was requested for domain 
            EventID(3018) - DNS Cache query for domain was made
            EventID(3019) - DNS Query hread was called for domain 
            EventID(3020) - DNS Query response for domain returned with result 
            */
        }
    }
}
