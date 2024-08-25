using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;


namespace WhoYouCalling.ETW
{
    public class DNSClientListener : Listener
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
            if (_trackedProcessId == data.ProcessID && data.EventName == "EventID(3006)") // DNS Lookup made by main tracked PID
            {
                string dnsQuery = data.PayloadByName("QueryName").ToString();
                dnsQuery ??= "N/A";
                Program.CatalogETWActivity(eventType: "dnsquery",
                    executable: _mainExecutableFileName,
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
}