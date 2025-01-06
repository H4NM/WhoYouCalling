using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;
using WhoYouCalling.Process;

namespace WhoYouCalling.Summary
{
    public struct RuntimeSummary
    {
        public string WYCCommandline { get; set; }
        public DateTime StartTime { get; set; }
        public string PresentableDuration { get; set; }
        public int NumberOfProcesses { get; set; }
        public int NumberOfProcessesWithNetworkActivity { get; set; }
        public List<string> MostCommonConnections { get; set; }
        public int NumberOfUniqueDomainsQueried { get; set; }
        public string TopLevelDomains { get; set; }

        public RuntimeSummary(List<MonitoredProcess> monitoredProcesses, DateTime startTime, string presentableMonitorDuration, int processesWithnetworkActivity)
        {
            HashSet<string> uniqueDomains = new();
            List<string> destinationPortsAndProtocol = new();

            foreach (MonitoredProcess monitoredProcess in monitoredProcesses)
            {
                foreach (ConnectionRecord connectionRecord in monitoredProcess.TCPIPTelemetry)
                {
                    if (!NetworkUtils.IsLocalhostIP(connectionRecord.DestinationIP))
                    {
                        string ipType = "";
                        if (NetworkUtils.IsLocalhostIP(connectionRecord.DestinationIP))
                        {
                            ipType = "Localhost";
                        }
                        else
                        {
                            ipType = "External IP";
                        }
                        destinationPortsAndProtocol.Add($"{connectionRecord.DestinationPort} {connectionRecord.TransportProtocol} {ipType}");
                    }
                }

                foreach (DNSQuery dnsQueries in monitoredProcess.DNSQueries)
                {
                    uniqueDomains.Add(dnsQueries.DomainQueried);
                }
            }

            WYCCommandline = GetFullWYCCommandLine();
            StartTime = startTime;
            PresentableDuration = presentableMonitorDuration;
            NumberOfProcesses = monitoredProcesses.Count;
            NumberOfProcessesWithNetworkActivity = processesWithnetworkActivity;
            TopLevelDomains = GetTLDText(uniqueDomains);
            MostCommonConnections = GetFiveMostCommonConnections(destinationPortsAndProtocol, maxNumberOfPorts: 5);
            NumberOfUniqueDomainsQueried = uniqueDomains.Count;
        }
        private static string GetFullWYCCommandLine()
        {
            string[] commandLineArgs = Environment.GetCommandLineArgs();
            return $"wyc.exe {string.Join(" ", commandLineArgs, 1, commandLineArgs.Length - 1)}"; 
        }
        private static string GetTLDText(HashSet<string> uniqueDomains)
        {
            HashSet<string> topLevelDomains = new();
            string tld = "";
            foreach (string domain in uniqueDomains)
            {
                if (domain.Contains("."))
                {
                    tld = domain.Split(".").Last();
                    if (!string.IsNullOrEmpty(tld))
                    {
                        topLevelDomains.Add(tld);
                    }
                }
            }
            return string.Join(", ", topLevelDomains);
        }
        private static List<string> GetFiveMostCommonConnections(List<string> destinationPortsAndProtocol, int maxNumberOfPorts)
        {
            return Utilities.Generic.GetMostCommonStringOccurrances(destinationPortsAndProtocol, maxNumberOfPorts);
        }
    }
}