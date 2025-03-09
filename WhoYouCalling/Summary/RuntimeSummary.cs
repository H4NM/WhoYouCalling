using System.Net;
using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;
using WhoYouCalling.Process;

namespace WhoYouCalling.Summary
{
    public struct RuntimeSummary
    {
        public string WYCCommandline { get; set; }
        public string WYCVersion { get; set; }
        public string Hostname { get; set; }
        public DateTime StartTime { get; set; }
        public string PresentableDuration { get; set; }
        public int NumberOfProcesses { get; set; }
        public int NumberOfProcessesWithNetworkActivity { get; set; }
        public int NumberOfUniqueDomainsQueried { get; set; }

        public RuntimeSummary(List<MonitoredProcess> monitoredProcesses, DateTime startTime, string presentableMonitorDuration, int processesWithnetworkActivity)
        {
            HashSet<string> uniqueDomains = new();
            List<string> destinationPortsAndProtocol = new();

            foreach (MonitoredProcess monitoredProcess in monitoredProcesses)
            {
                foreach (ConnectionRecord connectionRecord in monitoredProcess.TCPIPTelemetry)
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

                foreach (DNSQuery dnsQueries in monitoredProcess.DNSQueries)
                {
                    uniqueDomains.Add(dnsQueries.DomainQueried);
                }
            }

            WYCCommandline = GetFullWYCCommandLine();
            WYCVersion= Utilities.Generic.GetVersion();
            Hostname = GetHostname();
            StartTime = startTime;
            PresentableDuration = presentableMonitorDuration;
            NumberOfProcesses = monitoredProcesses.Count;
            NumberOfProcessesWithNetworkActivity = processesWithnetworkActivity;
        }
        private static string GetHostname()
        {
            try
            {
                string fqdn = System.Net.Dns.GetHostEntry("").HostName;
                return !string.IsNullOrWhiteSpace(fqdn) ? fqdn : Environment.MachineName;
            }
            catch
            {
                return Environment.MachineName;
            }
        }
        private static string GetFullWYCCommandLine()
        {
            string[] commandLineArgs = Environment.GetCommandLineArgs();
            return $"wyc.exe {string.Join(" ", commandLineArgs, 1, commandLineArgs.Length - 1)}"; 
        }
    }
}