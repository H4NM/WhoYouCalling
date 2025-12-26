using System.Net;
using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;
using WhoYouCalling.Process;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.Summary
{
    public struct RuntimeSummary
    {
        public string WYCCommandline { get; set; }
        public string WYCVersion { get; set; }
        public string Hostname { get; set; }
        public string HostOS { get; set; }
        public DateTime StartTime { get; set; }
        public DateTime StopTime { get; set; }
        public string PresentableDuration { get; set; }
        public int NumberOfProcesses { get; set; }
        public int NumberOfProcessesWithNetworkActivity { get; set; }

        public RuntimeSummary(List<MonitoredProcess> monitoredProcesses)
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

            WYCCommandline = Program.GetFullProgramCommandLine();
            WYCVersion= Generic.GetVersion();
            Hostname = Generic.GetHostname();
            HostOS = Generic.GetOS();
            StartTime = Program.GetStartTime();
            StopTime = Program.GetStopTime();
            PresentableDuration = Generic.GetPresentableDuration(startTime: Program.GetStartTime(), endTime: Program.GetStopTime());
            NumberOfProcesses = monitoredProcesses.Count;
            NumberOfProcessesWithNetworkActivity = ProcessManager.GetNumberOfProcessesWithNetworkTraffic(monitoredProcesses);
        }
    }
}