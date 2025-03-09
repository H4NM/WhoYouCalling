
using WhoYouCalling.Network;
using WhoYouCalling.Process;

namespace WhoYouCalling.Summary
{
    public struct TCPIPSummary
    {
        public string IPversionsText { get; set; }
        public string TransportProtocolsText { get; set; }
        public HashSet<string> UniqueIPs { get; set; }
        public string OnlyLocalhostTrafficText { get; set; }

        public TCPIPSummary(MonitoredProcess monitoredProcess)
        {
            HashSet<IPVersion> ipVersions = new();
            HashSet<TransportProtocol> transportProtocols = new();
            HashSet<string> destinationHosts = new();
            List<string> destinationPortsAndProtocol = new();
            bool onlyLocalhostTraffic = true;

            foreach (ConnectionRecord connectionRecord in monitoredProcess.TCPIPTelemetry)
            {
                ipVersions.Add(connectionRecord.IPversion);
                transportProtocols.Add(connectionRecord.TransportProtocol);
                destinationHosts.Add(connectionRecord.DestinationIP);
                string ipType = "";
                if (NetworkUtils.IsLocalhostIP(connectionRecord.DestinationIP))
                {
                    ipType = "Localhost";
                }
                else
                {
                    ipType = "External IP";
                    onlyLocalhostTraffic = false;
                }
                destinationPortsAndProtocol.Add($"{connectionRecord.DestinationPort} {connectionRecord.TransportProtocol} {ipType}");
            }

            IPversionsText = GetIPVersionText(ipVersions);
            TransportProtocolsText = GetTransportProtocolText(transportProtocols);
            UniqueIPs = destinationHosts;
            OnlyLocalhostTrafficText = GetIfOnlyLocalhostTrafficText(onlyLocalhostTraffic);
        }

        private static string GetIfOnlyLocalhostTrafficText(bool onlyLocalhostTraffic)
        {
            if (onlyLocalhostTraffic)
            {
                return "Only localhost traffic";
            }
            else
            {
                return "Contacted external IPs";
            }
        }

        private static string GetIPVersionText(HashSet<IPVersion> ipVersions)
        {
            return string.Join(" and ", ipVersions);
        }
        private static string GetTransportProtocolText(HashSet<TransportProtocol> transportProtocols)
        {
            return string.Join(" and ", transportProtocols);
        }
    }
}