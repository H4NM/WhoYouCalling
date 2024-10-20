using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;

namespace WhoYouCalling.Process
{
    public class MonitoredProcess
    {
        public string ImageName { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public List<int> ChildProcess { get; set; } = new();
        public HashSet<DNSQuery> DNSQueries { get; set; } = new();
        public HashSet<NetworkEndpoint> IPv4TCPEndpoint { get; set; } = new();
        public HashSet<NetworkEndpoint> IPv6TCPEndpoint { get; set; } = new();
        public HashSet<NetworkEndpoint> IPv4UDPEndpoint { get; set; } = new();
        public HashSet<NetworkEndpoint> IPv6UDPEndpoint { get; set; } = new();
        public HashSet<NetworkEndpoint> IPv4LocalhostEndpoint { get; set; } = new();
        public HashSet<NetworkEndpoint> IPv6LocalhostEndpoint { get; set; } = new();
    }
}