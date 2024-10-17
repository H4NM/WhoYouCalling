using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;

namespace WhoYouCalling.Process
{
    public class MonitoredProcess
    {
        public string ImageName { get; set; } = "";
        public List<int> ChildProcess { get; set; } = new List<int>();
        public HashSet<DNSQuery> DNSQueries { get; set; } = new HashSet<DNSQuery>();
        public HashSet<NetworkEndpoint> IPv4TCPEndpoint { get; set; } = new HashSet<NetworkEndpoint>();
        public HashSet<NetworkEndpoint> IPv6TCPEndpoint { get; set; } = new HashSet<NetworkEndpoint>();
        public HashSet<NetworkEndpoint> IPv4UDPEndpoint { get; set; } = new HashSet<NetworkEndpoint>();
        public HashSet<NetworkEndpoint> IPv6UDPEndpoint { get; set; } = new HashSet<NetworkEndpoint>();
        public HashSet<NetworkEndpoint> IPv4LocalhostEndpoint { get; set; } = new HashSet<NetworkEndpoint>();
        public HashSet<NetworkEndpoint> IPv6LocalhostEndpoint { get; set; } = new HashSet<NetworkEndpoint>();
    }
}