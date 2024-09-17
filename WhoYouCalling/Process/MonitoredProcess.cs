using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;

namespace WhoYouCalling.Process
{
    public class MonitoredProcess
    {
        public string ImageName { get; set; } = "";
        public List<int> ChildProcess { get; set; } = new List<int>();
        public HashSet<DNSQuery> DNSQueries { get; set; } = new HashSet<DNSQuery>();
        public HashSet<DestinationEndpoint> IPv4TCPEndpoint { get; set; } = new HashSet<DestinationEndpoint>();
        public HashSet<DestinationEndpoint> IPv6TCPEndpoint { get; set; } = new HashSet<DestinationEndpoint>();
        public HashSet<DestinationEndpoint> IPv4UDPEndpoint { get; set; } = new HashSet<DestinationEndpoint>();
        public HashSet<DestinationEndpoint> IPv6UDPEndpoint { get; set; } = new HashSet<DestinationEndpoint>();
        public HashSet<DestinationEndpoint> IPv4LocalhostEndpoint { get; set; } = new HashSet<DestinationEndpoint>();
        public HashSet<DestinationEndpoint> IPv6LocalhostEndpoint { get; set; } = new HashSet<DestinationEndpoint>();
    }
}