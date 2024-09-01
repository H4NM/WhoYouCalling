namespace WhoYouCalling.Utilities
{
    public class MonitoredProcess
    {
        public string ImageName { get; set; } = "";
        public List<int> ChildProcess { get; set; } = new List<int>();
        public HashSet<string> DNSQueries { get; set; } = new HashSet<string>();
        public HashSet<string> IPv4TCPEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> IPv6TCPEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> IPv4UDPEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> IPv6UDPEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> IPv4LocalhostEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> IPv6LocalhostEndpoint { get; set; } = new HashSet<string>();
    }
}