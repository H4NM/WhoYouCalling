namespace WhoYouCalling.Utilities
{
    public class MonitoredProcess
    {
        public string imageName { get; set; }
        public List<int> childprocess { get; set; } = new List<int>();
        public HashSet<string> dnsQueries { get; set; } = new HashSet<string>();
        public HashSet<string> ipv4TCPEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> ipv6TCPEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> ipv4UDPEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> ipv6UDPEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> ipv4LocalhostEndpoint { get; set; } = new HashSet<string>();
        public HashSet<string> ipv6LocalhostEndpoint { get; set; } = new HashSet<string>();
    }
}