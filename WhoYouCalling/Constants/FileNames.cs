
namespace WhoYouCalling.Constants
{
    static class FileNames
    {
        //// Root folder
        public const string RootFolderEntirePcapFileName = "Full network packet capture.pcap";
        public const string RootFolderAllProcessesFilteredPcapFileName = "All processes network packets.pcap";
        public const string RootFolderDFLFilterFileName = "All processes wireshark filter.txt";
        public const string RootFolderBPFFilterFileName = "All processes BPF-filter.txt";
        public const string RootFolderETWHistoryFileName = "ETW history.txt";
        public const string RootFolderJSONProcessDetailsFileName = "Process details.json";
        public const string RootFolderJSONDNSResponseFileName = "DNS responses.json";

        //// Per Process
        public const string ProcessFolderPcapFileName = "Network packets.pcap";
        public const string ProcessFolderBPFFilterFileName = "BPF-filter.txt";
        public const string ProcessFolderDFLFilterFileName = "Wireshark filter.txt";
        public const string ProcessFolderDNSQueriesFileName = "DNS queries.txt";
        public const string ProcessFolderIPv4TCPEndpoints = "IPv4 TCP Endpoints.txt";
        public const string ProcessFolderIPv6TCPEndpoints = "IPv6 TCP Endpoints.txt";
        public const string ProcessFolderIPv4UDPEndpoints = "IPv4 UDP Endpoints.txt";
        public const string ProcessFolderIPv6UDPEndpoints = "IPv6 UDP Endpoints.txt";
        public const string ProcessFolderIPv4LocalhostEndpoints = "Localhost Endpoints.txt";
        public const string ProcessFolderIPv6LocalhostEndpoints = "Localhost Endpoints IPv6.txt";
        public const string ProcessFolderDNSWiresharkFolderName = "Domain Wireshark filters";
    }
}
