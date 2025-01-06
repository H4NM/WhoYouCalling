
namespace WhoYouCalling.Constants
{
    static class FileNames
    {
        //// Root folder
        public const string RootFolderEntirePcapFileName = "Unfiltered packet capture.pcap";
        public const string RootFolderAllProcessesFilteredPcapFileName = "Combined processes packets.pcap";
        public const string RootFolderDFLFilterFileName = "Combined wireshark filter.txt";
        public const string RootFolderBPFFilterFileName = "Combined BPF-filter.txt";
        public const string RootFolderETWHistoryFileName = "Events.txt";
        public const string RootFolderJSONProcessDetailsFileName = "Result.json";
        public const string RootFolderSummaryProcessDetailsFileName = "Summary.txt";


        //// Per Process
        public const string ProcessFolderPcapFileName = "Packet capture.pcap";
        public const string ProcessFolderBPFFilterFileName = "BPF-filter.txt";
        public const string ProcessFolderDFLFilterFileName = "Wireshark filter.txt";
        public const string ProcessFolderDNSQueriesFileName = "DNS queries.txt";
        public const string ProcessFolderDNSQueryResponsesFileName = "DNS query responses.txt";
        public const string ProcessFolderIPv4TCPEndpoints = "IPv4 TCP endpoints.txt";
        public const string ProcessFolderIPv6TCPEndpoints = "IPv6 TCP endpoints.txt";
        public const string ProcessFolderIPv4UDPEndpoints = "IPv4 UDP endpoints.txt";
        public const string ProcessFolderIPv6UDPEndpoints = "IPv6 UDP endpoints.txt";
        public const string ProcessFolderIPv4LocalhostEndpoints = "Localhost endpoints IPv4.txt";
        public const string ProcessFolderIPv6LocalhostEndpoints = "Localhost endpoints IPv6.txt";
        public const string ProcessFolderDNSWiresharkFolderName = "Domain wireshark filters";
    }
}
