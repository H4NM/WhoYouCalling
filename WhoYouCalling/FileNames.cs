
namespace WhoYouCalling
{
    static class FileNames
    {
        //// Root folder
        public const string RootFolderEntirePcapFileName = "Unfiltered packets.pcap";
        public const string RootFolderAllProcessesFilteredPcapFileName = "Combined packets.pcap";
        public const string RootFolderDFLFilterFileName = "Combined DFL-filter.txt";
        public const string RootFolderBPFFilterFileName = "Combined BPF-filter.txt";
        public const string RootFolderETWHistoryFileName = "Events.txt";
        public const string RootFolderJSONProcessDetailsFileName = "Result.json";

        //// Per Process
        public const string ProcessFolderPcapFileName = "packets.pcap";
        public const string ProcessFolderProcessInformation = "proc.txt";
        public const string ProcessFolderBPFFilterFileName = "BPF-filter.txt";
        public const string ProcessFolderDFLFilterFileName = "DFL-filter.txt";
        public const string ProcessFolderDNSQueriesFileName = "DNS-queries.txt";
        public const string ProcessFolderDNSQueryResponsesFileName = "DNS-responses.txt";
        public const string ProcessFolderIPv4TCPEndpoints = "IPv4-TCP-endpoints.txt";
        public const string ProcessFolderIPv6TCPEndpoints = "IPv6-TCP-endpoints.txt";
        public const string ProcessFolderIPv4UDPEndpoints = "IPv4-UDP-endpoints.txt";
        public const string ProcessFolderIPv6UDPEndpoints = "IPv6-UDP-endpoints.txt";
        public const string ProcessFolderIPv4LocalhostEndpoints = "IPv4-localhost-endpoints.txt";
        public const string ProcessFolderIPv6LocalhostEndpoints = "IPv6-localhost-endpoints.txt";
        public const string ProcessFolderDNSWiresharkFolderName = "DFL-filters";

    }
}
