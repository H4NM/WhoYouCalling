using WhoYouCalling.Network.DNS;
using WhoYouCalling.Process;

namespace WhoYouCalling.Summary
{
    public struct DNSResponsesSummary
    {
        public string UniqueBundledRecordTypeText { get; set; }
        public int UniqueHostsResolvedCount { get; set; }

        public DNSResponsesSummary(MonitoredProcess monitoredProcess)
        {
            HashSet<string> bundledRecordTypesTexts = new();
            HashSet<string> resolvedIPs = new();

            foreach (DNSResponse dnsResponse in monitoredProcess.DNSResponses)
            {
                if (!string.IsNullOrEmpty(dnsResponse.QueryResult.BundledRecordTypeText))
                {
                    bundledRecordTypesTexts.Add(dnsResponse.QueryResult.BundledRecordTypeText);
                }

                foreach (string dnsResponseResultIP in dnsResponse.QueryResult.IPs)
                {
                    resolvedIPs.Add(dnsResponseResultIP);
                }
            }


            UniqueBundledRecordTypeText = GetBundledRecordTypeText(bundledRecordTypesTexts);
            UniqueHostsResolvedCount = GetResolvedIPsCount(resolvedIPs);
        }
    
        private static string GetBundledRecordTypeText(HashSet<string> bundledRecordTypes)
        {
            return string.Join(", ", bundledRecordTypes);
        }
        private static int GetResolvedIPsCount(HashSet<string> resolvedIPs)
        {
            return resolvedIPs.Count;
        }
    }
}