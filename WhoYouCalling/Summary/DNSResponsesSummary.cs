using WhoYouCalling.Network.DNS;
using WhoYouCalling.Process;

namespace WhoYouCalling.Summary
{
    public struct DNSResponsesSummary
    {
        public int UniqueDomainsCount { get; set; }
        public string UniqueTopLevelDomainsText { get; set; }
        public string UniqueDNSRecordTypesText { get; set; }
        public string UniqueDNSStatusText { get; set; }
        public string UniqueBundledRecordTypeText { get; set; }
        public int UniqueHostsResolvedCount { get; set; }

        public DNSResponsesSummary(MonitoredProcess monitoredProcess)
        {
            HashSet<string> domains = new();
            HashSet<string> recordTypes = new();
            HashSet<string> responseStatusTexts = new();
            HashSet<string> bundledRecordTypesTexts = new();
            HashSet<string> resolvedIPs = new();

            foreach (DNSResponse dnsResponse in monitoredProcess.DNSResponses)
            {
                domains.Add(dnsResponse.DomainQueried);
                recordTypes.Add(dnsResponse.RecordTypeText);
                responseStatusTexts.Add(dnsResponse.StatusText);
                if (dnsResponse.QueryResult.BundledRecordTypeText != null)
                {
                    bundledRecordTypesTexts.Add(dnsResponse.QueryResult.BundledRecordTypeText);
                }

                foreach (string dnsResponseResultIP in dnsResponse.QueryResult.IPs)
                {
                    resolvedIPs.Add(dnsResponseResultIP);
                }
            }

            UniqueDomainsCount = GetDomainsText(domains);
            UniqueTopLevelDomainsText = GetTLDText(domains);
            UniqueDNSRecordTypesText = GetRecordTypesText(recordTypes);

            UniqueDNSStatusText = GetStatusText(responseStatusTexts);
            UniqueBundledRecordTypeText = GetBundledRecordTypeText(bundledRecordTypesTexts);
            UniqueHostsResolvedCount = GetResolvedIPsCount(resolvedIPs);
        }
        private static string GetStatusText(HashSet<string> responseStatusTexts)
        {
            return string.Join(", ", responseStatusTexts);
        }
        private static string GetBundledRecordTypeText(HashSet<string> bundledRecordTypes)
        {
            return string.Join(", ", bundledRecordTypes);
        }
        private static int GetResolvedIPsCount(HashSet<string> resolvedIPs)
        {
            return resolvedIPs.Count;
        }
        private static int GetDomainsText(HashSet<string> domains)
        {
            return domains.Count;
        }
        private static string GetTLDText(HashSet<string> domains)
        {
            HashSet<string> topLevelDomains = new();
            string tld = "";
            foreach (string domain in domains)
            {
                tld = domain.Split(".").Last();
                topLevelDomains.Add(tld);
            }
            return string.Join(", ", topLevelDomains);
        }
        private static string GetRecordTypesText(HashSet<string> recordTypes)
        {
            return string.Join(", ", recordTypes);
        }
    }
}