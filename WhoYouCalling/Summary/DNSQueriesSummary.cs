
using WhoYouCalling.Network.DNS;
using WhoYouCalling.Process;

namespace WhoYouCalling.Summary
{
    public struct DNSQueriesSummary
    {
        public HashSet<string> UniqueDomains { get; set; }
        public string UniqueTopLevelDomainsText { get; set; }
        public string UniqueDNSRecordTypesText { get; set; }

        public DNSQueriesSummary(MonitoredProcess monitoredProcess)
        {
            HashSet<string> domains = new();
            HashSet<string> recordTypes = new();

            foreach (DNSQuery dnsQueries in monitoredProcess.DNSQueries)
            {
                domains.Add(dnsQueries.DomainQueried);
                recordTypes.Add(dnsQueries.RecordTypeText);
            }

            UniqueDomains = domains;
            UniqueTopLevelDomainsText = GetTLDText(domains);
            UniqueDNSRecordTypesText = GetRecordTypesText(recordTypes);
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