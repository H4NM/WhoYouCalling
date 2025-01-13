
namespace WhoYouCalling.Network.DNS
{
    public class DNSResponseResult
    {
        public int BundledRecordTypeCode { get; set; } 
        public string BundledRecordTypeText { get; set; } = string.Empty;
        public string BundledDomain { get; set; } = string.Empty;
        public List<string> IPs { get; set; }

        public override bool Equals(object? obj)
        {
            if (obj == null || this.GetType() != obj.GetType())
                return false;

            var other = (DNSResponseResult)obj;
            return BundledRecordTypeCode == other.BundledRecordTypeCode &&
                   BundledRecordTypeText == other.BundledRecordTypeText &&
                   BundledDomain == other.BundledDomain &&
                   IPs.SequenceEqual(other.IPs);
        }

        public override int GetHashCode()
        {
            int hash = 17;
            hash = hash * 31 + (BundledRecordTypeText != null ? BundledRecordTypeText.GetHashCode() : 0);
            hash = hash * 31 + BundledRecordTypeCode.GetHashCode();
            hash = hash * 31 + (BundledDomain != null ? BundledDomain.GetHashCode() : 0);
            if (IPs != null)
            {
                foreach (var ip in IPs)
                {
                    hash = hash * 31 + (ip != null ? ip.GetHashCode() : 0);
                }
            }
            return hash;
        }
    }
}
