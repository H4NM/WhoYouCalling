using System.Net;

namespace WhoYouCalling.Network.DNS
{
    public class DNSResponseResult 
    {
        public int BundledRecordTypeCode { get; set; }
        public string BundledRecordTypeText { get; set; }
        public string BundledDomainQueried { get; set; }
        public List<string> IPs { get; set; }
        public bool IPv4MappedIPv6Adresses { get; set; }


        public override bool Equals(object obj)
        {
            if (obj == null || this.GetType() != obj.GetType())
                return false;

            var other = (DNSResponseResult)obj;
            return IPs == other.IPs &&
                   BundledRecordTypeCode == other.BundledRecordTypeCode &&
                   BundledRecordTypeText == other.BundledRecordTypeText &&
                   BundledDomainQueried == other.BundledDomainQueried &&
                   IPv4MappedIPv6Adresses == other.IPv4MappedIPv6Adresses;
        }

        public override int GetHashCode()
        {
            int hash = 17;
            hash = hash * 31 + (IPs != null ? IPs.GetHashCode() : 0);
            hash = hash * 31 + BundledRecordTypeCode.GetHashCode();
            hash = hash * 31 + (BundledRecordTypeText != null ? BundledRecordTypeText.GetHashCode() : 0);
            hash = hash * 31 + (BundledDomainQueried != null ? BundledDomainQueried.GetHashCode() : 0);
            hash = hash * 31 + IPv4MappedIPv6Adresses.GetHashCode();
            return hash;
        }
    }
}
