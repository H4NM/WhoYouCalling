using System.Net;

namespace WhoYouCalling.Network.DNS
{
    public class DNSQuery 
    {
        public string DomainQueried { get; set; } 
        public int RecordTypeCode { get; set; }
        public string RecordTypeText { get; set; }

        public override bool Equals(object obj)
        {
            if (obj == null || this.GetType() != obj.GetType())
                return false;

            var other = (DNSQuery)obj;
            return DomainQueried == other.DomainQueried &&
                   RecordTypeCode == other.RecordTypeCode &&
                   RecordTypeText == other.RecordTypeText;
        }

        public override int GetHashCode()
        {
            int hash = 17;
            hash = hash * 31 + (DomainQueried != null ? DomainQueried.GetHashCode() : 0);
            hash = hash * 31 + RecordTypeCode.GetHashCode();
            hash = hash * 31 + (RecordTypeText != null ? RecordTypeText.GetHashCode() : 0);
            return hash;
        }
    }
}
