using System;

namespace WhoYouCalling.Network.DNS
{
    public struct DNSResponse
    {
        public string DomainQueried { get; set; }
        public int RecordTypeCode { get; set; }
        public string RecordTypeText { get; set; }
        public int StatusCode { get; set; }
        public string StatusText { get; set; }
        public DNSResponseResult QueryResult { get; set; }

        public override bool Equals(object obj)
        {
            if (obj == null || this.GetType() != obj.GetType())
                return false;

            var other = (DNSResponse)obj;
            return DomainQueried == other.DomainQueried &&
                   RecordTypeCode == other.RecordTypeCode &&
                   RecordTypeText == other.RecordTypeText &&
                   StatusCode == other.StatusCode &&
                   StatusText == other.StatusText &&
                   Equals(QueryResult, other.QueryResult); 
        }

        public override int GetHashCode()
        {
            int hash = 17;
            hash = hash * 31 + (DomainQueried != null ? DomainQueried.GetHashCode() : 0);
            hash = hash * 31 + RecordTypeCode.GetHashCode();
            hash = hash * 31 + (RecordTypeText != null ? RecordTypeText.GetHashCode() : 0);
            hash = hash * 31 + StatusCode.GetHashCode();
            hash = hash * 31 + (StatusText != null ? StatusText.GetHashCode() : 0);
            hash = hash * 31 + (QueryResult != null ? QueryResult.GetHashCode() : 0);  

            return hash;
        }
    }
}
