using System.Net;

namespace WhoYouCalling.Network.DNS
{
    public class DNSQuery 
    {
        public string DomainQueried { get; set; } = "";
        public int RecordTypeCode { get; set; } = 999999;
        public string RecordTypeText { get; set; } = "";
    }
}
