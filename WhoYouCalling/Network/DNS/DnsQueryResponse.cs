using System.Net;

namespace WhoYouCalling.Network.DNS
{
    public class DnsQueryResponse 
    {
        public int RecordTypeCode { get; set; } = 999999;
        public string RecordTypeText { get; set; } = "";
        public int StatusCode { get; set; } = 999999;
        public string StatusText { get; set; } = "";
        public string IP { get; set; } = "255.255.255.255";// Unable to maintain as IPAddress data type due to json serialization
        public bool IsIPv4MappedToIPv6 { get; set; } = false;
        public string IPv4AddressFromIPv6 { get; set; } = "";
    }
}
