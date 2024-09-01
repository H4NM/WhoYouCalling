namespace WhoYouCalling.DNS
{
    public class DnsQueryResponse 
    {
        public int RecordTypeCode { get; set; } = 999999;
        public string RecordTypeText { get; set; } = "";
        public int StatusCode { get; set; } = 999999;
        public string StatusText { get; set; } = "";
        public string IP { get; set; } // Unable to maintain as IPAddress data type due to json serialization
    }
}
