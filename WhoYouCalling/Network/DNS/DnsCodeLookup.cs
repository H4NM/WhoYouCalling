
namespace WhoYouCalling.Network.DNS
{
    public static class DnsCodeLookup
    {
        public static string GetDnsStatusName(int statusCode)
        {
            if (Enum.IsDefined(typeof(DnsStatusType), statusCode))
            {
                return ((DnsStatusType)statusCode).ToString();
            }
            return DnsStatusType.NA.ToString(); 
        }
        public static string GetDnsTypeName(int statusCode)
        {
            if (Enum.IsDefined(typeof(DnsType), statusCode))
            {
                return ((DnsType)statusCode).ToString();
            }
            return DnsType.NA.ToString();
        }
    }
}
