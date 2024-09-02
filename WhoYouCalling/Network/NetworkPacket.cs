
namespace WhoYouCalling.Network
{
    public class NetworkPacket
    {
        public string IPversion { get; set; } = "IPv4";
        public string TransportProtocol { get; set; } = "TCP";
        public string SourceIP { get; set; } = "255.255.255.255";
        public int SourcePort { get; set; } = 0;
        public string DestinationIP { get; set; } = "255.255.255.255";
        public int DestinationPort { get; set; } = 0;
    }
}
