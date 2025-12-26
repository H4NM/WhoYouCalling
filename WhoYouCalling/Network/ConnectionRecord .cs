
namespace WhoYouCalling.Network
{
    public struct ConnectionRecord
    {
        public IPVersion IPversion { get; set; }
        public TransportProtocol TransportProtocol { get; set; }
        public string SourceIP { get; set; }
        public int SourcePort { get; set; }
        public string DestinationIP { get; set; }
        public int DestinationPort { get; set; }
        public DateTime TimeStamp { get; set; }
    }
}
