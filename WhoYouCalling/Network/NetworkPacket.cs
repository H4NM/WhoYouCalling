
using WhoYouCalling.Network.DNS;

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

        public override bool Equals(object obj)
        {
            if (obj == null || this.GetType() != obj.GetType())
                return false;

            var other = (NetworkPacket)obj;
            return IPversion == other.IPversion &&
                   TransportProtocol == other.TransportProtocol &&
                   SourceIP == other.SourceIP &&
                   SourcePort == other.SourcePort &&
                   DestinationIP == other.DestinationIP &&
                   DestinationPort == other.DestinationPort;
        }

        public override int GetHashCode()
        {
            int hash = 17;
            hash = hash * 31 + (IPversion != null ? IPversion.GetHashCode() : 0);
            hash = hash * 31 + (TransportProtocol != null ? TransportProtocol.GetHashCode() : 0);
            hash = hash * 31 + (SourceIP != null ? SourceIP.GetHashCode() : 0);
            hash = hash * 31 + SourcePort.GetHashCode();
            hash = hash * 31 + (DestinationIP != null ? DestinationIP.GetHashCode() : 0);
            hash = hash * 31 + DestinationPort.GetHashCode();
            return hash;
        }
    }
}
