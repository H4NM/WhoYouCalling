
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

        public override bool Equals(object obj)
        {
            if (obj == null || this.GetType() != obj.GetType())
                return false;

            var other = (ConnectionRecord)obj;
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
            hash = hash * 31 + IPversion.GetHashCode();
            hash = hash * 31 + TransportProtocol.GetHashCode();
            hash = hash * 31 + (SourceIP != null ? SourceIP.GetHashCode() : 0);
            hash = hash * 31 + SourcePort.GetHashCode();
            hash = hash * 31 + (DestinationIP != null ? DestinationIP.GetHashCode() : 0);
            hash = hash * 31 + DestinationPort.GetHashCode();
            return hash;
        }
    }
}
