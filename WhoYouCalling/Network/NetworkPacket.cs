﻿
using WhoYouCalling.Network.DNS;

namespace WhoYouCalling.Network
{
    public struct NetworkPacket
    {
        public string IPversion { get; set; }
        public string TransportProtocol { get; set; }
        public string SourceIP { get; set; }
        public int SourcePort { get; set; }
        public string DestinationIP { get; set; }
        public int DestinationPort { get; set; }

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
