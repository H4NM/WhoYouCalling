using WhoYouCalling.Network;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.Network
{
    internal class NetworkFilter
    {

        public static string GetCombinedNetworkFilter(HashSet<NetworkPacket> networkPackets, FilterType filter, bool strictComsEnabled = false, bool filterPorts = true, bool onlyDestIP = false)
        {
            List<string> collectedFilterParts = new List<string>();
            ConsoleOutput.Print($"In GetCombined sc {strictComsEnabled},fp {filterPorts}, od {onlyDestIP}", PrintType.Fatal);
            foreach (NetworkPacket packet in networkPackets) //For each recorded unique network activity
            {
                string partialFilter = "";

                switch (filter)
                {
                    case FilterType.BPF:
                        {
                            partialFilter = GetBPFFilter(strictComsEnabled: strictComsEnabled, 
                                                         packet: packet, 
                                                         filterPorts: filterPorts,
                                                         onlyDestIP: onlyDestIP);
                            break;
                        }
                    case FilterType.DFL:
                        {
                            partialFilter = GetDFLFilter(strictComsEnabled: strictComsEnabled, 
                                                         packet: packet, 
                                                         filterPorts: filterPorts,
                                                         onlyDestIP: onlyDestIP);
                            break;
                        }
                }
                collectedFilterParts.Add(partialFilter);
            }

            string fullCombinedFilter = JoinFilterList(filter, collectedFilterParts);

            return fullCombinedFilter;
        }

        public static string JoinFilterList(FilterType filter, List<string> listOfFilters)
        {
            string joinedString = "";
            switch (filter) 
            {
                case FilterType.BPF:
                    {
                        joinedString = string.Join(" or ", listOfFilters);
                        break;
                    }
                case FilterType.DFL:
                    {
                        joinedString = string.Join(" || ", listOfFilters);
                        break;
                    }
            }
            return joinedString;
        }

        private static string GetBPFFilter(bool strictComsEnabled, NetworkPacket packet, bool filterPorts = true, bool onlyDestIP = false)
        {
            string partialFilter;
            string filterIPVersion;
            string filterTransportProto;


            if (packet.IPversion == Network.IPVersion.IPv4) // If it's ipv4 version
            {
                filterIPVersion = "ip";
            }
            else // else it's IPv6
            {
                filterIPVersion = "ip6"; // For BPF its ip6, for wireshark DFL its ipv6
            }
            if (packet.TransportProtocol == Network.TransportProtocol.TCP)
            {
                filterTransportProto = "tcp";
            }
            else // else it's UDP
            {
                filterTransportProto = "udp";
            }

            if (onlyDestIP)
            {
                if (strictComsEnabled)
                {
                    partialFilter = $"({filterIPVersion} and {filterTransportProto} and dst host {packet.DestinationIP})";
                }
                else
                {
                    partialFilter = $"({filterIPVersion} and {filterTransportProto} and host {packet.DestinationIP})";
                }
            }
            else 
            { 
                if (filterPorts)
                {
                    if (strictComsEnabled)
                    {
                        partialFilter = $"({filterIPVersion} and {filterTransportProto} and src host {packet.SourceIP} and src port {packet.SourcePort} and dst host {packet.DestinationIP} and dst port {packet.DestinationPort})";
                    }
                    else
                    {
                        partialFilter = $"({filterIPVersion} and {filterTransportProto} and ((host {packet.SourceIP} and host {packet.DestinationIP}) and ((dst port {packet.DestinationPort} and src port {packet.SourcePort}) or (dst port {packet.SourcePort} and src port {packet.DestinationPort}))))";
                    }
                }
                else
                {
                    if (strictComsEnabled)
                    {
                        partialFilter = $"({filterIPVersion} and {filterTransportProto} and src host {packet.SourceIP} and dst host {packet.DestinationIP})";
                    }
                    else
                    {
                        partialFilter = $"({filterIPVersion} and {filterTransportProto} and ((host {packet.SourceIP} and host {packet.DestinationIP})))";
                    }
                }
            }
            return partialFilter;
        }

        private static string GetDFLFilter(bool strictComsEnabled, NetworkPacket packet, bool filterPorts = true, bool onlyDestIP = false)
        {
            string partialFilter;
            string filterIPVersion;
            string filterTransportProto;

            if (packet.IPversion == Network.IPVersion.IPv4) // If it's ipv4 version
            {
                filterIPVersion = "ip";
            }
            else // else it's IPv6
            {
                filterIPVersion = "ipv6"; // For BPF its ip6, for wireshark DFL its ipv6
            }

            if (packet.TransportProtocol == Network.TransportProtocol.TCP)
            {
                filterTransportProto = "tcp";
            }
            else // else it's UDP
            {
                filterTransportProto = "udp";
            }


            if (onlyDestIP)
            {
                if (strictComsEnabled)
                {
                    partialFilter = $"({filterIPVersion}.dst == {packet.DestinationIP})";
                }
                else
                {
                    partialFilter = $"({filterIPVersion}.addr == {packet.DestinationIP})";
                }
            }
            else
            {
                if (filterPorts)
                {
                    if (strictComsEnabled)
                    {
                        partialFilter = $"({filterIPVersion}.src == {packet.SourceIP} && {filterTransportProto}.srcport == {packet.SourcePort} && {filterIPVersion}.dst == {packet.DestinationIP} && {filterTransportProto}.dstport == {packet.DestinationPort})";
                    }
                    else
                    {
                        partialFilter = $"(({filterIPVersion}.addr == {packet.SourceIP} && {filterIPVersion}.addr == {packet.DestinationIP}) && (({filterTransportProto}.srcport == {packet.DestinationPort} && {filterTransportProto}.dstport == {packet.SourcePort}) || ({filterTransportProto}.srcport == {packet.SourcePort} && {filterTransportProto}.dstport == {packet.DestinationPort})))";
                    }
                }
                else
                {
                    if (strictComsEnabled)
                    {
                        partialFilter = $"({filterIPVersion}.src == {packet.SourceIP} && {filterIPVersion}.dst == {packet.DestinationIP})";
                    }
                    else
                    {
                        partialFilter = $"({filterIPVersion}.addr == {packet.SourceIP} && {filterIPVersion}.addr == {packet.DestinationIP})";
                    }
                }
            }

            return partialFilter;
        }
    }
}
