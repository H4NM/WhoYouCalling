
namespace WhoYouCalling.Network
{
    internal class NetworkFilter
    {

        public static string GetCombinedNetworkFilter(HashSet<ConnectionRecord> connectionRecords, FilterType filter, bool strictComsEnabled = false, bool filterPorts = true, bool onlyDestIP = false)
        {
            HashSet<string> collectedFilterParts = new();
            foreach (ConnectionRecord connectionRecord in connectionRecords) //For each recorded unique network activity
            {
                string partialFilter = "";
                switch (filter)
                {
                    case FilterType.BPF:
                        {
                            partialFilter = GetBPFFilter(strictComsEnabled: strictComsEnabled,
                                                         connectionRecord: connectionRecord, 
                                                         filterPorts: filterPorts,
                                                         onlyDestIP: onlyDestIP);
                            break;
                        }
                    case FilterType.DFL:
                        {
                            partialFilter = GetDFLFilter(strictComsEnabled: strictComsEnabled, 
                                                         connectionRecord: connectionRecord, 
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

        public static string JoinFilterList(FilterType filter, HashSet<string> listOfFilters)
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

        private static string GetBPFFilter(bool strictComsEnabled, ConnectionRecord connectionRecord, bool filterPorts = true, bool onlyDestIP = false)
        {
            string partialFilter;
            string filterIPVersion;
            string filterTransportProto;


            if (connectionRecord.IPversion == Network.IPVersion.IPv4) // If it's ipv4 version
            {
                filterIPVersion = "ip";
            }
            else // else it's IPv6
            {
                filterIPVersion = "ip6"; // For BPF its ip6, for wireshark DFL its ipv6
            }
            if (connectionRecord.TransportProtocol == Network.TransportProtocol.TCP)
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
                    partialFilter = $"({filterIPVersion} and {filterTransportProto} and dst host {connectionRecord.DestinationIP})";
                }
                else
                {
                    partialFilter = $"({filterIPVersion} and {filterTransportProto} and host {connectionRecord.DestinationIP})";
                }
            }
            else 
            { 
                if (filterPorts)
                {
                    if (strictComsEnabled)
                    {
                        partialFilter = $"({filterIPVersion} and {filterTransportProto} and src host {connectionRecord.SourceIP} and src port {connectionRecord.SourcePort} and dst host {connectionRecord.DestinationIP} and dst port {connectionRecord.DestinationPort})";
                    }
                    else
                    {
                        partialFilter = $"({filterIPVersion} and {filterTransportProto} and ((host {connectionRecord.SourceIP} and host {connectionRecord.DestinationIP}) and ((dst port {connectionRecord.DestinationPort} and src port {connectionRecord.SourcePort}) or (dst port {connectionRecord.SourcePort} and src port {connectionRecord.DestinationPort}))))";
                    }
                }
                else
                {
                    if (strictComsEnabled)
                    {
                        partialFilter = $"({filterIPVersion} and {filterTransportProto} and src host {connectionRecord.SourceIP} and dst host {connectionRecord.DestinationIP})";
                    }
                    else
                    {
                        partialFilter = $"({filterIPVersion} and {filterTransportProto} and ((host {connectionRecord.SourceIP} and host {connectionRecord.DestinationIP})))";
                    }
                }
            }
            return partialFilter;
        }

        private static string GetDFLFilter(bool strictComsEnabled, ConnectionRecord connectionRecord, bool filterPorts = true, bool onlyDestIP = false)
        {
            string partialFilter;
            string filterIPVersion;
            string filterTransportProto;

            if (connectionRecord.IPversion == Network.IPVersion.IPv4) // If it's ipv4 version
            {
                filterIPVersion = "ip";
            }
            else // else it's IPv6
            {
                filterIPVersion = "ipv6"; // For BPF its ip6, for wireshark DFL its ipv6
            }

            if (connectionRecord.TransportProtocol == Network.TransportProtocol.TCP)
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
                    partialFilter = $"({filterIPVersion}.dst == {connectionRecord.DestinationIP})";
                }
                else
                {
                    partialFilter = $"({filterIPVersion}.addr == {connectionRecord.DestinationIP})";
                }
            }
            else
            {
                if (filterPorts)
                {
                    if (strictComsEnabled)
                    {
                        partialFilter = $"({filterIPVersion}.src == {connectionRecord.SourceIP} && {filterTransportProto}.srcport == {connectionRecord.SourcePort} && {filterIPVersion}.dst == {connectionRecord.DestinationIP} && {filterTransportProto}.dstport == {connectionRecord.DestinationPort})";
                    }
                    else
                    {
                        partialFilter = $"(({filterIPVersion}.addr == {connectionRecord.SourceIP} && {filterIPVersion}.addr == {connectionRecord.DestinationIP}) && (({filterTransportProto}.srcport == {connectionRecord.DestinationPort} && {filterTransportProto}.dstport == {connectionRecord.SourcePort}) || ({filterTransportProto}.srcport == {connectionRecord.SourcePort} && {filterTransportProto}.dstport == {connectionRecord.DestinationPort})))";
                    }
                }
                else
                {
                    if (strictComsEnabled)
                    {
                        partialFilter = $"({filterIPVersion}.src == {connectionRecord.SourceIP} && {filterIPVersion}.dst == {connectionRecord.DestinationIP})";
                    }
                    else
                    {
                        partialFilter = $"({filterIPVersion}.addr == {connectionRecord.SourceIP} && {filterIPVersion}.addr == {connectionRecord.DestinationIP})";
                    }
                }
            }

            return partialFilter;
        }
    }
}
