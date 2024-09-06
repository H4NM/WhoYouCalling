using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using WhoYouCalling.Network;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.WhoYouCalling.Network
{
    internal class NetworkFilter
    {
        public static Dictionary<int, string> GetNetworkFilter(Dictionary<int, HashSet<NetworkPacket>> networkPackets, bool strictComsEnabled, NetworkFilterType filter)
        {
            Dictionary<int, string> filterPerExecutable = new Dictionary<int, string>();

            foreach (KeyValuePair<int, HashSet<NetworkPacket>> entry in networkPackets) //For each Process 
            {
                if (entry.Value.Count == 0) // Check if the executable has any recorded network activity
                {
                    ConsoleOutput.Print($"Not calculating {filter} filter for PID {entry.Key}. No recored network activity", "debug");
                    continue;
                }
                List<string> fullFilterListForProcess = new List<string>();
                foreach (NetworkPacket packet in entry.Value) //For each recorded unique network activity
                {

                    string partialFilter = "";

                    switch (filter)
                    {
                        case NetworkFilterType.BPF: 
                            {
                                partialFilter = GetBPFFilter(strictComsEnabled: strictComsEnabled, packet: packet);
                                break;
                            }
                        case NetworkFilterType.DFL:
                            {
                                partialFilter = GetDFLFilter(strictComsEnabled: strictComsEnabled, packet: packet);
                                break;
                            }
                    }
     
                    fullFilterListForProcess.Add(partialFilter);
                }

                string executableFilter = JoinFilterList(filter, fullFilterListForProcess);
                filterPerExecutable[entry.Key] = executableFilter; // Add filter for executable
            }

            if (filterPerExecutable.Count > 1)
            {
                List<string> tempFilterList = new List<string>();
                foreach (KeyValuePair<int, string> processFilter in filterPerExecutable)
                {
                    tempFilterList.Add($"({processFilter.Value})");
                }
                filterPerExecutable[0] = JoinFilterList(filter, tempFilterList); //0 is the combined PID number for all
            }
            return filterPerExecutable;
        }

        private static string JoinFilterList(NetworkFilterType filter, List<string> listOfFilters)
        {
            string joinedString = "";
            switch (filter) 
            {
                case NetworkFilterType.BPF:
                    {
                        joinedString = string.Join(" or ", listOfFilters);
                        break;
                    }
                case NetworkFilterType.DFL:
                    {
                        joinedString = string.Join(" || ", listOfFilters);
                        break;
                    }
            }
            return joinedString;
        }

        private static string GetBPFFilter(bool strictComsEnabled, NetworkPacket packet)
        {
            string partialFilter;
            string filterIPVersion;
            string filterTransportProto = packet.TransportProtocol.ToLower();

            if (packet.IPversion == "IPv4") // If it's ipv4 version
            {
                filterIPVersion = "ip";
            }
            else // else it's IPv6
            {
                filterIPVersion = "ip6"; // For BPF its ip6, for wireshark DFL its ipv6
            }

            if (strictComsEnabled)
            {
                partialFilter = $"({filterIPVersion} and {filterTransportProto} and src host {packet.SourceIP} and src port {packet.SourcePort} and dst host {packet.DestinationIP} and dst port {packet.DestinationPort})";
            }
            else
            {
                partialFilter = $"({filterIPVersion} and {filterTransportProto} and ((host {packet.SourceIP} and host {packet.DestinationIP}) and ((dst port {packet.DestinationPort} and src port {packet.SourcePort}) or (dst port {packet.SourcePort} and src port {packet.DestinationPort}))))";
            }

            return partialFilter;
        }


        private static string GetDFLFilter(bool strictComsEnabled, NetworkPacket packet)
        {
            string partialFilter;
            string filterIPVersion;
            string filterTransportProto = packet.TransportProtocol.ToLower();

            if (packet.IPversion == "IPv4") // If it's ipv4 version
            {
                filterIPVersion = "ip";
            }
            else // else it's IPv6
            {
                filterIPVersion = "ipv6"; // For BPF its ip6, for wireshark DFL its ipv6
            }

            if (strictComsEnabled)
            {
                partialFilter = $"({filterIPVersion}.src == {packet.SourceIP} && {filterTransportProto}.srcport == {packet.SourcePort} && {filterIPVersion}.dst == {packet.DestinationIP} && {filterTransportProto}.dstport == {packet.DestinationPort})";
                //partialFilter = $"({filterIPVersion} and {filterTransportProto} and src host {packet.SourceIP} and src port {packet.SourcePort} and dst host {packet.DestinationIP} and dst port {packet.DestinationPort})";
            }
            else
            {
                //partialFilter = "((ip.src == 123.123.123.123 && ip.dst == 123.123.123.124) || ()  && tcp.srcport == 443 && ip.dst == 123.123.123.124 && tcp.dstport == 593434)";
                //partialFilter = $"({filterIPVersion} and {filterTransportProto} and ((host {packet.SourceIP} and host {packet.DestinationIP}) and ((dst port {packet.DestinationPort} and src port {packet.SourcePort}) or (dst port {packet.SourcePort} and src port {packet.DestinationPort}))))";
                partialFilter = $"(({filterIPVersion}.addr == {packet.SourceIP} && {filterIPVersion}.addr == {packet.DestinationIP}) && (({filterTransportProto}.srcport == {packet.DestinationPort} && {filterTransportProto}.dstport == {packet.SourcePort}) || ({filterTransportProto}.srcport == {packet.SourcePort} && {filterTransportProto}.dstport == {packet.DestinationPort})))";
            }

            return partialFilter;
        }
    }
}
