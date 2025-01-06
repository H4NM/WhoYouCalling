
using System.Net;
using System.Text.RegularExpressions;
using WhoYouCalling.Network.DNS;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.Network
{
    internal class NetworkUtils
    {
        public static bool IsLocalhostIP(string ip)
        {
            if (ip == "127.0.0.1" || ip == "::1")
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        public static Dictionary<ConnectionRecordType, List<string>> GetPresentableConnectionRecordsFormat(Dictionary<ConnectionRecordType, HashSet<string>> networkDetails)
        {
            Dictionary<ConnectionRecordType, List<string>> sortedNetworkDetailsAsList = new();
            foreach (KeyValuePair<ConnectionRecordType, HashSet<string>> entry in networkDetails)
            {
                List<string> sortedList = Generic.ConvertAndSortHashSetToList(entry.Value);
                sortedNetworkDetailsAsList[entry.Key] = sortedList;
            }
            return sortedNetworkDetailsAsList;
        }

        public static bool DNSResponsesContainsAdresses(HashSet<DNSResponse> dnsResponses)
        {
            foreach (DNSResponse dnsResponse in dnsResponses)
            {
                HashSet<ConnectionRecord> domainIPAdresses = GetNetworkAdressesFromDNSResponse(dnsResponse);
                if (domainIPAdresses.Count() > 0)
                {
                    return true;
                }
            }
            return false;
        }
            
        public static Dictionary<ConnectionRecordType, HashSet<string>> FilterConnectionRecords(HashSet<ConnectionRecord> tcpIPTelemetry)
        {
            Dictionary<ConnectionRecordType, HashSet<string>> filteredConnectionRecords = new Dictionary<ConnectionRecordType, HashSet<string>> {
                                                    {ConnectionRecordType.IPv4TCP, new HashSet<string>()},
                                                    {ConnectionRecordType.IPv6TCP, new HashSet<string>()},
                                                    {ConnectionRecordType.IPv4UDP, new HashSet<string>()},
                                                    {ConnectionRecordType.IPv6UDP, new HashSet<string>()},
                                                    {ConnectionRecordType.IPv4Localhost, new HashSet<string>()},
                                                    {ConnectionRecordType.IPv6Localhost, new HashSet<string>()}};

            foreach (ConnectionRecord connectionRecord in tcpIPTelemetry)
            {
                string endpoint = $"{connectionRecord.DestinationIP}:{connectionRecord.DestinationPort}";
                if (connectionRecord.IPversion == Network.IPVersion.IPv4)
                {
                    if (connectionRecord.DestinationIP == "127.0.0.1")
                    {
                        filteredConnectionRecords[ConnectionRecordType.IPv4Localhost].Add(endpoint);
                    }
                    else if (connectionRecord.TransportProtocol == Network.TransportProtocol.TCP)
                    {
                        filteredConnectionRecords[ConnectionRecordType.IPv4TCP].Add(endpoint);
                    }
                    else if (connectionRecord.TransportProtocol == Network.TransportProtocol.UDP)
                    {
                        filteredConnectionRecords[ConnectionRecordType.IPv4UDP].Add(endpoint);
                    }
                }
                else if (connectionRecord.IPversion == Network.IPVersion.IPv6)
                {
                    if (connectionRecord.DestinationIP == "::1")
                    {
                        filteredConnectionRecords[ConnectionRecordType.IPv6Localhost].Add(endpoint);
                    }
                    else if (connectionRecord.TransportProtocol == Network.TransportProtocol.TCP)
                    {
                        filteredConnectionRecords[ConnectionRecordType.IPv6TCP].Add(endpoint);
                    }
                    else if (connectionRecord.TransportProtocol == Network.TransportProtocol.UDP)
                    {
                        filteredConnectionRecords[ConnectionRecordType.IPv6UDP].Add(endpoint);
                    }
                }
            }
            return filteredConnectionRecords;
        }

        public static string GetActualIP(string ipAdress)
        {
            string actualIPAdress = "";
            IPAddress address = IPAddress.Parse(ipAdress);
            if (address.IsIPv4MappedToIPv6)
            {
                actualIPAdress = address.MapToIPv4().ToString();
            }
            else
            {
                actualIPAdress = ipAdress;
            }
            return actualIPAdress;
        }

        public static HashSet<ConnectionRecord> GetNetworkAdressesFromDNSResponse(DNSResponse dnsResponses)
        {
            HashSet<ConnectionRecord> domainIPAdresses = new();

            foreach (string ipAdress in dnsResponses.QueryResult.IPs)
            {
                IPAddress address = IPAddress.Parse(ipAdress);
                IPVersion ipVersion;
                string actualIPAdress = "";
                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                {
                    if (address.IsIPv4MappedToIPv6)
                    {
                        actualIPAdress = address.MapToIPv4().ToString();
                        ipVersion = IPVersion.IPv4;
                    }
                    else
                    {
                        actualIPAdress = ipAdress;
                        ipVersion = IPVersion.IPv6;
                    }
                }
                else
                {
                    ipVersion = IPVersion.IPv4;
                    actualIPAdress = ipAdress;
                }

                ConnectionRecord connectionRecord = new ConnectionRecord
                {
                    IPversion = ipVersion,
                    DestinationIP = actualIPAdress
                };

                domainIPAdresses.Add(connectionRecord);
            }
            return domainIPAdresses;
        }

        public static DNSResponseResult ParseDNSResult(string queryResults)
        {
            DNSResponseResult responseResult = new DNSResponseResult {
                IPs = new List<string> ()
            };

            if (!queryResults.Contains(";") || string.IsNullOrWhiteSpace(queryResults))
            {
                return responseResult;
            }

            string[] resultParts = queryResults.Split(";");
            foreach (string result in resultParts)
            {
                if (string.IsNullOrWhiteSpace(result))
                {
                    continue;
                }
                else if (result.Contains("type: "))
                {
                    MatchCollection matches = Regex.Matches(result, "type\\:\\s(\\d+)\\s(.*)");
                    int recordTypeCode = int.Parse(matches[0].Groups[1].Value);
                    string retrievedTextPart = matches[0].Groups[2].Value;
                    string domain = string.IsNullOrEmpty(retrievedTextPart) ? "N/A" : retrievedTextPart;

                    responseResult.BundledRecordTypeCode = recordTypeCode;
                    responseResult.BundledRecordTypeText = DnsCodeLookup.GetDnsTypeName(recordTypeCode);
                    responseResult.BundledDomain = domain;
                }
                else
                {
                    responseResult.IPs.Add(result);
                }
            }
            return responseResult;
        }
   

        private static IPAddress CleanIPAdress(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
            {
                ConsoleOutput.Print($"Attempted to clean ip \"{ip}\". It was Null or Whitespace", PrintType.Debug);
                return IPAddress.None;
            }

            string pattern = @"[^0-9a-fA-F\.:]";
            string cleanedIpAddress = Regex.Replace(ip, pattern, "").Trim();

            if (IPAddress.TryParse(cleanedIpAddress, out IPAddress? cleanedIPAddressObject)) // Parsing IP address
            {
                return cleanedIPAddressObject!;
            }
            else
            {
                ConsoleOutput.Print($"Attempted to clean ip \"{ip}\". Failed to parse it", PrintType.Debug);
                return IPAddress.None;
            }
        }
    }
}
