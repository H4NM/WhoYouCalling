
using System.Net;
using System.Text.RegularExpressions;
using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;
using WhoYouCalling.Utilities;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace WhoYouCalling.Network
{
    internal class NetworkUtils
    {

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

        public static HashSet<ConnectionRecord> GetNetworkAdressesFromDNSResponse(HashSet<DNSResponse>? dnsResponses)
        {
            HashSet<ConnectionRecord> domainIPAdresses = new();
            foreach (DNSResponse response in dnsResponses)
            {
                foreach (string ipAdress in response.QueryResult.IPs)
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
        public static List<string> ConvertDestinationEndpoints(HashSet<NetworkEndpoint> providedHashSet)
        {
            List<string> convertedToList = new List<string>();
            foreach (NetworkEndpoint dstEndpoint in providedHashSet)
            {
                convertedToList.Add($"{dstEndpoint.IP}:{dstEndpoint.Port}");
            }
            convertedToList.Sort();
            return convertedToList;
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
