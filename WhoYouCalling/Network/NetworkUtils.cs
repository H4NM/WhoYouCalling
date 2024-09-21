using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.WhoYouCalling.Network
{
    internal class NetworkUtils
    {
        public static bool IsIPv4MappedToIPv6Address(string ip)
        {
            IPAddress address = IPAddress.Parse(ip);
            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && address.IsIPv4MappedToIPv6)
            {
                return true;
            }
            else
            {
                return false;
            }
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
                    responseResult.BundledRecordTypeText = DnsTypeLookup.GetName(recordTypeCode);
                    responseResult.BundledDomain = domain;
                }
                else
                {
                    if (IsIPv4MappedToIPv6Address(result))
                    {
                        responseResult.IPv4MappedIPv6Adresses = true;
                        IPAddress address = IPAddress.Parse(result);
                        responseResult.IPs.Add(address.MapToIPv4().ToString());
                    }
                    else
                    {
                        responseResult.IPs.Add(result);
                    }
                }
            }
            return responseResult;
        }
        public static List<string> ConvertDestinationEndpoints(HashSet<DestinationEndpoint> providedHashSet)
        {
            List<string> convertedToList = new List<string>();
            foreach (DestinationEndpoint dstEndpoint in providedHashSet)
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

            if (IPAddress.TryParse(cleanedIpAddress, out IPAddress cleanedIPAddressObject)) // Parsing IP address
            {
                return cleanedIPAddressObject;
            }
            else
            {
                ConsoleOutput.Print($"Attempted to clean ip \"{ip}\". Failed to parse it", PrintType.Debug);
                return IPAddress.None;
            }
        }
    }
}
