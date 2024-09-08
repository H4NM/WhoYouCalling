﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
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
                IPs = new List<string>()
            };

            if (!queryResults.Contains(";") || string.IsNullOrWhiteSpace(queryResults))
            {
                ConsoleOutput.Print($"DEBUGGING-NETWORK_UTILS_REMOVE_ME_LATER - Parsing DNS result \"{queryResults}\". It did not contain a \";\" OR NULL OR EMPTY...", PrintType.Info);
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
                    ConsoleOutput.Print($"DEBUGGING-NETWORK_UTILS_REGEX_MATCH_TYPE_REMOVE_ME_LATER - \"{result}\"", PrintType.Debug);

                    MatchCollection coll = Regex.Matches(result, "type\\:\\s(\\d+)\\s(.*)");
                    int recordTypeCode = int.Parse(coll[0].Groups[1].Value);
                    string domainQueried = coll[0].Groups[2].Value;

                    responseResult.BundledRecordTypeCode = recordTypeCode;
                    responseResult.BundledRecordTypeText = DnsTypeLookup.GetName(recordTypeCode);
                    responseResult.BundledDomainQueried = domainQueried;
                }
                else
                {
                    if (IsIPv4MappedToIPv6Address(result))
                    {
                        ConsoleOutput.Print($"DEBUGGING-NETWORK_UTILS_IPv4ADDRINIPv6_REMOVE_ME_LATER - \"{result}\"", PrintType.Debug);
                        responseResult.IPv4MappedIPv6Adresses = true;
                        IPAddress address = IPAddress.Parse(result);
                        responseResult.IPs.Add(address.MapToIPv4().ToString());
                    }
                    else
                    {
                        ConsoleOutput.Print($"DEBUGGING-NETWORK_UTILS_ADDING_ORD_ADDR_REMOVE_ME_LATER - \"{result}\"", PrintType.Debug);
                        responseResult.IPs.Add(result);
                    }
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
