using SharpPcap.LibPcap;
using System.Net;
using System.Reflection;
using System.Text.RegularExpressions;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.Network.FPC
{
    internal class NetworkCaptureManagement
    {
        public static bool NpcapDriverExists()
        {
            string system32Path = Environment.SystemDirectory;
            string npcapPath = Path.Combine(system32Path, @"Drivers\npcap.sys");

            if (File.Exists(npcapPath))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

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
                        
        public static IPAddress CleanIPv4AndIPv6Address(string ip)
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

        public static LibPcapLiveDeviceList GetNetworkInterfaces()
        {
            return LibPcapLiveDeviceList.Instance; // Retrieve the device list
        }
        public static void PrintNetworkInterfaces()
        {
            var devices = GetNetworkInterfaces();
            if (devices.Count < 1)
            {
                ConsoleOutput.Print("No network interfaces were found on this machine.", PrintType.Error);
                Environment.Exit(1);
            }

            int i = 0;
            string deviceMsg;
            foreach (var dev in devices)
            {
                deviceMsg = $"{i}) {dev.Name} {dev.Description}";
                ConsoleOutput.Print(deviceMsg);
                i++;
            }
        }
    }
}
