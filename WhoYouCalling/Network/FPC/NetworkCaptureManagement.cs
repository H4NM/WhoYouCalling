using SharpPcap.LibPcap;
using System.Net;
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

        public static bool IsValidFilter(int deviceNumber, string filter)
        {
            try
            {
                var bpfProgram = BpfProgram.TryCreate(LibPcapLiveDeviceList.Instance[deviceNumber].Handle, filter, 0, 0);
                return true;
            }
            catch 
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

            ConsoleOutput.Print("Available interfaces:", PrintType.Info);
            int i = 0;
            string deviceMsg;
            foreach (var dev in devices)
            {
                deviceMsg = $"{i}) {dev.Description}";
                ConsoleOutput.Print(deviceMsg, PrintType.NetworkInterface);
                i++;
                foreach (PcapAddress addr in dev.Addresses)
                {
                    if (addr.Addr != null && addr.Addr.ipAddress != null)
                    {
                        IPAddress ip = addr.Addr.ipAddress;
                        if (!IsSelfAssignedIPv4(ip) && !IsLinkLocalIPv6(ip))
                        {
                            IPVersion ipVersion;
                            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                            {
                                ipVersion = IPVersion.IPv6;
                            }
                            else
                            {
                                ipVersion = IPVersion.IPv4;
                            }
                            ConsoleOutput.Print($"\t{ipVersion}: {ip}", PrintType.NetworkInterface);
                        }
                    }
                }
            }
        }

        static bool IsSelfAssignedIPv4(IPAddress ipAddress)
        {
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) 
            {
                byte[] bytes = ipAddress.GetAddressBytes();
                return bytes[0] == 169 && bytes[1] == 254;
            }
            return false;
        }

        static bool IsLinkLocalIPv6(IPAddress ipAddress)
        {
            if (ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) 
            {
                byte[] bytes = ipAddress.GetAddressBytes();
                return bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80;
            }
            return false;
        }
    }
}
