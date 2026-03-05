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
                return IPAddress.None;
            }

            string pattern = @"[^0-9a-fA-F\.:]";
            string cleanedIpAddress = Regex.Replace(ip, pattern, "").Trim();

            if (IPAddress.TryParse(cleanedIpAddress, out IPAddress? cleanedIPAddressObject)) // Parsing IP address
            {
                return cleanedIPAddressObject;
            }
            else
            {
                return IPAddress.None;
            }
        }

        public static LibPcapLiveDeviceList GetNetworkInterfaces()
        {
            return LibPcapLiveDeviceList.Instance; // Retrieve the device list
        }

        public static int? MatchIPToNetworkInterface(LibPcapLiveDeviceList networkDevices, string providedIPPart)
        {
            int deviceId = 0;
            foreach (var dev in networkDevices)
            {
                foreach (PcapAddress addr in dev.Addresses)
                {
                    if (addr.Addr != null && addr.Addr.ipAddress != null)
                    {
                        IPAddress ip = addr.Addr.ipAddress;
                        if (!IsSelfAssignedIPv4(ip) && !IsLinkLocalIPv6(ip))
                        {
                            if (ip.ToString().StartsWith(providedIPPart))
                            {
                                return deviceId;
                            }
                        }
                    }
                }
                deviceId++;
            }
            return null;
        }

        public static void PrintNetworkInterfaces(LibPcapLiveDeviceList networkDevices)
        {

            ConsoleOutput.Print("Available interfaces:", PrintType.Info);
            int deviceId = 0;
            string deviceMsg;
            foreach (var dev in networkDevices)
            {
                deviceMsg = $"{deviceId}) {dev.Description}";
                ConsoleOutput.Print(deviceMsg, PrintType.NetworkInterface);
                deviceId++;
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
