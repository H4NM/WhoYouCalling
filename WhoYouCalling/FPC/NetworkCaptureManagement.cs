using SharpPcap.LibPcap;
using System.Net;
using System.Text.RegularExpressions;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.FPC
{
    public class NetworkUtils
    {
        public static IPAddress CleanIPv4AndIPv6Address(string ip)
        {
            if (string.IsNullOrWhiteSpace(ip))
            {
                ConsoleOutput.Print($"Attempted to clean ip \"{ip}\". It was Null or Whitespace", "debug");
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
                ConsoleOutput.Print($"Attempted to clean ip \"{ip}\". Failed to parse it", "debug");
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
                ConsoleOutput.Print("No network interfaces were found on this machine.", "error");
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
