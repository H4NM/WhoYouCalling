using SharpPcap.LibPcap;
using WhoYouCalling.Utilities;


namespace WhoYouCalling.FPC
{
    public class NetworkUtils
    {
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
