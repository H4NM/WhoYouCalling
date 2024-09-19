using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace WhoYouCalling.Utilities
{
    public class Generic
    {
        public static string NormalizePath(string path)
        {
            return path.Replace(@"\\", @"\"); 
        }
        public static double ConvertToMilliseconds(double providedSeconds)
        {
            TimeSpan timeSpan = TimeSpan.FromSeconds(providedSeconds);
            double milliseconds = timeSpan.TotalMilliseconds;
            return milliseconds;
        }

        public static string GetRunInstanceFolderName(string executableName)
        {
            string timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            string folderName = $"{executableName}-{timestamp}";
            return folderName;
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

        public static string GetTimestampNow()
        {
            return DateTime.Now.ToString("HH:mm:ss");
        }

        public static string GetPresentableDuration(DateTime startTime, DateTime endTime)
        {
            var duration = endTime - startTime;
            string presentableDuration = "";
            if (duration.TotalSeconds <= 60)
            {
                presentableDuration = Math.Round(duration.TotalSeconds, 2).ToString() + "s";
            }
            else if (duration.TotalMinutes <= 60)
            {
                presentableDuration = Math.Round(duration.TotalMinutes, 2).ToString() + "m";
            }
            else
            {
                presentableDuration = Math.Round(duration.TotalHours, 2).ToString() + "h";
            }
            return presentableDuration;
        }
    }
}
