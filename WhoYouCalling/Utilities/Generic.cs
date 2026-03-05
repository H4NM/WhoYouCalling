using System.Reflection;
using System.Runtime.InteropServices;

namespace WhoYouCalling.Utilities
{
    public class Generic
    {
        public static List<string> ConvertAndSortHashSetToList(HashSet<string> unsortedStringHashSet)
        {
            List<string> sortedList = unsortedStringHashSet.ToList();
            sortedList.Sort();
            return sortedList;
        }

        public static string GetVersion()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var fileVersion = assembly.GetCustomAttribute<AssemblyFileVersionAttribute>()?.Version ?? "Unknown";
            return $"v{fileVersion}";
        }

        public static string GetMachineTimeZone()
        {
            return TimeZoneInfo.Local.DisplayName.ToString();
        }

        public static string GetHostname()
        {
            try
            {
                string fqdn = System.Net.Dns.GetHostEntry("").HostName;
                return !string.IsNullOrWhiteSpace(fqdn) ? fqdn : Environment.MachineName;
            }
            catch
            {
                return Environment.MachineName;
            }
        }

        public static string GetOS()
        {
            return RuntimeInformation.OSDescription;
        }

        public static string NormalizePath(string path)
        {
            if (path.StartsWith(@"\\")) // Is Remote share
            { 
                string remainder = path.Substring(2);    
                remainder = remainder.Replace(@"\\", @"\");
                path = @"\\" + remainder;          
            }    
            else
            {
                path = path.Replace(@"\\", @"\");
            }

            if (path.EndsWith(@"\"))
            {
                path = path.Remove(path.LastIndexOf(@"\"));
            }
            return path; 
        }
        public static double ConvertToMilliseconds(double providedSeconds)
        {
            TimeSpan timeSpan = TimeSpan.FromSeconds(providedSeconds);
            double milliseconds = timeSpan.TotalMilliseconds;
            return milliseconds;
        }

        public static string GetRunInstanceName(string runInstanceName)
        {
            string timestamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
            string folderName = $"{runInstanceName}-{timestamp}";
            return folderName;
        }

        public static bool DateTimeIsInRangeBySeconds(DateTime referenceTime, DateTime rangeTime, int maxSecondRange)
        {
            if ((referenceTime - rangeTime).TotalSeconds <= maxSecondRange || (rangeTime - referenceTime).TotalSeconds <= maxSecondRange)
            {
                return true;
            }
            else
            {
                return false;
            }
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
