using System.Reflection;
using WhoYouCalling.Process;

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

        public static string GetRunInstanceFolderName(string runInstanceName)
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
   
        public static void PrintObjectProperties(object obj)
        {
            Type type = obj.GetType();

            PropertyInfo[] properties = type.GetProperties();
            foreach (var property in properties)
            {
                var value = property.GetValue(obj, null);

                if (value is List<string> stringList)
                {
                    Console.WriteLine($"{property.Name}: {string.Join(',', stringList)}");
                }
                else
                {
                    Console.WriteLine($"{property.Name}: {value}");
                }
            }

            FieldInfo[] fields = type.GetFields();
            foreach (var field in fields)
            {
                var value = field.GetValue(obj);
                if (value is List<string> stringList)
                {
                    Console.WriteLine($"{field.Name}: {string.Join(',', stringList)}");
                }
                else
                {
                    Console.WriteLine($"{field.Name}: {value}");
                }
                
            }
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
