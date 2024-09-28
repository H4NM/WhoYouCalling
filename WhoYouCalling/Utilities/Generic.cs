using System.Reflection;

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

        public static string GetTimestampNow()
        {
            return DateTime.Now.ToString("HH:mm:ss");
        }

        public static void PrintObjectProperties(object obj)
        {
            Type type = obj.GetType();

            // Get all properties of the object
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

            // Optionally, get all fields as well (for non-auto properties or public fields)
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
