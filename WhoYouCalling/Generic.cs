﻿namespace WhoYouCalling.Utilities
{
    public class Generic
    {
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

        public static List<string> ConvertHashSetToSortedList(HashSet<string> providedHashSet)
        {
            List<string> convertedToList = providedHashSet.ToList();
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
