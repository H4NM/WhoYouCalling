namespace WhoYouCalling.Utilities
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
    }
}
