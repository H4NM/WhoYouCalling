
namespace WhoYouCalling.Utilities
{
    internal static class FileAndFolders
    {
        public static string GetProcessFolderNameIncremented(string directoryPath, string processFolderName)
        {
            var directories = Directory.GetDirectories(directoryPath, processFolderName + "*");
            return $"{processFolderName} - {directories.Length}";
        }
        public static bool FolderExists(string directoryPath)
        {
            if (Directory.Exists(directoryPath))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public static void CreateFolder(string folder)
        {
            Directory.CreateDirectory(folder);
        }
        public static void CreateTextFileListOfStrings(string filePath, List<string> listWithStrings)
        {
            File.WriteAllLines(filePath, listWithStrings);
        }
        public static void CreateTextFileString(string filePath, string text)
        {
            File.WriteAllText(filePath, text);
        }
        public static void DeleteFile(string file)
        {
            if (File.Exists(file))
            {
                File.Delete(file);
                ConsoleOutput.Print($"Deleted file {file}", PrintType.Debug);
            }
            else
            {
                ConsoleOutput.Print($"Unable to delete file {file}. It doesnt exist", PrintType.Warning);
            }
        }
    }
}
