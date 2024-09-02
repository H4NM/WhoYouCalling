using System.IO;

namespace WhoYouCalling.Utilities
{
    public static class FileAndFolders
    {
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
                ConsoleOutput.Print($"Deleted file {file}", "debug");
            }
            else
            {
                ConsoleOutput.Print($"Unable to delete file {file}. It doesnt exist", "warning");
            }
        }
    }
}
