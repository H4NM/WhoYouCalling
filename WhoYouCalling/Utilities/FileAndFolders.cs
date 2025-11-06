using System.IO.Compression;

namespace WhoYouCalling.Utilities
{
    internal static class FileAndFolders
    {
        public static string GetProcessFolderNameIncremented(string directoryPath, string processFolderName)
        {
            var directories = Directory.GetDirectories(directoryPath, processFolderName + "*");
            return $"{processFolderName} - {directories.Length + 1}";
        }
        public static bool FolderExists(string directoryPath)
        {
            return Directory.Exists(directoryPath);
        }
        public static bool FileExists(string filePath)
        {
            return File.Exists(filePath);
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
            }
            else
            {
                ConsoleOutput.Print($"Unable to delete file {file}. It doesnt exist", PrintType.Warning);
            }
        }
        public static void DeleteOutputFolder(string folder)
        {
            Directory.Delete(folder, true);
        }

        public static void ZipOutputFolder(string outputFolder, string compressedFolderName)
        {
            try
            {
                ZipFile.CreateFromDirectory(sourceDirectoryName: outputFolder, destinationArchiveFileName: compressedFolderName);
            }
            catch (Exception ex)
            {
                ConsoleOutput.Print($"Unable to compress output folder to ZIP file. Error: {ex}", PrintType.Error);
            }
        }
    }
}
