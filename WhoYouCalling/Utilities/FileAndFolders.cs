using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using WhoYouCalling.Constants;

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

        public static string? CalculateFileMD5(string filePath)
        {
            try { 
                using (var md5 = MD5.Create())
                {
                    using (var stream = File.OpenRead(filePath))
                    {
                        var hash = md5.ComputeHash(stream);
                        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                    }
                }
            }
            catch
            {
                return null;
            }
        }
        public static string? CalculateFileSHA1(string filePath)
        {
            try
            {
                using (var sha1 = SHA1.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha1.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch
            {
                return null;
            }
        }

        public static string? CalculateFileSHA256(string filePath)
        {
            try
            {
                using (var sha256 = SHA256.Create())
                using (var stream = File.OpenRead(filePath))
                {
                    var hash = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                }
            }
            catch 
            {
                return null;
            }
        }

        public static string? GetFileCreationTime(string filePath)
        {
            try
            {
                var fileInfo = new System.IO.FileInfo(filePath);
                return fileInfo.CreationTime.ToString();
            }
            catch 
            {
                return null;
            }
        }

        public static bool FileIsDigitallySigned(string filePath)
        {
            try
            {
                return X509Certificate.CreateFromSignedFile(filePath) != null;
            }
            catch
            {
                return false;
            }
        }

    }
}
