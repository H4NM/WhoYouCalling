
namespace WhoYouCalling.Process
{
    public class ExecutableInformation
    {
        public string? FilePath { get; set; } = null;
        public long? FileSize { get; set; } = null;
        public string? FileCompany { get; set; } = null;
        public string? FileProductName { get; set; } = null;
        public string? FileProductVersion { get; set; } = null;
        public double? FileEntropy { get; set; } = null;
        public string? MD5 { get; set; } = null;
        public string? SHA1 { get; set; } = null;
        public string? SHA256 { get; set; } = null;
        public bool? IsSigned { get; set; } = null;
        public string? CreatedTimestamp { get; set; } = null;

    }
}