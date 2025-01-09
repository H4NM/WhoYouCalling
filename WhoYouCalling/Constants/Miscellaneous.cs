
namespace WhoYouCalling.Constants
{
    static class Miscellaneous
    {
        public const Int32 NotApplicableStatusNumber = 999999;
        public const Int32 CustomWindowsDNSStatusCode = 87;
        public const Int32 MaxSecondsUnmappedProcessRange = 3;
        public const string UnmappedProcessDefaultName = "UnmappedProcess";
        public const string MainExecutableUnretrievableName = "UnretrievedExecutableName";
        public static readonly List<string> SpinnerChars = new List<string>
        {
            "-", "/", "|", "\\"
        };
    }
}
