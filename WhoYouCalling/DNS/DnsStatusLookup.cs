namespace WhoYouCalling.DNS
{
    public static class DnsStatusLookup
    {
        private static readonly Dictionary<int, string> CodeToName = new Dictionary<int, string>
        {
            { 0, "NoError" },          // No error condition
            { 1, "FormErr" },          // Format error
            { 2, "ServFail" },         // Server failure
            { 3, "NXDomain" },         // Non-existent domain
            { 4, "NotImp" },           // Not implemented
            { 5, "Refused" },          // Query refused
            { 6, "YXDomain" },         // Name exists when it should not
            { 7, "YXRRSet" },          // RR set exists when it should not
            { 8, "NXRRSet" },          // RR set that should exist does not
            { 9, "NotAuth" },          // Not authorized (formerly NotAuth)
            { 10, "NotZone" },         // Name not in zone
            { 16, "BADVERS" },         // Bad OPT version / TSIG signature failure
            { 17, "BADKEY" },          // Key not recognized
            { 18, "BADTIME" },         // Signature out of time window
            { 19, "BADMODE" },         // Bad TKEY mode
            { 20, "BADNAME" },         // Duplicate key name
            { 21, "BADALG" },          // Algorithm not supported
            { 22, "BADTRUNC" },        // Bad truncation
            { 23, "BADCOOKIE" },               // Bad/missing server cookie
            { 87, "ERROR_INVALID_PARAMETER" }, // Custom Windows DNS error. Not part of DNS standard
            { 999999, "N/A" }                  // Custom Non-existent DNS Status Value
        };

        private static readonly Dictionary<string, int> NameToCode = CodeToName
            .ToDictionary(kv => kv.Value, kv => kv.Key);

        public static string GetName(int statusCode)
        {
            return CodeToName.TryGetValue(statusCode, out string name) ? name : null;
        }

        public static int? GetStatusCode(string name)
        {
            return NameToCode.TryGetValue(name, out int statusCode) ? statusCode : (int?)null;
        }
    }
}
