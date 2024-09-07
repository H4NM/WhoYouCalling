using PacketDotNet;
using static System.Runtime.InteropServices.JavaScript.JSType;
using System.Xml.Linq;

namespace WhoYouCalling.Network.DNS
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
            { 23, "BADCOOKIE" },       // Bad/missing server cookie
            { 999999, "N/A" },         // Custom Non-existent DNS Status Value

            { 87, "WIN_ERROR_INVALID_PARAMETER" }, // All status codes blow are Custom Windows DNS error. Not part of DNS standard
            { 9001, "WIN_DNS_SERVER_UNABLE_TO_INTERPRET_FORMAT" }, 
            { 9002, "WIN_DNS_SERVER_FAILURE"},
            { 9003, "WIN_DNS_NAME_DOES_NOT_EXIST" },
            { 9004, "WIN_DNS_REQUEST_NOT_SUPPORTED_BY_NAME_SERVER" },
            { 9005, "WIN_DNS_OPERATION_REFUSED" },
            { 9006, "WIN_DNS_NAME_THAT_OUGHT_NOT_EXIST_DOES_EXIST" },
            { 9007, "WIN_DNS_RR_SET_THAT_OUGHT_NOT_EXIST_DOES_EXIST" },
            { 9008, "WIN_DNS_RR_SET_THAT_OUGHT_TO_EXIST_DOES_NOT_EXIST" },
            { 9009, "WIN_DNS_SERVER_NOT_AUTHORITATIVE_FOR_ZONE" },
            { 9010, "WIN_DNS_NAME_IN_UPDATE_OR_PREREQ_IS_NOT_IN_ZONE" },
            { 9016, "WIN_DNS_SIGNATURE_FAILED_TO_VERIFY" },
            { 9017, "WIN_DNS_BAD_KEY" },
            { 9018, "WIN_DNS_SIGNATURE_VALIDITY_EXPIRED" },
            { 9501, "WIN_NO_RECORDS_FOUND_FOR_GIVEN_DNS_QUERY" },
            { 9502, "WIN_BAD_DNS_PACKET" },
            { 9503, "WIN_NO_DNS_PACKET_9504" },
            { 9505, "WIN_UNSECURED_DNS_PACKET" }

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
