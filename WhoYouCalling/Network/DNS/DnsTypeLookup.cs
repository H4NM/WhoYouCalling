namespace WhoYouCalling.Network.DNS
{
    public static class DnsTypeLookup
    {
        private static readonly Dictionary<int, string> TypeToName = new Dictionary<int, string>
        {
            { 1, "A" },              // Address record
            { 2, "NS" },             // Name server record
            { 5, "CNAME" },          // Canonical name record
            { 6, "SOA" },            // Start of authority record
            { 12, "PTR" },           // Pointer record (reverse DNS)
            { 15, "MX" },            // Mail exchange record
            { 16, "TXT" },           // Text record
            { 28, "AAAA" },          // IPv6 address record
            { 33, "SRV" },           // Service locator
            { 255, "ANY" },          // Any type (wildcard)
            { 17, "RP" },            // Responsible person
            { 18, "AFSDB" },         // AFS database record
            { 29, "LOC" },           // Location record
            { 35, "NAPTR" },         // Naming authority pointer
            { 36, "KX" },            // Key exchange
            { 37, "CERT" },          // Certificate record
            { 39, "DNAME" },         // Delegation name
            { 41, "OPT" },           // Option record
            { 42, "APL" },           // Address prefix list
            { 43, "DS" },            // Delegation signer
            { 44, "SSHFP" },         // SSH fingerprint
            { 45, "IPSECKEY" },      // IPSEC key
            { 46, "RRSIG" },         // Resource record signature
            { 47, "NSEC" },          // Next secure record
            { 48, "DNSKEY" },        // DNS key
            { 49, "DHCID" },         // DHCP identifier
            { 50, "NSEC3" },         // Next secure record version 3
            { 51, "NSEC3PARAM" },    // NSEC3 parameters
            { 52, "TLSA" },          // TLSA record
            { 53, "SMIMEA" },        // S/MIME cert association
            { 55, "HIP" },           // Host identity protocol
            { 59, "CDS" },           // Child DS
            { 60, "CDNSKEY" },       // Child DNSKEY
            { 61, "OPENPGPKEY" },    // OpenPGP key record
            { 62, "CSYNC" },         // Child-to-parent synchronization
            { 63, "ZONEMD" },        // Message digest for DNS zone
            { 64, "SVCB" },          // Service binding
            { 65, "HTTPS" },         // HTTPS binding
            { 249, "TKEY" },         // Transaction key
            { 250, "TSIG" },         // Transaction signature
            { 251, "IXFR" },         // Incremental zone transfer
            { 252, "AXFR" },         // Authoritative zone transfer
            { 256, "URI" },          // URI record
            { 257, "CAA" },          // Certification authority authorization
            { 258, "AVC" },          // Application visibility and control
            { 260, "AMTRELAY" },     // Automatic multicast tunneling relay
            { 32768, "TA" },         // DNSSEC Trust Authorities
            { 32769, "DLV" },        // DNSSEC Lookaside Validation
            { 999999, "N/A" }        // Custom Non-existent DNS Type Value
        };

        private static readonly Dictionary<string, int> NameToType = TypeToName
            .ToDictionary(kv => kv.Value, kv => kv.Key);

        public static string GetName(int typeNumber)
        {
            return TypeToName.TryGetValue(typeNumber, out string name) ? name : null;
        }

        public static int? GetTypeNumber(string name)
        {
            return NameToType.TryGetValue(name, out int typeNumber) ? typeNumber : null;
        }
    }
}
