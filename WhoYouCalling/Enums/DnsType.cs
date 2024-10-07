
namespace WhoYouCalling.Network.DNS
{
    public enum DnsType : int
    {
        A = 1,               // Address record
        NS = 2,              // Name server record
        CNAME = 5,           // Canonical name record
        SOA = 6,             // Start of authority record
        PTR = 12,            // Pointer record (reverse DNS)
        MX = 15,             // Mail exchange record
        TXT = 16,            // Text record
        AAAA = 28,           // IPv6 address record
        SRV = 33,            // Service locator
        ANY = 255,           // Any type (wildcard)
        RP = 17,             // Responsible person
        AFSDB = 18,          // AFS database record
        LOC = 29,            // Location record
        NAPTR = 35,          // Naming authority pointer
        KX = 36,             // Key exchange
        CERT = 37,           // Certificate record
        DNAME = 39,          // Delegation name
        OPT = 41,            // Option record
        APL = 42,            // Address prefix list
        DS = 43,             // Delegation signer
        SSHFP = 44,          // SSH fingerprint
        IPSECKEY = 45,       // IPSEC key
        RRSIG = 46,          // Resource record signature
        NSEC = 47,           // Next secure record
        DNSKEY = 48,         // DNS key
        DHCID = 49,          // DHCP identifier
        NSEC3 = 50,          // Next secure record version 3
        NSEC3PARAM = 51,     // NSEC3 parameters
        TLSA = 52,           // TLSA record
        SMIMEA = 53,         // S/MIME cert association
        HIP = 55,            // Host identity protocol
        CDS = 59,            // Child DS
        CDNSKEY = 60,        // Child DNSKEY
        OPENPGPKEY = 61,     // OpenPGP key record
        CSYNC = 62,          // Child-to-parent synchronization
        ZONEMD = 63,         // Message digest for DNS zone
        SVCB = 64,           // Service binding
        HTTPS = 65,          // HTTPS binding
        TKEY = 249,          // Transaction key
        TSIG = 250,          // Transaction signature
        IXFR = 251,          // Incremental zone transfer
        AXFR = 252,          // Authoritative zone transfer
        URI = 256,           // URI record
        CAA = 257,           // Certification authority authorization
        AVC = 258,           // Application visibility and control
        AMTRELAY = 260,      // Automatic multicast tunneling relay
        TA = 32768,          // DNSSEC Trust Authorities
        DLV = 32769,         // DNSSEC Lookaside Validation

        NA = 999999          // Custom Non-existent DNS Type Value
    }
}
