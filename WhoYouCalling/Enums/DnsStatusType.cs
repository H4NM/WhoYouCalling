
namespace WhoYouCalling.Network.DNS
{
    public enum DnsStatusType : int
    {
        // Official DNS standard types
        NoError = 0,
        FormErr = 1,
        ServFail = 2,
        NXDomain = 3,
        NotImp = 4,
        Refused = 5,
        YXDomain = 6,
        YXRRSet = 7,
        NXRRSet = 8,
        NotAuth = 9,
        NotZone = 10,
        BADVERS = 16,
        BADKEY = 17,
        BADTIME = 18,
        BADMODE = 19,
        BADNAME = 20,
        BADALG = 21,
        BADTRUNC = 22,
        BADCOOKIE = 23,

        // Custom Windows types
        InvalidParameter = 87,
        DnsServerUnableToInterpretFormat = 9001,
        DnsServerFailure = 9002,
        DnsNameDoesNotExist = 9003,
        DnsRequestNotSupportedByNameServer = 9004,
        DnsOperationRefused = 9005,
        DnsNameThatOughtNotExistDoesExist = 9006,
        DnsRRSetThatOughtNotExistDoesExist = 9007,
        DnsRRSetThatOughtToExistDoesNotExist = 9008,
        DnsServerNotAuthoritativeForZone = 9009,
        DnsNameInUpdateOrPrereqIsNotInZone = 9010,
        DnsSignatureFailedToVerify = 9016,
        DnsBadKey = 9017,
        DnsSignatureValidityExpired = 9018,
        NoRecordsFoundForGivenDnsQuery = 9501,
        BadDnsPacket = 9502,
        NoDnsPacket = 9503,
        UnsecuredDnsPacket = 9505,

        // Custom value for non-existent DNS status
        NA = Constants.Miscellaneous.NotApplicableStatusNumber
    }
}
