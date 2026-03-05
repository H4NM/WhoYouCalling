
namespace WhoYouCalling.Constants
{
    static class TokenPrivileges
    {
        public const Int32 Duplicate = 2;
        public const Int32 Query = 8;
        public const Int32 AssignPrimary = 1;
        public const Int32 AdjustPrivileges = 0x20;
        public const Int32 AdjustDefault = 0x80;
        public const Int32 AdjustSessionID = 0x100;
    }
}
