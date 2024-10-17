
namespace WhoYouCalling.Network
{
    public struct NetworkEndpoint
    {
        public string IP { get; set; }
        public int Port { get; set; }

        public override bool Equals(object obj)
        {
            if (obj == null || this.GetType() != obj.GetType())
                return false;

            var other = (NetworkEndpoint)obj;
            return IP == other.IP &&
                   Port == other.Port;
        }

        public override int GetHashCode()
        {
            int hash = 17;
            hash = hash * 31 + (IP != null ? IP.GetHashCode() : 0);
            hash = hash * 31 + Port.GetHashCode();
            return hash;
        }
    }
}
