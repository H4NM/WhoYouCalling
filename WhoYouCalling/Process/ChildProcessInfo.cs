
namespace WhoYouCalling.Process
{
    public class ChildProcessInfo
    {
        public int PID { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public DateTime ETWRegisteredStartTime { get; set; } = new();
    }
}
