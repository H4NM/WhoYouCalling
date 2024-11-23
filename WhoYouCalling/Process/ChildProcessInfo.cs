
namespace WhoYouCalling.Process
{
    public class ChildProcessInfo
    {
        public int ProcessID { get; set; }
        public string ProcessName { get; set; }
        public DateTime ETWRegisteredStartTime { get; set; } = new();
    }
}
