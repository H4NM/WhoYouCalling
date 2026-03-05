
namespace WhoYouCalling.Process
{
    public class ObservedProcess
    {
        public int PID { get; set; } = 0;
        public string ProcessName { get; set; } = "";
        public string? CommandLine { get; set; } = null;
        public DateTime? StartTime { get; set; } = null;
        public DateTime? StopTime { get; set; } = null;
    }
}