using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;

namespace WhoYouCalling.Process
{
    public class MonitoredProcess
    {
        public int PID { get; set; } = 0;
        public string ProcessName { get; set; } = "";
        public string? CommandLine { get; set; } = null;
        public ExecutableInformation Executable { get; set; } = new ExecutableInformation();
        public bool MappedProcess { get; set; } = true;
        public bool? IsolatedProcess { get; set; } = null;
        public DateTime AddedToMonitoringTime { get; set; } = new();
        public DateTime? StartTime { get; set; } = null;
        public DateTime? StopTime { get; set; } = null;
        public List<ChildProcessInfo> ChildProcesses { get; set; } = new(); 
        public List<ConnectionRecord> TCPIPTelemetry { get; set; } = new();
        public HashSet<DNSQuery> DNSQueries { get; set; } = new();
        public HashSet<DNSResponse> DNSResponses { get; set; } = new();
    }
}