using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;

namespace WhoYouCalling.Process
{
    public class MonitoredProcess
    {
        public int PID { get; set; } = 0;
        public string ProcessName { get; set; } = "";
        public string? CommandLine { get; set; } = null;
        public string? ProcessUser { get; set; } = "";
        public int SessionID { get; set; } = 0;
        public ExecutableInformation Executable { get; set; } = new ExecutableInformation();
        public bool MappedProcess { get; set; } = true;
        public bool IsolatedProcess { get; set; } = false;
        public DateTime AddedToMonitoringTime { get; set; } = new();
        public DateTime? StartTime { get; set; } = null;
        public DateTime? StopTime { get; set; } = null;
        public List<ChildProcessInfo> ChildProcesses { get; set; } = []; 
        public HashSet<ConnectionRecord> TCPIPTelemetry { get; set; } = [];
        public HashSet<DNSQuery> DNSQueries { get; set; } = [];
        public HashSet<DNSResponse> DNSResponses { get; set; } = [];
    }
}