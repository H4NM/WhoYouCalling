using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;

namespace WhoYouCalling.Process
{
    public class MonitoredProcess
    {
        public int PID { get; set; } = 0;
        public string ProcessName { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public bool? IsolatedProcess { get; set; } = null;
        public DateTime ProcessStartTime { get; set; } = new();
        public DateTime ProcessStopTime { get; set; } = new();
        public List<ChildProcessInfo> ChildProcesses { get; set; } = new();
        public HashSet<ConnectionRecord> TCPIPTelemetry { get; set; } = new();
        public HashSet<DNSQuery> DNSQueries { get; set; } = new();
        public HashSet<DNSResponse> DNSResponses { get; set; } = new();
    }
}