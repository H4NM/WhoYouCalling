using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;

namespace WhoYouCalling.Process
{
    public class MonitoredProcess
    {
        public int PID { get; set; } = 0;
        public string ProcessName { get; set; } = "";
        public string CommandLine { get; set; } = "";
        public string? ExecutableFileName { get; set; } = null;
        public bool MappedProcess { get; set; } = true;
        public bool? IsolatedProcess { get; set; } = null;
        public DateTime ProcessAddedToMonitoringTime { get; set; } = new();
        public DateTime? ProcessStartTime { get; set; } = null;
        public DateTime? ProcessStopTime { get; set; } = null;
        public List<ChildProcessInfo> ChildProcesses { get; set; } = new(); 
        public HashSet<ConnectionRecord> TCPIPTelemetry { get; set; } = new();
        public HashSet<DNSQuery> DNSQueries { get; set; } = new();
        public HashSet<DNSResponse> DNSResponses { get; set; } = new();
    }
}