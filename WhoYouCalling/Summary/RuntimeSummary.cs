using WhoYouCalling.Process;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.Summary
{
    public struct RuntimeSummary
    {
        public string WYCMode { get; set; }
        public string WYCCommandline { get; set; }
        public string WYCVersion { get; set; }
        public string WYCResultsOutputPath { get; set; }
        public bool FPC {  get; set; }
        public DateTime StartTime { get; set; }
        public DateTime StopTime { get; set; }
        public string PresentableDuration { get; set; }
        public string Hostname { get; set; }
        public string HostOS { get; set; }
        public string HostTimeZone { get; set; }

        public RuntimeSummary(List<MonitoredProcess> monitoredProcesses)
        {

            WYCMode = Program.GetRunningMainMode().ToString();
            WYCCommandline = Program.GetFullProgramCommandLine();
            WYCVersion= Generic.GetVersion();
            WYCResultsOutputPath = Program.GetFinalFullOutputPath();
            FPC = Program.FPCWasCollected();
            Hostname = Generic.GetHostname();
            HostOS = Generic.GetOS();
            HostTimeZone = Generic.GetMachineTimeZone();
            StartTime = Program.GetStartTime();
            StopTime = Program.GetStopTime();
            PresentableDuration = Generic.GetPresentableDuration(startTime: Program.GetStartTime(), endTime: Program.GetStopTime());
        }
    }
}