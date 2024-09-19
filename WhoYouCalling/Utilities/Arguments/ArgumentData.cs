using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WhoYouCalling.Utilities.Arguments
{
    public struct ArgumentData
    {
        public List<string> ExecutableNamesToMonitor { get; set; }
        public bool ExecutableNamesToMonitorProvided { get; set; }
        public int TrackedProcessId { get; set; }
        public double ProcessRunTimer { get; set; }
        public bool ProcessRunTimerWasProvided { get; set; }
        public int NetworkInterfaceChoice { get; set; }
        public string ExecutablePath { get; set; }
        public bool ExecutablePathProvided { get; set; }
        public string ExecutableArguments { get; set; }
        public string OutputDirectory { get; set; }
        public bool ProvidedOutputDirectory { get; set; }
        public bool KillProcesses { get; set; }
        public bool SaveFullPcap { get; set; }
        public bool NoPacketCapture { get; set; }
        public bool DumpResultsToJson { get; set; }
        public bool StrictCommunicationEnabled { get; set; }
        public bool OutputBPFFilter { get; set; }
        public bool OutputWiresharkFilter { get; set; }
        public bool Debug { get; set; }
        public bool TrackChildProcesses { get; set; }
    }
}
