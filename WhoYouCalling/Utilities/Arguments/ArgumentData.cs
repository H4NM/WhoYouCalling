
namespace WhoYouCalling.Utilities.Arguments
{
    public struct ArgumentData
    {
        // Argument meta flags
        public bool InvalidArgumentValueProvided;
        public bool ExecutableFlagSet;
        public bool ExecutableNamesToMonitorFlagSet;
        public bool ExecutableArgsFlagSet;
        public bool PIDFlagSet;
        public bool NetworkInterfaceDeviceFlagSet;
        public bool NoPCAPFlagSet;
        public bool KillProcessesFlagSet;

        // Arguments
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
        public bool Debug { get; set; } // Gets a default value since it's set to a public variable in Program
        public bool TrackChildProcesses { get; set; } // Gets a default value since it's set to a public variable in Program

        public ArgumentData(bool executableFlagSet = false,
                            bool executableNamesToMonitorFlagSet = false,
                            bool executableArgsFlagSet = false,
                            bool PIDFlagSet = false,
                            bool networkInterfaceDeviceFlagSet = false,
                            bool noPCAPFlagSet = false,
                            bool killProcessesFlagSet = false,
                            bool invalidArgumentValueProvided = false,
                            bool debug = false,
                            bool trackChildProcesses = true,
                            string outputDirectory = "")
        {
            this.ExecutableFlagSet = executableFlagSet;
            this.ExecutableNamesToMonitorFlagSet = executableNamesToMonitorFlagSet;
            this.ExecutableArgsFlagSet = executableArgsFlagSet;
            this.PIDFlagSet = PIDFlagSet;
            this.NetworkInterfaceDeviceFlagSet = networkInterfaceDeviceFlagSet;
            this.NoPCAPFlagSet = noPCAPFlagSet;
            this.KillProcessesFlagSet = killProcessesFlagSet;
            this.InvalidArgumentValueProvided = invalidArgumentValueProvided;
            this.Debug = debug;
            this.TrackChildProcesses = trackChildProcesses;
            this.OutputDirectory = outputDirectory;
        }
    }
}
