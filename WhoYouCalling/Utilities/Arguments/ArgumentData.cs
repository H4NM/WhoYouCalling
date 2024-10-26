
namespace WhoYouCalling.Utilities.Arguments
{
    public struct ArgumentData
    {

        // Provided meta
        public bool InvalidArgumentValueProvided;

        // Set flags
        public bool ExecutableFlagSet;
        public bool ExecutableArgsFlagSet;
        public bool PIDFlagSet;
        public bool NetworkInterfaceDeviceFlagSet;
        public bool NoPCAPFlagSet;
        public bool KillProcessesFlagSet;
        public bool ExecutableNamesToMonitorFlagSet;
        public bool ProcessRunTimerFlagSet;
        public bool UserNameFlagSet;
        public bool UserPasswordFlagSet;
        public bool OutputDirectoryFlagSet;
        public bool MonitorEverythingFlagSet;

        // Value holders
        public List<string> ExecutableNamesToMonitor { get; set; }
        public int TrackedProcessId { get; set; }
        public double ProcessRunTimer { get; set; }
        public int NetworkInterfaceChoice { get; set; }
        public string ExecutablePath { get; set; }
        public string ExecutableArguments { get; set; }
        public bool RunExecutableWithHighPrivilege { get; set; }
        public string UserName { get; set; }
        public string UserPassword { get; set; }
        public string OutputDirectory { get; set; }
        public bool KillProcesses { get; set; }
        public bool SaveFullPcap { get; set; }
        public bool NoPacketCapture { get; set; }
        public bool DumpResultsToJson { get; set; }
        public bool StrictCommunicationEnabled { get; set; }
        public bool OutputBPFFilter { get; set; }
        public bool OutputWiresharkFilter { get; set; }
        public bool Debug { get; set; } // Gets a default value since it's set to a public variable in Program
        public bool TrackChildProcesses { get; set; } // Gets a default value since it's set to a public variable in Program

        public ArgumentData(bool invalidArgumentValueProvided = false,
                            bool executableFlagSet = false,
                            bool executableNamesToMonitorFlagSet = false,
                            bool processRunTimerFlagSet = false,
                            bool executableArgsFlagSet = false,
                            bool PIDFlagSet = false,
                            bool networkInterfaceDeviceFlagSet = false,
                            bool noPCAPFlagSet = false,
                            bool killProcessesFlagSet = false,
                            bool outputDirectoryFlagSet = false,
                            bool userNameFlagSet = false,
                            bool userPasswordFlagSet = false,
                            bool monitorEverythingFlagSet = false,
                            bool debug = false,
                            bool runExecutableWithHighPrivilege = false,
                            bool trackChildProcesses = true,
                            string outputDirectory = "",
                            string userName = "",
                            string password = "")
        {
            this.ExecutableFlagSet = executableFlagSet;
            this.ExecutableArgsFlagSet = executableArgsFlagSet;
            this.ProcessRunTimerFlagSet = processRunTimerFlagSet;
            this.PIDFlagSet = PIDFlagSet;
            this.NetworkInterfaceDeviceFlagSet = networkInterfaceDeviceFlagSet;
            this.NoPCAPFlagSet = noPCAPFlagSet;
            this.KillProcessesFlagSet = killProcessesFlagSet;
            this.OutputDirectoryFlagSet = outputDirectoryFlagSet;
            this.UserNameFlagSet = userNameFlagSet;
            this.UserPasswordFlagSet = userPasswordFlagSet;
            this.InvalidArgumentValueProvided = invalidArgumentValueProvided;
            this.TrackChildProcesses = trackChildProcesses;
            this.RunExecutableWithHighPrivilege = runExecutableWithHighPrivilege;
            this.OutputDirectory = outputDirectory;
            this.UserName = userName;
            this.UserPassword = password;
            this.MonitorEverythingFlagSet = monitorEverythingFlagSet;
            this.Debug = debug;
        }
    }
}
