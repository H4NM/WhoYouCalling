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
        public bool ProcessesesNamesToMonitorFlagSet;
        public bool ProcessRunTimerFlagSet;
        public bool UserNameFlagSet;
        public bool UserPasswordFlagSet;
        public bool OutputDirectoryFlagSet;
        public bool MonitorEverythingFlagSet;

        // Value holders
        public List<string> ProcessesNamesToMonitor;
        public int TrackedProcessId;
        public double ProcessRunTimer;
        public int NetworkInterfaceChoice;
        public string ExecutablePath;
        public string ExecutableArguments;
        public bool RunExecutableWithHighPrivilege;
        public string UserName;
        public string UserPassword;
        public string OutputDirectory;
        public bool KillProcesses;
        public bool SaveFullPcap;
        public bool NoPacketCapture;
        public bool StrictCommunicationEnabled;
        public bool OutputBPFFilter;
        public bool OutputWiresharkFilter;
        public bool Debug;

        public ArgumentData()
        {
            InvalidArgumentValueProvided = false;

            ExecutableFlagSet = false;
            ExecutableArgsFlagSet = false;
            PIDFlagSet = false;
            NetworkInterfaceDeviceFlagSet = false;
            NoPCAPFlagSet = false;
            KillProcessesFlagSet = false;
            ProcessesesNamesToMonitorFlagSet = false;
            ProcessRunTimerFlagSet = false;
            UserNameFlagSet = false;
            UserPasswordFlagSet = false;
            OutputDirectoryFlagSet = false;
            MonitorEverythingFlagSet = false;

            ProcessesNamesToMonitor = new List<string>();
            TrackedProcessId = 0;
            ProcessRunTimer = 0;
            NetworkInterfaceChoice = 0;
            ExecutablePath = string.Empty;
            ExecutableArguments = string.Empty;
            RunExecutableWithHighPrivilege = false;
            UserName = string.Empty;
            UserPassword = string.Empty;
            OutputDirectory = string.Empty;
            KillProcesses = false;
            SaveFullPcap = false;
            NoPacketCapture = false;
            StrictCommunicationEnabled = false;
            OutputBPFFilter = false;
            OutputWiresharkFilter = false;
            Debug = false;
        }
    }
}
