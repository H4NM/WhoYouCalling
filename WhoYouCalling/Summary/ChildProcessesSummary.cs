using WhoYouCalling.Process;

namespace WhoYouCalling.Summary
{
    public struct ChildProcessesSummary
    {
        public int NumberOfChildProcesses { get; set; }
        public HashSet<string> ChildProcessesNames { get; set; }

        public ChildProcessesSummary(MonitoredProcess monitoredProcess)
        {
            HashSet<string> childProcessNames = new();

            foreach (ChildProcessInfo childProcess in monitoredProcess.ChildProcesses)
            {
                childProcessNames.Add(childProcess.ProcessName);
            }

            NumberOfChildProcesses = monitoredProcess.ChildProcesses.Count;
            ChildProcessesNames = childProcessNames;
        }
    }
}

