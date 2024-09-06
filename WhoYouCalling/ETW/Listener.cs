using Microsoft.Diagnostics.Tracing.Session;


namespace WhoYouCalling.ETW
{
    internal class Listener
    {
        protected int _trackedProcessId = 0;
        protected string _mainExecutableFileName = "";
        protected TraceEventSession _session;

        public bool IsAMonitoredProcess(int pid)
        {
            if (_trackedProcessId == pid || Program.IsTrackedChildPID(pid))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public void SetPIDAndImageToTrack(int pid, string executable)
        {
            _mainExecutableFileName = executable;
            _trackedProcessId = pid;
        }

        public void StopSession()
        {
            _session.Dispose();
        }
        public bool GetSessionStatus()
        {
            return _session.IsActive;
        }
    }
}