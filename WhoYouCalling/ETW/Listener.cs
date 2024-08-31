using Microsoft.Diagnostics.Tracing.Session;


namespace WhoYouCalling.ETW
{
    public class Listener
    {
        protected int _trackedProcessId = 0;
        protected string _mainExecutableFileName = "";
        protected TraceEventSession _session;

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