using Microsoft.Diagnostics.Tracing.Session;

namespace WhoYouCalling.ETW
{
    internal class Listener
    {
        protected TraceEventSession _session;
        public string SourceName = "";

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