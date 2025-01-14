using Microsoft.Diagnostics.Tracing.Session;

namespace WhoYouCalling.ETW
{
    internal class Listener
    {
        protected TraceEventSession? _session;
        public string SourceName = "";

        public void StopSession()
        {
            if (_session != null) 
            {
                _session.Dispose();
            }
        }
        public bool GetSessionStatus()
        {
            if (_session != null)
            {
                return _session.IsActive;
            }
            else
            {
                return false;
            }
        }
    }
}