using Microsoft.Diagnostics.Tracing.Session;

namespace WhoYouCalling.ETW
{
    internal class Listener
    {
        protected TraceEventSession? _session;
        public string SourceName = "";
        private readonly object _lock = new();

        public void StopSession()
        {
            lock (_lock) 
            {
                if (_session != null)
                {
                    _session.Dispose();
                    _session = null;
                }
            }
        }
        public bool GetSessionStatus()
        {
            try
            {
                return _session != null && _session.IsActive;
            }
            catch (ObjectDisposedException)
            {
                return false;
            }
        }
    }
}