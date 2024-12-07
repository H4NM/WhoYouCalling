using System.ComponentModel;

namespace WhoYouCalling.Win32
{
    public class Win32ErrorManager
    {
        public static void ThrowDetailedWindowsError(string message, int errorCode)
        {
            string errorMessage = new Win32Exception(errorCode).Message; 
            throw new Win32Exception(errorCode, $"{message}. [WinError: {errorCode}] - {errorMessage}");
        }
    }
}
