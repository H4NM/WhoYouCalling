using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using WhoYouCalling.Utilities;
using System.ComponentModel;
using WhoYouCalling.Win32;
using System;
using System.Security;

namespace WhoYouCalling.Process
{ 
    internal static class ProcessManager
    {

        public static bool IsProcessRunning(int pid)
        {
            System.Diagnostics.Process[] processList = System.Diagnostics.Process.GetProcesses();
            foreach (System.Diagnostics.Process activePID in processList)
            {
                if (pid == activePID.Id)
                {
                    ConsoleOutput.Print($"Provided PID ({pid}) is active on the system", PrintType.Debug);
                    return true;
                }
            }
            ConsoleOutput.Print($"Unable to find process with pid {pid}", PrintType.Debug);
            return false;
        }

        public static string GetProcessFileName(int pid)
        {
            try
            {
                System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(pid);
                StringBuilder buffer = new StringBuilder(1024);
                int size = buffer.Capacity;
                if (Win32.WinAPI.QueryFullProcessImageName(process.Handle, 0, buffer, ref size))
                {
                    string executableFullPath = buffer.ToString();
                    return Path.GetFileName(executableFullPath);
                }
            }
            catch (Exception ex)
            {
                ConsoleOutput.Print($"Error when retrieving executable filename from PID: {ex.Message}", PrintType.Debug);
            }
            string defaultExecName = "NA";
            ConsoleOutput.Print($"Unable to retrieve executable filename from PID. Setting default name \"{defaultExecName}\"", PrintType.Debug);
            return defaultExecName;

        }

        public static void KillProcess(int pid)
        {
            try
            {
                System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(pid);

                if (!process.HasExited)
                {
                    ConsoleOutput.Print($"Killing the process with PID {pid}", PrintType.Debug);
                    process.Kill();
                }
            }
            catch (ArgumentException)
            {
                ConsoleOutput.Print($"Process with PID {pid} has already exited.", PrintType.Debug);
            }
            catch (Exception ex)
            {
                ConsoleOutput.Print($"An error occurred when stopping process when timer expired: {ex.Message}", PrintType.Debug);
            }
        }

        private static void EnableSeIncreaseQuotaPrivilege()
        {
            var hProcessToken = IntPtr.Zero;
            try
            {
                var process = Win32.WinAPI.GetCurrentProcess();
                if (!Win32.WinAPI.OpenProcessToken(process, 0x0020, out hProcessToken))
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    string errorMessage = new Win32Exception(errorCode).Message;
                    throw new Win32Exception(errorCode, $"Failed to lookup privilege value for current process. [ERROR: {errorCode}] - {errorMessage}");

                }

                var tkp = new Win32.WinAPI.TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new Win32.WinAPI.LUID_AND_ATTRIBUTES[1]
                };

                if (!Win32.WinAPI.LookupPrivilegeValue(null, "SeIncreaseQuotaPrivilege", ref tkp.Privileges[0].Luid))
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    string errorMessage = new Win32Exception(errorCode).Message;
                    throw new Win32Exception(errorCode, $"Failed to lookup privilege value for current process. [ERROR: {errorCode}] - {errorMessage}");

                }

                tkp.Privileges[0].Attributes = 0x00000002;

                if (!Win32.WinAPI.AdjustTokenPrivileges(hProcessToken, false, ref tkp, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    string errorMessage = new Win32Exception(errorCode).Message;
                    throw new Win32Exception(errorCode, $"Failed to adjust current process token privilege. [ERROR: {errorCode}] - {errorMessage}");
                }

            }
            finally
            {
                Win32.WinAPI.CloseHandle(hProcessToken);
            }
        }

        public static int StarProcessAndGetPIDWithShellWindow(string executablePath, string arguments = "")
        {
            /*
            This function spawns a process with a medium integrity level, i.e. user privilege.
            It depends on the desktop shell window (which is typically the Windows Explorer process, explorer.exe)
            as it copies the security token of that process, which is unprivileged by default and thereafter creates 
            the target process with a duplicate of that token. Spawning unprivileged processes from an already privileged 
            process is tricky and this was deemed as the best approach. For now. 
             */

            EnableSeIncreaseQuotaPrivilege();

            var shellWnd = Win32.WinAPI.GetShellWindow();
            if (shellWnd == IntPtr.Zero)
            {
                throw new Exception($"Could not find shell window to retrieve token for spawning unprivileged process");
            }

            string tempWorkingDirectory = Path.GetDirectoryName(executablePath);

            uint shellProcessId;
            WinAPI.GetWindowThreadProcessId(shellWnd, out shellProcessId); // Get the process ID of the shell window

            var hShellProcess = Win32.WinAPI.OpenProcess(Constants.QueryInformation, false, shellProcessId); // To query the process for the token
            if (hShellProcess == IntPtr.Zero)
            {
                int errorCode = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception(errorCode).Message;
                throw new Win32Exception(errorCode, $"Failed to open desktop shell process. [ERROR: {errorCode}] - {errorMessage}");
            }
            
            var hShellToken = IntPtr.Zero;
            if (!Win32.WinAPI.OpenProcessToken(hShellProcess, Constants.TokenDuplicate, out hShellToken)) // Read the token of the shell process, the DesiredAccess is 2 which is duplicate token
            {
                int errorCode = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception(errorCode).Message;
                throw new Win32Exception(errorCode, $"Failed to open process token from desktop shell window. [ERROR: {errorCode}] - {errorMessage}");
            }

            uint tokenAccess = Constants.TokenQuery | Constants.TokenAssignPrimary | Constants.TokenDuplicate | Constants.TokenAdjustDefault | Constants.TokenAdjustSessionID;
            var hToken = IntPtr.Zero;
            if (!Win32.WinAPI.DuplicateTokenEx(hShellToken, tokenAccess, IntPtr.Zero, Constants.ImpersonationSecurity, Constants.TokenAssignPrimary, out hToken))
            {
                int errorCode = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception(errorCode).Message;
                throw new Win32Exception(errorCode, $"Failed to duplicate token for new unprivileged process. [ERROR: {errorCode}] - {errorMessage}");
            }

            // Set up the startup information for the new process
            var startInfo = new Win32.WinAPI.STARTUPINFO();
            startInfo.cb = Marshal.SizeOf(startInfo);
            var processInfo = new Win32.WinAPI.PROCESS_INFORMATION();

            string commandLine = $"{executablePath} {arguments}";
            if (!Win32.WinAPI.CreateProcessWithTokenW(hToken, Constants.LogonFlags, null, commandLine, Constants.CreationFlags, IntPtr.Zero, tempWorkingDirectory, ref startInfo, out processInfo))
            {
                int errorCode = Marshal.GetLastWin32Error();
                string errorMessage = new Win32Exception(errorCode).Message;
                throw new Win32Exception(errorCode, $"Failed to create unprivileged process with duplicated token. [ERROR: {errorCode}] - {errorMessage}. Maybe try running it with the elevated flag?");
            }

            return (int)(processInfo.dwProcessId); 
        }

        public static int StartProcessAndGetId(string executablePath, 
                                               string arguments = "",
                                               string username = "",
                                               string password = "",
                                               bool runPrivileged = false)
        {
            var prevWorkingDirectory = Environment.CurrentDirectory;
            try
            {
                string tempWorkingDirectory = Path.GetDirectoryName(executablePath);
                Environment.CurrentDirectory = tempWorkingDirectory;
   
                System.Diagnostics.Process proc = new System.Diagnostics.Process
                {
                    StartInfo =
                    {
                       FileName =  executablePath,
                       WorkingDirectory = tempWorkingDirectory
                    }
                };

                if (runPrivileged)
                {
                    proc.StartInfo.Verb = "runas";
                    proc.StartInfo.UseShellExecute = true;
                }
                else
                {
                    proc.StartInfo.Verb = "open";
                    proc.StartInfo.UseShellExecute = false;
                }

                if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
                {
                    proc.StartInfo.UserName = username;
                    SecureString ssPassword = new SecureString();
                    foreach (char c in password)  
                    {
                        ssPassword.AppendChar(c);
                    }
                    proc.StartInfo.Password = ssPassword;
                }


                if (!string.IsNullOrEmpty(arguments))
                {
                    proc.StartInfo.Arguments = arguments;
                }

                proc.Start();

                if (proc != null)
                {
                    return proc.Id;
                }
                else
                {
                    throw new InvalidOperationException("Failed to start the process.");
                }
            }
            catch (Exception ex)
            {
                ConsoleOutput.Print($"An error occurred: {ex.Message}", PrintType.Error);
                throw;
            }
            finally
            {
                Environment.CurrentDirectory = prevWorkingDirectory;
            }
        }
    }
}