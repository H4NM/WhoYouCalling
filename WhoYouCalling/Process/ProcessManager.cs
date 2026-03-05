
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;

using WhoYouCalling.Utilities;
using WhoYouCalling.Win32;
using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;


namespace WhoYouCalling.Process
{ 
    internal static class ProcessManager
    {

        public static bool ProcessHasNoRecordedNetworkActivity(MonitoredProcess monitoredProcess)
        {
            if (monitoredProcess.DNSQueries.Count == 0 &&
                monitoredProcess.DNSResponses.Count == 0 &&
                monitoredProcess.TCPIPTelemetry.Count == 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        public static int GetNumberOfProcessesWithNetworkTraffic(List<MonitoredProcess> monitoredProcesses)
        {
            int counter = 0;
            foreach (MonitoredProcess monitoredProcess in monitoredProcesses)
            {
                if (!ProcessHasNoRecordedNetworkActivity(monitoredProcess)) // Check if the processes has any network activities recorded. If not, go to next process
                {
                    counter++;
                }
            }
            return counter;
        }

        public static string GetUniqueProcessIdentifier(int pid, string processName)
        {
            return $"{processName}{pid}";
        }

        public static string GetPIDProcessName(int pid)
        {
            try
            {
                return System.Diagnostics.Process.GetProcessById(pid).ProcessName;
            }
            catch
            {
                if (Program.IsMonitoredProcess(pid: pid))
                {
                    string processName = "";
                    if (Program.MonitoredProcessCanBeRetrievedWithPID(pid))
                    {
                        processName = Program.GetMonitoredProcessWithPID(pid).ProcessName;
                    }
                    else
                    {
                        processName = Program.GetBackupProcessName(pid);
                    }
                    return processName;
                }
                else
                {
                    return WhoYouCalling.Miscellaneous.UnmappedProcessDefaultName;
                }
            }
        }

        public static bool IsProcessRunning(int pid)
        {
            System.Diagnostics.Process[] processList = System.Diagnostics.Process.GetProcesses();
            foreach (System.Diagnostics.Process activePID in processList)
            {
                if (pid == activePID.Id)
                {
                    return true;
                }
            }
            return false;
        }

        public static void MergeMonitoredProcesses(MonitoredProcess target, MonitoredProcess source)
        {
            if (target.Executable.FilePath == null && source.Executable.FilePath != null)
            {
                target.Executable.FilePath = source.Executable.FilePath;
            }
            if (target.StartTime == null && source.StartTime != null)
            {
                target.StartTime = source.StartTime;
            }
            if (target.StopTime == null && source.StopTime != null)
            {
                target.StopTime = source.StopTime;
            }
            if (source.ChildProcesses.Count > 0)
            {
                foreach (ChildProcessInfo childProcessInfo in source.ChildProcesses)
                {
                    target.ChildProcesses.Add(childProcessInfo);
                }
            }
            if (source.TCPIPTelemetry.Count > 0)
            {
                foreach (ConnectionRecord connectionRecord in source.TCPIPTelemetry)
                {
                    target.TCPIPTelemetry.Add(connectionRecord);
                }
            }
            if (source.DNSQueries.Count > 0)
            {
                foreach (DNSQuery dnsQuery in source.DNSQueries)
                {
                    target.DNSQueries.Add(dnsQuery);
                }
            }
            if (source.DNSResponses.Count > 0)
            {
                foreach (DNSResponse dnsResponse in source.DNSResponses)
                {
                    target.DNSResponses.Add(dnsResponse);
                }
            }
        }
        public static void KillProcess(int pid)
        {
            try
            {
                System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(pid);

                if (!process.HasExited)
                {
                    process.Kill();
                }
            }
            catch (Exception ex)
            {
                ConsoleOutput.Print($"An error occurred when stopping process when timer expired: {ex.Message}", PrintType.Warning);
            }
        }

        public static MonitoredProcess EnrichMonitoredProcessData(MonitoredProcess monitoredProcess, int pid, string processName)
        {

            System.Diagnostics.Process? process = null;

            try
            {
                process = System.Diagnostics.Process.GetProcessById(pid);
            }
            catch 
            {
            }

            if (process != null)
            {
                monitoredProcess.ProcessUser = GetProcessUser(process);
                monitoredProcess.ProcessName = process.ProcessName;
                monitoredProcess.SessionID = process.SessionId;
                monitoredProcess.StartTime = process.StartTime;

                try
                {
                        #pragma warning disable CS8602 // Dereference of a possibly null reference.
                        monitoredProcess.Executable.FilePath = process.MainModule.FileName;
                        #pragma warning restore CS8602 // Dereference of a possibly null reference.
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    monitoredProcess.IsolatedProcess = true;
                }
                catch (InvalidOperationException)
                {
                }

            }

            if (monitoredProcess.ProcessName == WhoYouCalling.Miscellaneous.UnmappedProcessDefaultName) // Ensuring that if it's still unmapped name it's defined as not Unmapped
            {
                monitoredProcess.MappedProcess = false;
            }

            return monitoredProcess;
        }

        // https://stackoverflow.com/questions/777548/how-do-i-determine-the-owner-of-a-process-in-c
        public static string? GetProcessUser(System.Diagnostics.Process process)
        {
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                Win32.WinAPI.OpenProcessToken(process.Handle, 8, out processHandle);

                #pragma warning disable CA1416 // Warning stating that the code only works on Windows. I know, thanks. 
                WindowsIdentity wi = new WindowsIdentity(processHandle);
                string user = wi.Name;
                #pragma warning restore CA1416

                if (string.IsNullOrEmpty(user))
                {
                    return null;
                }

                return user.Contains(@"\") ? user.Substring(user.IndexOf(@"\") + 1) : user;
            }
            catch
            {
                return null;
            }
            finally
            {
                if (processHandle != IntPtr.Zero)
                {
                    Win32.WinAPI.CloseHandle(processHandle);
                }
            }
        }

        private static void EnableSeIncreaseQuotaPrivilege()
        {
            var hProcessToken = IntPtr.Zero;
            try
            {
                var process = Win32.WinAPI.GetCurrentProcess();
                if (!Win32.WinAPI.OpenProcessToken(process, Constants.TokenPrivileges.AdjustPrivileges, out hProcessToken))
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    Win32.Win32ErrorManager.ThrowDetailedWindowsError("Failed to lookup privilege value for current process", errorCode);
                }

                var tkp = new Win32.WinAPI.TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges = new Win32.WinAPI.LUID_AND_ATTRIBUTES[1]
                };

                if (!Win32.WinAPI.LookupPrivilegeValue("", "SeIncreaseQuotaPrivilege", ref tkp.Privileges[0].Luid))
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    Win32.Win32ErrorManager.ThrowDetailedWindowsError("Failed to lookup privilege value for current process", errorCode);
                }

                tkp.Privileges[0].Attributes = SecurityFlags.SePrivilegeEnabled;

                if (!Win32.WinAPI.AdjustTokenPrivileges(hProcessToken, false, ref tkp, 0, IntPtr.Zero, IntPtr.Zero))
                {
                    int errorCode = Marshal.GetLastWin32Error();
                    Win32.Win32ErrorManager.ThrowDetailedWindowsError("Failed to adjust current process token privilege", errorCode);
                }
            }
            catch (Exception ex)
            {
                // This exception is not set as fatal at the moment as this function may not be needed
                ConsoleOutput.Print($"An error occurred while attempting to enable the SeIncreaseQuotaPrivilege: {ex.Message}", PrintType.Warning);
            }
            finally
            {
                Win32.WinAPI.CloseHandle(hProcessToken);
            }
        }

        public static int StartProcessAndGetPIDWithShellWindow(string executablePath, string arguments = "")
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

            string tempWorkingDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();

            WinAPI.GetWindowThreadProcessId(shellWnd, out uint shellProcessId);

            var hShellProcess = Win32.WinAPI.OpenProcess(SecurityFlags.QueryInformation, false, shellProcessId);
            if (hShellProcess == IntPtr.Zero)
            {
                int errorCode = Marshal.GetLastWin32Error();
                Win32.Win32ErrorManager.ThrowDetailedWindowsError("Failed to open desktop shell process", errorCode);
            }

            nint hShellToken = IntPtr.Zero;
            if (!Win32.WinAPI.OpenProcessToken(hShellProcess, Constants.TokenPrivileges.Duplicate, out hShellToken))
            {
                int errorCode = Marshal.GetLastWin32Error();
                Win32.Win32ErrorManager.ThrowDetailedWindowsError("Failed to open process token from desktop shell window", errorCode);
            }

            uint tokenAccess = Constants.TokenPrivileges.Query |
                               Constants.TokenPrivileges.AssignPrimary |
                               Constants.TokenPrivileges.Duplicate |
                               Constants.TokenPrivileges.AdjustDefault |
                               Constants.TokenPrivileges.AdjustSessionID;

            var hToken = IntPtr.Zero;

            if (!Win32.WinAPI.DuplicateTokenEx(hShellToken, tokenAccess, IntPtr.Zero, SecurityFlags.ImpersonationSecurity, Constants.TokenPrivileges.AssignPrimary, out hToken))
            {
                int errorCode = Marshal.GetLastWin32Error();
                Win32.Win32ErrorManager.ThrowDetailedWindowsError("Failed to duplicate token for new unprivileged process", errorCode);
            }

            var startInfo = new Win32.WinAPI.STARTUPINFO();
            startInfo.cb = Marshal.SizeOf(startInfo);
            var processInfo = new Win32.WinAPI.PROCESS_INFORMATION();

            string commandLine = $"{executablePath} {arguments}";
            if (!Win32.WinAPI.CreateProcessWithTokenW(hToken, SecurityFlags.LogonFlags, null, commandLine, SecurityFlags.CreationFlags, IntPtr.Zero, tempWorkingDirectory, ref startInfo, out processInfo))
            {
                int errorCode = Marshal.GetLastWin32Error();
                Win32.Win32ErrorManager.ThrowDetailedWindowsError("Failed to create unprivileged process with duplicated token", errorCode);
            }
            return (int)(processInfo.dwProcessId);
        }

        public static int StartProcessAndGetId(string executablePath = "", 
                                               string arguments = "",
                                               string username = "",
                                               string password = "",
                                               bool runPrivileged = false)
        {
            var prevWorkingDirectory = Environment.CurrentDirectory;
            try
            {
                string tempWorkingDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();
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
                    #pragma warning disable CA1416 // Warning stating that the code only works on Windows. I know, thanks. 
                    proc.StartInfo.Password = ssPassword;
                    #pragma warning restore CA1416
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