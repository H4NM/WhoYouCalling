
using System.Runtime.InteropServices;
using WhoYouCalling.Utilities;
using WhoYouCalling.Win32;
using System.Security;
using WhoYouCalling.Network;
using WhoYouCalling.Network.DNS;


namespace WhoYouCalling.Process
{ 
    internal static class ProcessManager
    {
        public static bool IsCorrectlyMatchingProcess(string retrievedProcessName, string providedProcessName)
        {
            if (!string.IsNullOrEmpty(providedProcessName) && providedProcessName != Constants.Miscellaneous.UnmappedProcessDefaultName && providedProcessName == retrievedProcessName)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        public static System.Diagnostics.Process? GetProcessSafelyByPID(int pid)
        {
            System.Diagnostics.Process? process;
            try
            {
                process = System.Diagnostics.Process.GetProcessById(pid);
            }
            catch
            {
                process = null;
            }
            return process;
        }

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
                System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(pid);
                return process.ProcessName;
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
                    return Constants.Miscellaneous.UnmappedProcessDefaultName;
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
            try
            {
                System.Diagnostics.Process process = System.Diagnostics.Process.GetProcessById(pid);
                if (monitoredProcess.ProcessName == Constants.Miscellaneous.UnmappedProcessDefaultName || String.IsNullOrEmpty(monitoredProcess.ProcessName))
                {
                    monitoredProcess.ProcessName = process.ProcessName;
                }

                if (ProcessManager.IsCorrectlyMatchingProcess(retrievedProcessName: process.ProcessName, providedProcessName: monitoredProcess.ProcessName)) // IF the passed process name is the same as the one that's been retrieved
                {
                    if (process.SessionId == 0)
                    {
                        monitoredProcess.IsolatedProcess = true;
                    }
                    else
                    {
                        monitoredProcess.IsolatedProcess = false;
                        monitoredProcess.StartTime = process.StartTime;
                    }
                    if (process.MainModule != null)
                    {
                        monitoredProcess.Executable.FilePath = process.MainModule.FileName;
                    }
                }
            }
            catch
            {
                if (string.IsNullOrEmpty(monitoredProcess.ProcessName)) // In case the try catch when retrieving the process details fails it resorts to setting the ProcessName value to unmapped default name
                {
                    monitoredProcess.ProcessName = Constants.Miscellaneous.UnmappedProcessDefaultName;
                }
            }


            if (monitoredProcess.ProcessName == Constants.Miscellaneous.UnmappedProcessDefaultName) // Ensuring that if it's still unmapped name it's defined as not Unmapped
            {
                monitoredProcess.MappedProcess = false;
            }

            return monitoredProcess;
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

                tkp.Privileges[0].Attributes = Constants.SecurityFlags.SePrivilegeEnabled;

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

            string tempWorkingDirectory = Path.GetDirectoryName(executablePath) ?? Directory.GetCurrentDirectory();

            uint shellProcessId;
            WinAPI.GetWindowThreadProcessId(shellWnd, out shellProcessId);

            var hShellProcess = Win32.WinAPI.OpenProcess(Constants.SecurityFlags.QueryInformation, false, shellProcessId);
            if (hShellProcess == IntPtr.Zero)
            {
                int errorCode = Marshal.GetLastWin32Error();
                Win32.Win32ErrorManager.ThrowDetailedWindowsError("Failed to open desktop shell process", errorCode);
            }

            var hShellToken = IntPtr.Zero;
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

            if (!Win32.WinAPI.DuplicateTokenEx(hShellToken, tokenAccess, IntPtr.Zero, Constants.SecurityFlags.ImpersonationSecurity, Constants.TokenPrivileges.AssignPrimary, out hToken))
            {
                int errorCode = Marshal.GetLastWin32Error();
                Win32.Win32ErrorManager.ThrowDetailedWindowsError("Failed to duplicate token for new unprivileged process", errorCode);
            }

            var startInfo = new Win32.WinAPI.STARTUPINFO();
            startInfo.cb = Marshal.SizeOf(startInfo);
            var processInfo = new Win32.WinAPI.PROCESS_INFORMATION();

            string commandLine = $"{executablePath} {arguments}";
            if (!Win32.WinAPI.CreateProcessWithTokenW(hToken, Constants.SecurityFlags.LogonFlags, null, commandLine, Constants.SecurityFlags.CreationFlags, IntPtr.Zero, tempWorkingDirectory, ref startInfo, out processInfo))
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