using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using WhoYouCalling.Utilities;

namespace WhoYouCalling.Process
{ 
    internal static class ProcessManager
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);

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
                if (QueryFullProcessImageName(process.Handle, 0, buffer, ref size))
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

        public static int StartProcessAndGetId(string executablePath, string arguments = "")
        {
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo(executablePath);

                if (!string.IsNullOrEmpty(arguments))
                {
                    startInfo.Arguments = arguments;
                }

                startInfo.UseShellExecute = true;
                startInfo.Verb = "open";

                System.Diagnostics.Process process = System.Diagnostics.Process.Start(startInfo);

                if (process != null)
                {
                    // Retrieve the PID
                    return process.Id;
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
        }
    }
}