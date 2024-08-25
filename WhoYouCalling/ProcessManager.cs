using System.Diagnostics;

namespace WhoYouCalling.Utilities
{ 
    public static class ProcessManager
    {
        public static bool IsProcessRunning(int pid)
        {
            Process[] processList = Process.GetProcesses();
            foreach (Process activePID in processList)
            {
                if (pid == activePID.Id)
                {
                    ConsoleOutput.Print($"Provided PID ({pid}) is active on the system", "debug");
                    return true;
                }
            }
            ConsoleOutput.Print($"Unable to find process with pid {pid}", "warning");
            return false;
        }
        public static string GetProcessFileName(int PID)
        {
            Process runningProcess = Process.GetProcessById(PID);
            return Path.GetFileName(runningProcess.MainModule.FileName);
        }
        public static void KillProcess(int pid)
        {
            try
            {
                Process process = Process.GetProcessById(pid);

                if (!process.HasExited)
                {
                    ConsoleOutput.Print($"Killing the process with PID {pid}", "debug");
                    process.Kill();
                }
            }
            catch (ArgumentException)
            {
                ConsoleOutput.Print($"Process with PID {pid} has already exited.", "debug");
            }
            catch (Exception ex)
            {
                ConsoleOutput.Print($"An error occurred when stopping process when timer expired: {ex.Message}", "error");
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

                Process process = Process.Start(startInfo);

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
                ConsoleOutput.Print($"An error occurred: {ex.Message}", "error");
                throw;
            }
        }
    }
}