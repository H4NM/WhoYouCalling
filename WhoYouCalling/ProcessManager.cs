using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace WhoYouCalling.Utilities
{ 
    public static class ProcessManager
    {

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);


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

        public static string GetProcessFileName(int pid)
        {
            try
            {
                Process process = Process.GetProcessById(pid);
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
                ConsoleOutput.Print($"Error when retrieving executable filename from PID: {ex.Message}", "error");
            }
            string defaultExecName = "NOTAPPLICABLE";
            ConsoleOutput.Print($"Unable to retrieve executable filename from PID. Setting default name {defaultExecName}", "warning");
            return defaultExecName;

        }

        /*
                 public static string GetProcessFileName(int PID)
        {
            try
            {
                Process runningProcess = Process.GetProcessById(PID);
                return Path.GetFileName(runningProcess.MainModule.FileName);
            }
            catch (Exception ex)
            {
                ConsoleOutput.Print($"Failed to read executable name of PID {PID}: {ex.Message}. The process", "warning");
                return "UNRETRIEVABLE_FILENAME";
            }
            
        }
         */

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