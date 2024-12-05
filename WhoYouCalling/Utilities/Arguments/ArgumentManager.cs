using System.Globalization;
using WhoYouCalling.Network.FPC;

namespace WhoYouCalling.Utilities.Arguments
{
    internal class ArgumentManager
    {
        public ArgumentData ParseArguments(string[] args)
        {
            ArgumentData argumentData = new ArgumentData(); 

            // Check if no args are provided
            if (args.Length > 0)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i] == ArgumentFlags.ExecutableFlagShort || args[i] == ArgumentFlags.ExecutableFlagLong)
                    {
                        // Ensure there's a subsequent argument that represents the executable
                        if (i + 1 < args.Length)
                        {
                            argumentData.ExecutablePath = args[i + 1];
                            argumentData.ExecutableFlagSet = true;
                        }
                        else
                        {
                            ConsoleOutput.Print($"No arguments specified after {ArgumentFlags.ExecutableFlagShort}/{ArgumentFlags.ExecutableFlagLong} flag", PrintType.Warning);
                        }
                    }
                    else if (args[i] == ArgumentFlags.MultipleNamePatternFlagShort || args[i] == ArgumentFlags.MultipleNamePatternFlagLong) 
                    {
                        // Ensure there's a subsequent argument that represents the executable
                        if (i + 1 < args.Length)
                        {
                            string namePatternsProvided = args[i + 1];
                            List<string> namePatternsParsed = new List<string>();

                            if (namePatternsProvided.Contains(","))
                            {
                                ConsoleOutput.Print($"Multiple additional executable file names to monitor: {namePatternsProvided}", PrintType.Warning);
                                namePatternsParsed.AddRange(namePatternsProvided.Split(","));
                            }
                            else
                            {
                                ConsoleOutput.Print($"One additional executable file name to monitor: {namePatternsProvided}", PrintType.Warning);
                                namePatternsParsed.Add(namePatternsProvided);
                            }
                            argumentData.ProcessesNamesToMonitor = namePatternsParsed;
                            argumentData.ProcessesesNamesToMonitorFlagSet = true;
                        }
                        else
                        {
                            ConsoleOutput.Print($"No arguments specified after {ArgumentFlags.MultipleNamePatternFlagShort}/{ArgumentFlags.MultipleNamePatternFlagLong} flag", PrintType.Warning);
                        }
                    }
                    else if (args[i] == ArgumentFlags.ExecutableArgsFlagShort || args[i] == ArgumentFlags.ExecutableArgsFlagLong) 
                    {
                        if (i + 1 < args.Length)
                        {
                            argumentData.ExecutableArguments = args[i + 1];
                            argumentData.ExecutableArgsFlagSet = true;
                        }
                        else
                        {
                            ConsoleOutput.Print($"No arguments specified after {ArgumentFlags.ExecutableArgsFlagShort}/{ArgumentFlags.ExecutableArgsFlagLong} flag", PrintType.Warning);
                            argumentData.InvalidArgumentValueProvided = true;
                            return argumentData;
                        }
                    }
                    else if (args[i] == ArgumentFlags.UserNameFlagShort || args[i] == ArgumentFlags.UserNameFlagLong) 
                    {
                        if (i + 1 < args.Length)
                        {
                            argumentData.UserName = args[i + 1];
                            argumentData.UserNameFlagSet = true;
                        }
                        else
                        {
                            ConsoleOutput.Print($"No arguments specified after {ArgumentFlags.UserNameFlagShort}/{ArgumentFlags.UserNameFlagLong} flag", PrintType.Warning);
                            argumentData.InvalidArgumentValueProvided = true;
                            return argumentData;
                        }
                    }
                    else if (args[i] == ArgumentFlags.UserPasswordFlagShort || args[i] == ArgumentFlags.UserPasswordFlagLong)
                    {
                        if (i + 1 < args.Length)
                        {
                            argumentData.UserPassword = args[i + 1];
                            argumentData.UserPasswordFlagSet = true;
                        }
                        else
                        {
                            ConsoleOutput.Print($"No arguments specified after {ArgumentFlags.UserPasswordFlagShort}/{ArgumentFlags.UserPasswordFlagLong} flag", PrintType.Warning);
                            argumentData.InvalidArgumentValueProvided = true;
                            return argumentData;
                        }
                    }
                    else if (args[i] == ArgumentFlags.MonitorEverythingFlagShort || args[i] == ArgumentFlags.MonitorEverythingFlagLong) 
                    {
                        argumentData.MonitorEverythingFlagSet = true;
                    }
                    else if (args[i] == ArgumentFlags.ExecutePrivilegedFlagShort || args[i] == ArgumentFlags.ExecutePrivilegedFlagLong)
                    {
                        argumentData.RunExecutableWithHighPrivilege = true;
                    }
                    else if (args[i] == ArgumentFlags.StrictFilterFlagShort || args[i] == ArgumentFlags.StrictFilterFlagLong)
                    {
                        argumentData.StrictCommunicationEnabled = true;
                    }
                    else if (args[i] == ArgumentFlags.OutputBPFFlagShort || args[i] == ArgumentFlags.OutputBPFFlagLong)
                    {
                        argumentData.OutputBPFFilter = true;
                    }
                    else if (args[i] == ArgumentFlags.OutputDFLFlagShort || args[i] == ArgumentFlags.OutputDFLFlagLong)
                    {
                        argumentData.OutputWiresharkFilter = true;
                    }
                    else if (args[i] == ArgumentFlags.KillChildProcessesFlagShort || args[i] == ArgumentFlags.KillChildProcessesFlagLong) 
                    {
                        argumentData.KillProcesses = true;
                        argumentData.KillProcessesFlagSet = true;
                    }
                    else if (args[i] == ArgumentFlags.SaveFullPcapFlagShort || args[i] == ArgumentFlags.SaveFullPcapFlagLong)
                    {
                        argumentData.SaveFullPcap = true;
                    }
                    else if (args[i] == ArgumentFlags.OutputJSONFlagShort || args[i] == ArgumentFlags.OutputJSONFlagLong) 
                    {
                        argumentData.DumpResultsToJson = true;
                    }
                    else if (args[i] == ArgumentFlags.OutputFolderFlagShort || args[i] == ArgumentFlags.OutputFolderFlagLong) 
                    {
                        if (i + 1 < args.Length)
                        {
                            string path = args[i + 1];

                            if (Path.IsPathRooted(path) && Directory.Exists(path))
                            {
                                if (path.Substring(path.Length - 1) == @"\")
                                {
                                    argumentData.OutputDirectory = path;
                                }
                                else
                                {
                                    argumentData.OutputDirectory = path + @"\";
                                }
                                argumentData.OutputDirectoryFlagSet = true;
                            }
                            else
                            {
                                ConsoleOutput.Print("Provide full path to an existing catalog.", PrintType.Warning);
                                argumentData.InvalidArgumentValueProvided = true;
                                return argumentData;
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print($"No arguments specified after {ArgumentFlags.OutputFolderFlagShort}/{ArgumentFlags.OutputFolderFlagLong} flag", PrintType.Warning);
                            argumentData.InvalidArgumentValueProvided = true;
                            return argumentData;
                        }

                    }
                    else if (args[i] == ArgumentFlags.NoPcapFlagShort || args[i] == ArgumentFlags.NoPcapFlagLong) 
                    {
                        argumentData.NoPacketCapture = true;
                        argumentData.NoPCAPFlagSet = true;
                    }
                    else if (args[i] == ArgumentFlags.ProcessIDFlagShort || args[i] == ArgumentFlags.ProcessIDFlagLong) 
                    {
                        if (i + 1 < args.Length)
                        {
                            if (int.TryParse(args[i + 1], out int trackedProcessId))
                            {
                                argumentData.TrackedProcessId = trackedProcessId;
                                argumentData.PIDFlagSet = true;
                            }
                            else
                            {
                                ConsoleOutput.Print($"The provided value for PID ({trackedProcessId}) is not a valid integer", PrintType.Warning);
                                argumentData.InvalidArgumentValueProvided = true;
                                return argumentData;
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print($"No arguments specified after {ArgumentFlags.ProcessIDFlagShort}/{ArgumentFlags.ProcessIDFlagLong} flag", PrintType.Warning);
                            argumentData.InvalidArgumentValueProvided = true;
                            return argumentData;
                        }
                    }
                    else if (args[i] == ArgumentFlags.TimerFlagShort || args[i] == ArgumentFlags.TimerFlagLong)
                    {
                        if (i + 1 < args.Length)
                        {
                            if (double.TryParse(args[i + 1], NumberStyles.Any, CultureInfo.InvariantCulture, out double processRunTimer))
                            {
                                argumentData.ProcessRunTimer = processRunTimer;
                                argumentData.ProcessRunTimerFlagSet = true;
                            }
                            else
                            {
                                ConsoleOutput.Print($"The provided value for timer ({processRunTimer}) is not a valid double", PrintType.Warning);
                                argumentData.InvalidArgumentValueProvided = true;
                                return argumentData;
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print($"No arguments specified after {ArgumentFlags.TimerFlagShort}/{ArgumentFlags.TimerFlagLong} flag", PrintType.Warning);
                            argumentData.InvalidArgumentValueProvided = true;
                            return argumentData;
                        }
                    }
                    else if (args[i] == ArgumentFlags.InterfaceFlagShort || args[i] == ArgumentFlags.InterfaceFlagLong) 
                    {
                        if (!NetworkCaptureManagement.NpcapDriverExists())
                        {
                            ConsoleOutput.Print("Npcap does not seem to be installed. It's required to capture network packets", PrintType.Warning);
                            Environment.Exit(1);
                        }

                        if (i + 1 < args.Length)
                        {
                            if (int.TryParse(args[i + 1], out int networkInterfaceChoice))
                            {
                                argumentData.NetworkInterfaceChoice = networkInterfaceChoice;
                                argumentData.NetworkInterfaceDeviceFlagSet = true;
                            }
                            else
                            {
                                ConsoleOutput.Print($"The provided value for network device ({networkInterfaceChoice}) is not a valid integer", PrintType.Warning);
                                argumentData.InvalidArgumentValueProvided = true;
                                return argumentData;
                            }
                        }
                        else
                        {
                            ConsoleOutput.Print($"No arguments specified after {ArgumentFlags.InterfaceFlagShort}/{ArgumentFlags.InterfaceFlagLong} flag", PrintType.Warning);
                            argumentData.InvalidArgumentValueProvided = true;
                            return argumentData;
                        }
                    }
                    else if (args[i] == ArgumentFlags.GetInterfacesFlagShort || args[i] == ArgumentFlags.GetInterfacesFlagLong)
                    {
                        if (NetworkCaptureManagement.NpcapDriverExists())
                        {
                            NetworkCaptureManagement.PrintNetworkInterfaces();
                        }
                        else
                        {
                            ConsoleOutput.Print("Npcap does not seem to be installed. It's required to capture network packets", PrintType.Warning);
                        }
                        Environment.Exit(1);
                    }
                    else if (args[i] == ArgumentFlags.DebugFlagShort || args[i] == ArgumentFlags.DebugFlagLong) 
                    {
                        argumentData.Debug = true;
                    }
                    else if (args[i] == ArgumentFlags.HelpFlagShort || args[i] == ArgumentFlags.HelpFlagLong) 
                    {
                        ConsoleOutput.PrintHelp();
                        Environment.Exit(1);
                    }
                }
            }
            else
            {
                argumentData.InvalidArgumentValueProvided = true;
                return argumentData;
            }

            return argumentData;
        }

        public bool IsValidCombinationOfArguments(ArgumentData argumentData)
        {
            if ((argumentData.ExecutableFlagSet && argumentData.PIDFlagSet) && !argumentData.MonitorEverythingFlagSet) 
            {
                ConsoleOutput.Print($"Only one of {ArgumentFlags.ExecutableFlagShort} ({ArgumentFlags.ExecutableFlagLong}) and {ArgumentFlags.ProcessIDFlagShort} ({ArgumentFlags.ProcessIDFlagLong}) can be supplied, not both", PrintType.Error);
                return false;
            }
            if ((!argumentData.ExecutableFlagSet && !argumentData.PIDFlagSet) && !argumentData.MonitorEverythingFlagSet)
            {
                ConsoleOutput.Print($"You need to either supply {ArgumentFlags.ExecutableFlagShort} ({ArgumentFlags.ExecutableFlagLong}) or {ArgumentFlags.ProcessIDFlagShort} ({ArgumentFlags.ProcessIDFlagLong}) or {ArgumentFlags.MonitorEverythingFlagShort} ({ArgumentFlags.MonitorEverythingFlagLong})", PrintType.Error);
                return false;
            }
            else if (argumentData.ExecutableArgsFlagSet && !argumentData.ExecutableFlagSet)
            {
                ConsoleOutput.Print($"You need to use {ArgumentFlags.ExecutableFlagShort}/{ArgumentFlags.ExecutableFlagLong} and specify an executable when providing with arguments with {ArgumentFlags.ExecutableArgsFlagShort}/{ArgumentFlags.ExecutableArgsFlagLong}", PrintType.Error);
                return false;
            }
            else if (argumentData.KillProcessesFlagSet && argumentData.PIDFlagSet)
            {
                ConsoleOutput.Print($"You can only specify {ArgumentFlags.KillChildProcessesFlagShort}/{ArgumentFlags.KillChildProcessesFlagLong} for killing process that's been started, and not via listening to a running process", PrintType.Error);
                return false;
            }
            else if (argumentData.NetworkInterfaceDeviceFlagSet == argumentData.NoPCAPFlagSet)
            {
                ConsoleOutput.Print($"You need to specify a network device interface or specify {ArgumentFlags.NoPcapFlagShort}/{ArgumentFlags.NoPcapFlagLong} to skip packet capture. Run again with {ArgumentFlags.GetInterfacesFlagShort}/{ArgumentFlags.GetInterfacesFlagLong} to view available network devices", PrintType.Error);
                return false;
            }
            else if (argumentData.UserNameFlagSet != argumentData.UserPasswordFlagSet)
            {
                ConsoleOutput.Print("You need to specify a username for a password and vice versa", PrintType.Error);
                return false;
            }
            else if (argumentData.RunExecutableWithHighPrivilege && !argumentData.ExecutableFlagSet)
            {
                ConsoleOutput.Print("You need to provide an executable path when using the elevated flag", PrintType.Error);
                return false;
            }
            else if ((argumentData.UserNameFlagSet && argumentData.UserPasswordFlagSet) && argumentData.RunExecutableWithHighPrivilege)
            {
                ConsoleOutput.Print("You can't execute applications elevated with provided username and password in this version. Sign in with the user and execute it with the elevated flag", PrintType.Error);
                return false;
            }
            else if (!argumentData.RunExecutableWithHighPrivilege && 
                     (!argumentData.UserNameFlagSet && !argumentData.UserPasswordFlagSet) &&
                     !Win32.WinAPI.HasShellWindow())
            {
                ConsoleOutput.Print("You need to specify a username and password when running unprivileged from an uninteractive session. Provide local account details or run as privileged or get desktop access", PrintType.Error);
                return false;
            }
            return true;
        }
    }
}
