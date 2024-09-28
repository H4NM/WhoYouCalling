using System.Globalization;
using WhoYouCalling.Network.FPC;

namespace WhoYouCalling.Utilities.Arguments
{
    internal class ArgumentManager
    {
        public ArgumentData ParseArguments(string[] args)
        {
            ArgumentData argumentData = new ArgumentData(trackChildProcesses: true); 

            // Check if no args are provided
            if (args.Length > 0)
            {
                // Iterate args
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i] == "-e" || args[i] == "--executable") // Executable flag
                    {
                        // Ensure there's a subsequent argument that represents the executable
                        if (i + 1 < args.Length)
                        {
                            argumentData.ExecutablePath = args[i + 1];
                            argumentData.ExecutablePathProvided = true;
                            argumentData.ExecutableFlagSet = true;
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -e/--executable flag", PrintType.Warning);
                        }
                    }
                    else if (args[i] == "-x" || args[i] == "--execnames") // Executable flag
                    {
                        // Ensure there's a subsequent argument that represents the executable
                        if (i + 1 < args.Length)
                        {
                            string execNamesProvided = args[i + 1];
                            List<string> execNamesParsed = new List<string>();

                            if (execNamesProvided.Contains(","))
                            {
                                ConsoleOutput.Print($"Multiple additional executable file names to monitor: {execNamesProvided}", PrintType.Warning);
                                execNamesParsed.AddRange(execNamesProvided.Split(","));
                            }
                            else
                            {
                                ConsoleOutput.Print($"One additional executable file name to monitor: {execNamesProvided}", PrintType.Warning);
                                execNamesParsed.Add(execNamesProvided);
                            }
                            Console.WriteLine(execNamesParsed);
                            argumentData.ExecutableNamesToMonitor = execNamesParsed;
                            argumentData.ExecutableNamesToMonitorProvided = true;
                            argumentData.ExecutableNamesToMonitorFlagSet = true;

                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -e/--executable flag", PrintType.Warning);
                        }
                    }
                    else if (args[i] == "-a" || args[i] == "--arguments") // Executable arguments flag
                    {
                        if (i + 1 < args.Length)
                        {
                            argumentData.ExecutableArguments = args[i + 1];
                            argumentData.ExecutableArgsFlagSet = true;
                        }
                        else
                        {
                            ConsoleOutput.Print("No arguments specified after -a/--arguments flag", PrintType.Warning);
                            argumentData.InvalidArgumentValueProvided = true;
                            return argumentData;
                        }
                    }
                    else if (args[i] == "-c" || args[i] == "--nochildprocs") // Track the network activity by child processes
                    {
                        argumentData.TrackChildProcesses = false;
                    }
                    else if (args[i] == "-S" || args[i] == "--strictfilter")
                    {
                        argumentData.StrictCommunicationEnabled = true;
                    }
                    else if (args[i] == "-B" || args[i] == "--outputbpf")
                    {
                        argumentData.OutputBPFFilter = true;
                    }
                    else if (args[i] == "-D" || args[i] == "--outputdfl")
                    {
                        argumentData.OutputWiresharkFilter = true;
                    }
                    else if (args[i] == "-k" || args[i] == "--killprocesses") // Track the network activity by child processes
                    {
                        argumentData.KillProcesses = true;
                        argumentData.KillProcessesFlagSet = true;
                    }
                    else if (args[i] == "-s" || args[i] == "--savefullpcap") //Save the full pcap
                    {
                        argumentData.SaveFullPcap = true;
                    }
                    else if (args[i] == "-j" || args[i] == "--json") //Save the full pcap
                    {
                        argumentData.DumpResultsToJson = true;
                    }
                    else if (args[i] == "-o" || args[i] == "--output") //Save the full pcap
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
                                argumentData.ProvidedOutputDirectory = true;
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
                            ConsoleOutput.Print("No arguments specified after -o/--output flag", PrintType.Warning);
                            argumentData.InvalidArgumentValueProvided = true;
                            return argumentData;
                        }

                    }
                    else if (args[i] == "-n" || args[i] == "--nopcap") // Don't collect pcap
                    {
                        argumentData.NoPacketCapture = true;
                        argumentData.NoPCAPFlagSet = true;
                    }
                    else if (args[i] == "-p" || args[i] == "--pid") // Running process id
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
                            ConsoleOutput.Print("No arguments specified after -p/--pid flag", PrintType.Warning);
                            argumentData.InvalidArgumentValueProvided = true;
                            return argumentData;
                        }
                    }
                    else if (args[i] == "-t" || args[i] == "--timer") // Executable run timer
                    {
                        if (i + 1 < args.Length)
                        {
                            if (double.TryParse(args[i + 1], NumberStyles.Any, CultureInfo.InvariantCulture, out double processRunTimer))
                            {
                                argumentData.ProcessRunTimer = processRunTimer;
                                argumentData.ProcessRunTimerWasProvided = true;
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
                            ConsoleOutput.Print("No arguments specified after -t/--timer flag", PrintType.Warning);
                            argumentData.InvalidArgumentValueProvided = true;
                            return argumentData;
                        }
                    }
                    else if (args[i] == "-i" || args[i] == "--interface") // Network interface device flag
                    {
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
                            ConsoleOutput.Print("No arguments specified after -i/--interface flag", PrintType.Warning);
                            argumentData.InvalidArgumentValueProvided = true;
                            return argumentData;
                        }
                    }

                    else if (args[i] == "-g" || args[i] == "--getinterfaces") //Print available interfaces
                    {
                        NetworkCaptureManagement.PrintNetworkInterfaces();
                        Environment.Exit(1);
                    }
                    else if (args[i] == "-d" || args[i] == "--debug") //Save the full pcap
                    {
                        argumentData.Debug = true;
                    }
                    else if (args[i] == "-h" || args[i] == "--help") //Output help instructions
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

        public bool IsNotValidCombinationOfArguments(ArgumentData argumentData)
        {
            // Forbidden combination of flags
            if (argumentData.ExecutableFlagSet == argumentData.PIDFlagSet) //Must specify PID or executable file and not both
            {
                ConsoleOutput.Print("One of -e or -p must be supplied, and not both", PrintType.Error);
                return true;
            }
            else if (argumentData.ExecutableArgsFlagSet && !argumentData.ExecutableFlagSet)
            {
                ConsoleOutput.Print("You need to specify an executable when providing with arguments with -a", PrintType.Error);
                return true;
            }
            else if (argumentData.KillProcessesFlagSet && argumentData.PIDFlagSet)
            {
                ConsoleOutput.Print("You can only specify -k for killing process that's been started, and not via listening to a running process", PrintType.Error);
                return true;
            }
            else if (argumentData.NetworkInterfaceDeviceFlagSet == argumentData.NoPCAPFlagSet)
            {
                ConsoleOutput.Print("You need to specify a network device interface or specify -n/--nopcap to skip packet capture. Run again with -g to view available network devices", PrintType.Error);
                return true;
            }
            return false;
        }
    }
}
