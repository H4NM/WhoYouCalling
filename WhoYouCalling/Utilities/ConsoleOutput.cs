using System;

namespace WhoYouCalling.Utilities
{
    internal static class ConsoleOutput
    {
        public static void Print(string message, string type = "")
        {
            string prefix;
            switch (type)
            {
                case "info":
                    if (Program.Debug)
                    {
                        return;
                    }
                    prefix = "[*]";
                    break;
                case "infoTime":
                    string currentTimestamp = Generic.GetTimestampNow();
                    prefix = $"[{currentTimestamp}]";
                    break;
                case "runningStats":
                    if (Program.Debug)
                    {
                        return;
                    }
                    prefix = "\r[~]";
                    Console.Write($"{prefix} {message}");
                    return;
                case "warning":
                    prefix = "[!]";
                    break;
                case "error":
                    prefix = "[?]";
                    break;
                case "fatal":
                    prefix = "[!!!]";
                    break;
                case "debug":
                    if (Program.Debug)
                    {
                        prefix = $"[DEBUG]";
                    }
                    else
                    {
                        return;
                    }
                    break;
                default:
                    prefix = "";
                    break;
            }
            Console.WriteLine($"{prefix} {message}");
        }
        public static void PrintHeader()
        {
            string headerText = @" 
                                                                   ?
                                                                   | 
  __      ___      __   __         ___      _ _ _              .===:
  \ \    / / |_  __\ \ / /__ _  _ / __|__ _| | (_)_ _  __ _    |[_]|
   \ \/\/ /| ' \/ _ \ V / _ \ || | (__/ _` | | | | ' \/ _` |   |:::|
    \_/\_/ |_||_\___/|_|\___/\_,_|\___\__,_|_|_|_|_||_\__, |   |:::|
                                                      |___/     \___\
";
            ConsoleColor initialForeground = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(headerText);
            Console.ForegroundColor = initialForeground;
        }

        public static void PrintHelp()
        {
            string helpText = @"
Usage: WhoYouCalling.exe [options]
Options:
  -e, --executable    : Executes the specified executable in a non-privileged context.
  -a, --arguments     : Appends arguments contained within quotes to the executable file.
  -c, --nochildprocs  : Only monitors and tracks the main PID that's executed or running.
  -s, --savefullpcap  : Does not delete the full pcap thats not filtered.
  -p, --pid           : The running process id to track rather than executing the binary.
  -t, --timer         : The number of seconds the execute binary will run for. Is a double variable so can take floating-point values.
  -k, --killprocesses : Used in conjunction with the timer in which the main process is killed. 
                        If full tracking flag is set, childprocesses are also killed.
  -i, --interface     : The network interface number. Retrievable with the -g/--getinterfaces flag.
  -g, --getinterfaces : Prints the network interface devices with corresponding number (usually 0-10).
  -S, --strictbpf     : Only generates a BPF filter based of recorded traffic that was sent by processes. 
                        This excludes received traffic in the .pcap files.
  -n, --nopcap        : Skips collecting full packet capture.
  -o, --output        : Output directory, full path.
  -j, --json          : If the process information should be dumped to json file.
  -B, --outputbpf     : Write the applied BPF-filter to text file.
  -D, --outputdfl     : Write the equivalent Wireshark Display Filter to text file.
  -h, --help          : Displays this help information.

Examples:
  WhoYouCalling.exe -e C:\Windows\System32\calc.exe -f -t 10.5 -k -i 8 -o C:\Users\H4NM\Desktop 
  WhoYouCalling.exe --pid 4351 --nopcap --fulltracking --output C:\Windows\Temp 
";
            Console.WriteLine(helpText);
        }
    }
}
