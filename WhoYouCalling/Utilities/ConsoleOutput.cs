using WhoYouCalling.Utilities.Arguments;

namespace WhoYouCalling.Utilities
{
    internal static class ConsoleOutput
    {
        public static void Print(string message, PrintType type = PrintType.Info)
        {
            string prefix;
            switch (type)
            {
                case PrintType.Info:
                    if (Program.Debug())
                    {
                        return;
                    }
                    prefix = "[*]";
                    break;
                case PrintType.InfoTime:
                    string currentTimestamp = Generic.GetTimestampNow(); 
                    prefix = $"[{currentTimestamp}]";
                    break;
                case PrintType.RunningMetrics:
                    if (Program.Debug())
                    {
                        return;
                    }
                    prefix = "\r[~]";
                    Console.Write($"{prefix} {message}");
                    return;
                case PrintType.NetworkInterface:
                    prefix = "";
                    break;
                case PrintType.Warning:
                    prefix = "[!]";
                    break;
                case PrintType.Error:
                    prefix = "[?]";
                    break;
                case PrintType.Fatal:
                    prefix = "[!!!]";
                    break;
                case PrintType.Debug:
                    if (Program.Debug())
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

        public static void PrintMetrics()
        {
            int packetCount = Program.GetLivePacketCount();
            int etwActivities = Program.GetETWActivityCount();
            int dnsActivities = Program.GetDNSActivityCount();
            int processCount = Program.GetProcessesCount();
            Print($"Processes: {processCount}. ETW Events: {etwActivities}. DNS Queries: {dnsActivities}. Network Packets: {packetCount}", PrintType.RunningMetrics);
        }
        public static void PrintStartMonitoringText()
        {
            Console.Clear();
            PrintHeader();
            Print($"Starting.. Press CTRL+C to cancel process monitoring.", PrintType.InfoTime);
        }

        public static void PrintArgumentValues(ArgumentData argumentData)
        {
            Print("=== Arguments ===", PrintType.Debug);
            Generic.PrintObjectProperties(argumentData);      
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

By Hannes Michel (@H4NM)
";
            ConsoleColor initialForeground = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.Write(headerText);
            Console.ForegroundColor = initialForeground;
        }

        public static void PrintHelp()
        {
            string helpText = ArgumentFlags.GetHelpText();
            Console.WriteLine(helpText);
        }
    }
}
