
namespace WhoYouCalling.Utilities.Arguments
{
    internal class ArgumentFlags
    {
        /*TO DO */
        public const string ExecutableFlagShort = "-e";
        public const string ExecutableFlagLong = "--executable";

        public const string ExecutableArgsFlagShort = "-a";
        public const string ExecutableArgsFlagLong = "--arguments";

        public const string ExecutePrivilegedFlagShort = "-R";
        public const string ExecutePrivilegedFlagLong = "--privileged";

        public const string UserNameFlagShort = "-u";
        public const string UserNameFlagLong = "--user";

        public const string UserPasswordFlagShort = "-p";
        public const string UserPasswordFlagLong = "--password";

        public const string ProcessIDFlagShort = "-P";
        public const string ProcessIDFlagLong = "--PID";

        public const string MonitorEverythingFlagShort = "-E";
        public const string MonitorEverythingFlagLong = "--everything";

        public const string InterfaceFlagShort = "-i";
        public const string InterfaceFlagLong = "--interface";

        public const string GetInterfacesFlagShort = "-g";
        public const string GetInterfacesFlagLong = "--getinterfaces";

        public const string TimerFlagShort = "-t";
        public const string TimerFlagLong = "--timer";

        public const string KillChildProcessesFlagShort = "-k";
        public const string KillChildProcessesFlagLong = "--killprocesses";

        public const string StrictFilterFlagShort = "-S";
        public const string StrictFilterFlagLong = "--strictfilter";

        public const string SaveFullPcapFlagShort = "-s";
        public const string SaveFullPcapFlagLong = "--savefullpcap";

        public const string OutputFolderFlagShort = "-o";
        public const string OutputFolderFlagLong = "--output";

        public const string OutputBPFFlagShort = "-B";
        public const string OutputBPFFlagLong = "--outputbpf";

        public const string OutputDFLFlagShort = "-D";
        public const string OutputDFLFlagLong = "--outputdfl";

        public const string BPFFilterShort = "-m";
        public const string BPFFilterLong = "--bpffilter";

        public const string BPFFilterFileShort = "-y";
        public const string BPFFilterFileLong = "--bpffilterfile";

        public const string HelpFlagShort = "-h";
        public const string HelpFlagLong = "--help";

        public const string CompressFlagShort = "-c";
        public const string CompressFlagLong = "--compress";

        public static string GetHelpText()
        {
            return $@"
Usage: wyc.exe [options]
Options:
  {ExecutableFlagShort}, {ExecutableFlagLong}    : Executes the specified executable which is in a non-privileged context
                        unless --privileged flag is provided.
  {ExecutableArgsFlagShort}, {ExecutableArgsFlagLong}     : Appends arguments contained within quotes to the executable file.
  {ExecutePrivilegedFlagShort}, {ExecutePrivilegedFlagLong}    : Executes the specified executable in a privileged context. 
                        Inherits the integrity level and access token of WhyYouCalling.exe.
  {UserNameFlagShort}, {UserNameFlagLong}          : The user that the process should run as.
  {UserPasswordFlagShort}, {UserPasswordFlagLong}      : The password for the specified user that the process should run as.
  {ProcessIDFlagShort}, {ProcessIDFlagLong}           : The running process id to track rather than executing the binary.
  {MonitorEverythingFlagShort}, {MonitorEverythingFlagLong}    : Captures everything from everything. 
                        Good for incident response or just checking what the heck your computer is doing. 
                        Can be used with pcap capture.
  {InterfaceFlagShort}, {InterfaceFlagLong}     : The network interface number. Retrievable with the {GetInterfacesFlagShort}/{GetInterfacesFlagLong} flag.
  {GetInterfacesFlagShort}, {GetInterfacesFlagLong} : Prints the network interface devices with corresponding number (usually 0-10).
  {TimerFlagShort}, {TimerFlagLong}         : The number of seconds to monitor. Is a double variable so can take floating-point values.
                        The monitoring duration may be longer when executing a binary which is due to ETW subscription timing.
  {KillChildProcessesFlagShort}, {KillChildProcessesFlagLong} : Used in conjunction with the timer in which the main process is killed. 
                        If full tracking flag is set, childprocesses are also killed.
  {StrictFilterFlagShort}, {StrictFilterFlagLong}  : Only generates a BPF filter based of recorded traffic that was sent by processes. 
                        This excludes received traffic in the .pcap files.
  {SaveFullPcapFlagShort}, {SaveFullPcapFlagLong}  : Does not delete the full pcap thats not filtered.
  {OutputFolderFlagShort}, {OutputFolderFlagLong}        : Output directory, full path.
  {OutputBPFFlagShort}, {OutputBPFFlagLong}     : Write the applied BPF-filter to text file.
  {OutputDFLFlagShort}, {OutputDFLFlagLong}     : Write the equivalent Wireshark Display Filter to text file. 
                        Useful in conjunction with --savefullpcap to filter process activity based on all traffic.
  {CompressFlagShort}, {CompressFlagLong}      : Compress the output folder to a .zip file. Only the compressed folder is kept. 
  {HelpFlagShort}, {HelpFlagLong}          : Displays this help information.

Examples:
  wyc.exe {ExecutableFlagShort} C:\Windows\System32\cmd.exe -t 10.5 -k -i 8 -o C:\Users\H4NM\Desktop 
  wyc.exe {ProcessIDFlagLong} 4351 {OutputDFLFlagLong} {OutputFolderFlagLong} C:\Windows\Temp 
  wyc.exe {MonitorEverythingFlagLong} 
";
        }
    }
}
