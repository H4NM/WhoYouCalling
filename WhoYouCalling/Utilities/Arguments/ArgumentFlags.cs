
namespace WhoYouCalling.Utilities.Arguments
{
    internal class ArgumentFlags
    {
        /*TO DO */
        public const string ExecutableFlagShort = "-E";
        public const string ExecutableFlagLong = "--executable";

        public const string ExecutableArgsFlagShort = "-a";
        public const string ExecutableArgsFlagLong = "--arguments";

        public const string ExecutePrivilegedFlagShort = "-r";
        public const string ExecutePrivilegedFlagLong = "--privileged";

        public const string UserNameFlagShort = "-u";
        public const string UserNameFlagLong = "--user";

        public const string UserPasswordFlagShort = "-p";
        public const string UserPasswordFlagLong = "--password";

        public const string ProcessIDFlagShort = "-P";
        public const string ProcessIDFlagLong = "--pid";

        public const string MonitorEverythingFlagShort = "-M";
        public const string MonitorEverythingFlagLong = "--machine";

        public const string MonitorEverythingWithLoopbackFlagShort = "-l";
        public const string MonitorEverythingWithLoopbackFlagLong = "--localhost";

        public const string MonitorEverythingWithProcessStartFlagShort = "-F";
        public const string MonitorEverythingWithProcessStartFlagLong = "--started";

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
Usage: wyc.exe {MonitorEverythingFlagShort}/{ExecutableFlagShort }/{ProcessIDFlagShort} [options]
Main modes with additions:
  {MonitorEverythingFlagShort}, {MonitorEverythingFlagLong}         : Monitors all outgoing TCPIP activity.  
    {MonitorEverythingWithLoopbackFlagShort}, {MonitorEverythingWithLoopbackFlagLong}     : Record loopback traffic.
    {MonitorEverythingWithProcessStartFlagShort}, {MonitorEverythingWithProcessStartFlagLong}       : Record and started processes even if they don't have TCPIP activity.
  {ExecutableFlagShort}, {ExecutableFlagLong}      : Executes the specified executable which is in a non-privileged context.
    {ExecutableArgsFlagShort}, {ExecutableArgsFlagLong}     : Appends arguments contained within quotes to the executable file.
    {ExecutePrivilegedFlagShort}, {ExecutePrivilegedFlagLong}    : Executes the specified executable in a privileged context. 
    {KillChildProcessesFlagShort}, {KillChildProcessesFlagLong} : Kills the main process and registered child processes on monitoring exit. 
    {UserNameFlagShort}, {UserNameFlagLong}          : The user that the process should run as.
    {UserPasswordFlagShort}, {UserPasswordFlagLong}      : The password for the specified user.
  {ProcessIDFlagShort}, {ProcessIDFlagLong}             : Monitors the process with the provided PID.

Monitoring:
  {TimerFlagShort}, {TimerFlagLong}           : The number of seconds to monitor.

FPC:
  {InterfaceFlagShort}, {InterfaceFlagLong}       : The network interface number. Retrievable with the {GetInterfacesFlagShort}/{GetInterfacesFlagLong} flag.
  {GetInterfacesFlagShort}, {GetInterfacesFlagLong}   : Prints the network interface devices with corresponding number (usually 0-10).

Output:
  {StrictFilterFlagShort}, {StrictFilterFlagLong}    : Only generate a BPF filter based of traffic sent from the process. 
  {SaveFullPcapFlagShort}, {SaveFullPcapFlagLong}    : Does not delete the full pcap thats not filtered.
  {OutputFolderFlagShort}, {OutputFolderFlagLong}          : Output directory, full path.
  {OutputBPFFlagShort}, {OutputBPFFlagLong}       : Write the applied BPF-filter to text file.
  {OutputDFLFlagShort}, {OutputDFLFlagLong}       : Write the equivalent Wireshark Display Filter to text file. 
  {CompressFlagShort}, {CompressFlagLong}        : Compress the output folder to a .zip file.  
  {HelpFlagShort}, {HelpFlagLong}            : Displays this help information.

Examples:
  wyc.exe {ExecutableFlagShort} C:\Windows\System32\cmd.exe -t 10.5 -k -i 8 -o C:\Users\H4NM\Desktop 
  wyc.exe {ProcessIDFlagLong} 4351 {OutputDFLFlagLong} {OutputFolderFlagLong} C:\Windows\Temp 
  wyc.exe {MonitorEverythingFlagLong} 
";
        }
    }
}
