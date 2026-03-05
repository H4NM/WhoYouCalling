
using System.Net;
using System.Runtime.InteropServices;
using System.Text;

namespace WhoYouCalling.Win32
{
    public static class WinAPI
    {
        [DllImport("C:\\Windows\\System32\\user32.dll", SetLastError = true)]
        public static extern IntPtr GetShellWindow();

        [DllImport("C:\\Windows\\System32\\user32.dll", SetLastError = true)]
        public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);

        [DllImport("C:\\Windows\\System32\\kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("C:\\Windows\\System32\\kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);

        [DllImport("C:\\Windows\\System32\\kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("C:\\Windows\\System32\\kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("C:\\Windows\\System32\\advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

        [DllImport("C:\\Windows\\System32\\advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("C:\\Windows\\System32\\advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("C:\\Windows\\System32\\advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

        [DllImport("C:\\Windows\\System32\\advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, 
                                                          uint dwLogonFlags, 
                                                          string? lpApplicationName, 
                                                          string lpCommandLine, 
                                                          uint dwCreationFlags, 
                                                          IntPtr lpEnvironment, 
                                                          string lpCurrentDirectory, 
                                                          ref STARTUPINFO lpStartupInfo, 
                                                          out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("C:\\Windows\\System32\\iphlpapi.dll", SetLastError = true)]
        public static extern uint GetExtendedTcpTable(IntPtr pTcpTable,
                                                      ref int dwOutBufLen,
                                                      bool sort,
                                                      int ipVersion,
                                                      TCP_TABLE_CLASS tblClass,
                                                      uint reserved = 0);





        [StructLayout(LayoutKind.Sequential)]
        struct MIB_TCPROW_OWNER_PID
        {
            public uint state;
            public uint localAddr;
            public uint localPort;
            public uint remoteAddr;
            public uint remotePort;
            public int owningPid;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MIB_TCP6ROW_OWNER_PID
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] localAddr;      

            public uint localScopeId;    
            public uint localPort;  

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] remoteAddr;   

            public uint remoteScopeId; 
            public uint remotePort;    

            public uint state;
            public int owningPid;
        }


        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb; 
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public uint PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        public static bool HasShellWindow()
        {
            var shellWnd = GetShellWindow();
            return shellWnd != IntPtr.Zero;
        }


        public static void AddEstablishedConnectionsToMonitoring(AF_INET AF_INET, int specificPID = 0)
        {
            int bufferSize = 0;
            Win32.WinAPI.GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, (int)AF_INET,
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);

            IntPtr tcpTablePtr = Marshal.AllocHGlobal(bufferSize);

            try
            {
                uint result = GetExtendedTcpTable(tcpTablePtr,
                                                  ref bufferSize, 
                                                  true,
                                                  (int)AF_INET,
                                                  TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL);

                if (result != 0)
                    return;

                int rowStructSize;
                uint state;

                if (AF_INET == AF_INET.IPv4)
                    rowStructSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                else
                    rowStructSize = Marshal.SizeOf(typeof(MIB_TCP6ROW_OWNER_PID));

                IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4);

                int numEntries = Marshal.ReadInt32(tcpTablePtr);

                for (int i = 0; i < numEntries; i++)
                {
                    string sourceIP = "";
                    int sourcePort = 0;
                    string destIP = "";
                    int destPort = 0;

                    int pid = 0;

                    Network.IPVersion ipVersion = Network.IPVersion.IPv4;

                    if (AF_INET == AF_INET.IPv4)
                    {
                        var tcpRow = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);

                        sourceIP = new IPAddress(tcpRow.localAddr).ToString();
                        sourcePort = (ushort)IPAddress.NetworkToHostOrder((short)tcpRow.localPort);

                        destIP = new IPAddress(tcpRow.remoteAddr).ToString();
                        destPort = (ushort)IPAddress.NetworkToHostOrder((short)tcpRow.remotePort);

                        pid = tcpRow.owningPid;
                        state = tcpRow.state;
                    }
                    else
                    {
                        ipVersion = Network.IPVersion.IPv6;
                        var tcpRow = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);

                        sourceIP = new IPAddress(tcpRow.localAddr, tcpRow.localScopeId).ToString();
                        sourcePort = (ushort)IPAddress.NetworkToHostOrder((short)tcpRow.localPort);

                        destIP = new IPAddress(tcpRow.remoteAddr, tcpRow.remoteScopeId).ToString();
                        destPort = (ushort)IPAddress.NetworkToHostOrder((short)tcpRow.remotePort);
                        pid = tcpRow.owningPid;
                        state = tcpRow.state;
                    }

                    rowPtr = IntPtr.Add(rowPtr, rowStructSize);

                    // If not active TCP connections
                    if (state != TcpConnectionsFlags.ESTABLISHED_STATE)
                    {
                        continue;
                    }

                    // If specific PID has been provided and the iterated PID is not equal to the specified one. Applicable for when PID is main mode
                    if (specificPID != 0 && pid != specificPID)
                    {
                        continue ;
                    }

                    // If monitor everything but neglect localhost traffic
                    if (!Program.IncludeLoopbackWhenMonitoringEverything() && Network.NetworkUtils.IsLocalhostIP(destIP))
                    {
                        continue;
                    }

                    if (!Program.IsMonitoredProcess(pid: pid))
                    {
                        Program.AddProcessToMonitor(pid: pid);
                    }

                    Program.AddConnectionRecordToMonitoredProcess(pid: pid,
                                                                  ipVersion: ipVersion,
                                                                  transportProto: Network.TransportProtocol.TCP,
                                                                  sourceIP: sourceIP,
                                                                  sourcePort: sourcePort,
                                                                  destIP: destIP,
                                                                  destPort: destPort);

                }
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTablePtr);
            }
        }
    }
}
