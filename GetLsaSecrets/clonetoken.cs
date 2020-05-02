using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace utilities
{
    static class CloneToken
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        public const int SE_PRIVILEGE_ENABLED = 0x00000002;
        public const int TOKEN_QUERY = 0x00000008;
        public const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;

        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const UInt32 TOKEN_DUPLICATE = 0x0002;
        public const UInt32 TOKEN_IMPERSONATE = 0x0004;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
          TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
          TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
          TOKEN_ADJUST_SESSIONID);

        public const string SE_TIME_ZONE_NAMETEXT = "SeTimeZonePrivilege";
        public const int ANYSIZE_ARRAY = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public UInt32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = ANYSIZE_ARRAY)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public extern static bool DuplicateToken(IntPtr ExistingTokenHandle, int
            SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);


        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetThreadToken(
          IntPtr PHThread,
          IntPtr Token
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr ProcessHandle,
           UInt32 DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

        [DllImport("kernel32.dll", ExactSpelling = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
         ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

        public static void DuplicateToken(string processName)
        {
            long luid = 0;

            TokPriv1Luid tokPriv1Luid = new TokPriv1Luid()
            {
                Count = 1,
                Luid = luid,
                Attr = SE_PRIVILEGE_ENABLED

            };

            bool retVal = LookupPrivilegeValue(null, "SeDebugPrivilege", ref tokPriv1Luid.Luid);
            if (!retVal)
            {
                throw new Exception("LookupPrivilegeValue: " + Marshal.GetLastWin32Error());
            }

            retVal = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, out IntPtr htoken);

            if (!retVal)
            {
                throw new Exception("OpenProcessToken: " + Marshal.GetLastWin32Error());
            }

            retVal = AdjustTokenPrivileges(htoken, false, ref tokPriv1Luid, 0, IntPtr.Zero, IntPtr.Zero);

            if (!retVal)
            {
                throw new Exception("AdjustTokenPrivileges: " + Marshal.GetLastWin32Error());
            }

            Process myProc = Process.GetProcessesByName(processName)[0];
            retVal = OpenProcessToken(myProc.Handle, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, out IntPtr hlsasstoken);

            if (!retVal)
            {
                throw new Exception("OpenProcessToken: " + Marshal.GetLastWin32Error() + " for " + myProc);
            }
            else
            {
                Console.WriteLine("PID: " + myProc.Id + " Name: " + myProc.ProcessName);

            }

            retVal = DuplicateToken(hlsasstoken, 2, out IntPtr dulicateTokenHandle);

            if (!retVal)
            {
                throw new Exception("DuplicateToken: " + Marshal.GetLastWin32Error());
            }

            retVal = SetThreadToken(IntPtr.Zero, dulicateTokenHandle);

            if (!retVal)
            {
                throw new Exception("SetThreadToken: " + Marshal.GetLastWin32Error());
            }
        }
    }
}

