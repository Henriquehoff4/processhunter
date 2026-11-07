using System.Runtime.InteropServices;
using System.Text;

namespace ProcessHunter.Native;

internal static class Win32
{
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_SET_INFORMATION = 0x0200;
    public const uint PROCESS_TERMINATE = 0x0001;
    public const uint TOKEN_QUERY = 0x0008;

    [DllImport("ntdll.dll")]
    public static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORYSTATUSEX
    {
        public uint dwLength, dwMemoryLoad;
        public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX m);

    [StructLayout(LayoutKind.Sequential)]
    public struct PERFORMANCE_INFORMATION
    {
        public uint cb;
        public UIntPtr CommitTotal, CommitLimit, CommitPeak, PhysicalTotal, PhysicalAvailable, SystemCache, KernelTotal, KernelPaged, KernelNonpaged, PageSize;
        public uint HandleCount, ProcessCount, ThreadCount;
    }

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool GetPerformanceInfo(out PERFORMANCE_INFORMATION pi, uint size);

    [DllImport("kernel32.dll")] public static extern ulong GetTickCount64();

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool QueryFullProcessImageNameW(IntPtr h, uint flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll")] public static extern uint GetPriorityClass(IntPtr h);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetPriorityClass(IntPtr h, uint cls);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("kernel32.dll")] public static extern bool IsWow64Process(IntPtr h, out bool wow64);

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    public static extern bool ShellExecuteExW(ref SHELLEXECUTEINFO info);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHELLEXECUTEINFO
    {
        public int cbSize; public uint fMask; public IntPtr hwnd;
        public string lpVerb, lpFile, lpParameters, lpDirectory;
        public int nShow; public IntPtr hInstApp, lpIDList;
        public string lpClass; public IntPtr hkeyClass; public uint dwHotKey; public IntPtr hIcon, hProcess;
    }

    public static void ShowProperties(string path)
    {
        var i = new SHELLEXECUTEINFO { cbSize = Marshal.SizeOf<SHELLEXECUTEINFO>(), fMask = 0x0000000C /*INVOKEIDLIST|NOCLOSEPROCESS... */ | 0x40, lpVerb = "properties", lpFile = path, nShow = 5 };
        i.fMask = 0x0000000C;
        ShellExecuteExW(ref i);
    }
}

/// <summary>Layout de SYSTEM_PROCESS_INFORMATION (x64) - offsets documentados.</summary>
internal static class SysProcLayout
{
    public const int NextEntry = 0, NumThreads = 4, WorkingSetPrivate = 8, CreateTime = 32, UserTime = 40, KernelTime = 48,
        ImageNameLen = 56, ImageNamePtr = 64, BasePriority = 72, Pid = 80, ParentPid = 88, HandleCount = 96, SessionId = 100,
        WorkingSet = 144, PagefileUsage = 184, PrivatePage = 200, ReadOps = 208, WriteOps = 216, ReadBytes = 232, WriteBytes = 240, OtherBytes = 248;
    public const int ThreadsOffset = 256;
}

internal static class Pdh
{
    [DllImport("pdh.dll", CharSet = CharSet.Unicode)] static extern int PdhOpenQueryW(string? src, IntPtr user, out IntPtr q);
    [DllImport("pdh.dll", CharSet = CharSet.Unicode)] static extern int PdhAddEnglishCounterW(IntPtr q, string path, IntPtr user, out IntPtr c);
    [DllImport("pdh.dll")] static extern int PdhCollectQueryData(IntPtr q);
    [DllImport("pdh.dll")] static extern int PdhCloseQuery(IntPtr q);
    [DllImport("pdh.dll")] static extern int PdhGetFormattedCounterArrayW(IntPtr c, uint fmt, ref int bufSize, ref int count, IntPtr buf);

    const int PDH_MORE_DATA = unchecked((int)0x800007D2);
    const uint PDH_FMT_DOUBLE = 0x200;

    /// <summary>Consulta PDH com contadores curinga (ex.: \GPU Engine(*)\Utilization Percentage).</summary>
    public sealed class Query : IDisposable
    {
        IntPtr _q;
        readonly List<IntPtr> _counters = new();
        IntPtr _buf = Marshal.AllocHGlobal(1 << 16);
        int _bufSize = 1 << 16;
        public bool Ok => _q != IntPtr.Zero;

        public Query()
        {
            if (PdhOpenQueryW(null, IntPtr.Zero, out _q) != 0) _q = IntPtr.Zero;
        }

        /// <summary>Retorna índice do contador ou -1 se não existir neste sistema.</summary>
        public int Add(string path)
        {
            if (_q == IntPtr.Zero) return -1;
            if (PdhAddEnglishCounterW(_q, path, IntPtr.Zero, out var c) != 0) return -1;
            _counters.Add(c);
            return _counters.Count - 1;
        }

        public bool Collect() => _q != IntPtr.Zero && PdhCollectQueryData(_q) == 0;

        public List<(string Name, double Value)> Read(int idx)
        {
            var res = new List<(string, double)>();
            if (idx < 0 || idx >= _counters.Count) return res;
            int count = 0, size = _bufSize;
            int r = PdhGetFormattedCounterArrayW(_counters[idx], PDH_FMT_DOUBLE, ref size, ref count, _buf);
            if (r == PDH_MORE_DATA)
            {
                Marshal.FreeHGlobal(_buf);
                _bufSize = size + 4096;
                _buf = Marshal.AllocHGlobal(_bufSize);
                size = _bufSize;
                r = PdhGetFormattedCounterArrayW(_counters[idx], PDH_FMT_DOUBLE, ref size, ref count, _buf);
            }
            if (r != 0) return res;
            for (int i = 0; i < count; i++)
            {
                IntPtr item = _buf + i * 24;
                var name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(item)) ?? "";
                uint status = (uint)Marshal.ReadInt32(item, 8);
                if (status != 0 && status != 0x00000001) continue; // PDH_CSTATUS_VALID_DATA / NEW_DATA
                double v = BitConverter.Int64BitsToDouble(Marshal.ReadInt64(item, 16));
                res.Add((name, v));
            }
            return res;
        }

        public void Dispose()
        {
            if (_q != IntPtr.Zero) { PdhCloseQuery(_q); _q = IntPtr.Zero; }
            if (_buf != IntPtr.Zero) { Marshal.FreeHGlobal(_buf); _buf = IntPtr.Zero; }
        }
    }
}
