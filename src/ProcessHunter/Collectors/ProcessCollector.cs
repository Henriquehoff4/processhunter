using System.Runtime.InteropServices;
using ProcessHunter.Native;
using L = ProcessHunter.Native.SysProcLayout;

namespace ProcessHunter.Collectors;

internal struct RawProc
{
    public int Pid, ParentPid, Threads, Handles, BasePriority, Session;
    public string Name;
    public long CreateTime, CpuTime;         // FILETIME / 100ns
    public long WorkingSet, Private, Commit;
    public long ReadBytes, WriteBytes, OtherBytes;
}

/// <summary>Coleta todos os processos com UMA chamada NtQuerySystemInformation (sem WMI, sem Process.GetProcesses).</summary>
internal sealed class ProcessCollector : IDisposable
{
    IntPtr _buf = Marshal.AllocHGlobal(1 << 20);
    int _size = 1 << 20;

    public bool TryCollect(List<RawProc> into)
    {
        into.Clear();
        int status;
        for (int attempt = 0; attempt < 4; attempt++)
        {
            status = Win32.NtQuerySystemInformation(5, _buf, _size, out int need);
            if (status == unchecked((int)0xC0000004) || status == unchecked((int)0xC0000023))
            {
                Marshal.FreeHGlobal(_buf);
                _size = Math.Max(need + (256 << 10), _size * 2);
                _buf = Marshal.AllocHGlobal(_size);
                continue;
            }
            if (status != 0) return false;
            Parse(_buf, into);
            return true;
        }
        return false;
    }

    internal static unsafe void Parse(IntPtr buf, List<RawProc> into)
    {
        byte* p = (byte*)buf;
        while (true)
        {
            var r = new RawProc
            {
                Threads = *(int*)(p + L.NumThreads),
                CreateTime = *(long*)(p + L.CreateTime),
                CpuTime = *(long*)(p + L.UserTime) + *(long*)(p + L.KernelTime),
                BasePriority = *(int*)(p + L.BasePriority),
                Pid = (int)*(long*)(p + L.Pid),
                ParentPid = (int)*(long*)(p + L.ParentPid),
                Handles = *(int*)(p + L.HandleCount),
                Session = *(int*)(p + L.SessionId),
                WorkingSet = *(long*)(p + L.WorkingSet),
                Commit = *(long*)(p + L.PagefileUsage),
                Private = *(long*)(p + L.PrivatePage),
                ReadBytes = *(long*)(p + L.ReadBytes),
                WriteBytes = *(long*)(p + L.WriteBytes),
                OtherBytes = *(long*)(p + L.OtherBytes),
            };
            ushort len = *(ushort*)(p + L.ImageNameLen);
            IntPtr np = *(IntPtr*)(p + L.ImageNamePtr);
            r.Name = len > 0 && np != IntPtr.Zero ? new string((char*)np, 0, len / 2) : (r.Pid == 0 ? "Ociosidade do Sistema" : "System");
            into.Add(r);
            uint next = *(uint*)(p + L.NextEntry);
            if (next == 0) break;
            p += next;
        }
    }

    public void Dispose() { if (_buf != IntPtr.Zero) { Marshal.FreeHGlobal(_buf); _buf = IntPtr.Zero; } }
}
