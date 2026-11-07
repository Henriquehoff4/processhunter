using System.Runtime.InteropServices;
using System.Text;
using ProcessHunter.Core;
using ProcessHunter.Native;

namespace ProcessHunter.Collectors;

/// <summary>CPU (por núcleo), memória, disco, rede, frequência e zona térmica. Tudo via NtQuery/PDH (sem WMI).</summary>
internal sealed class SystemCollector : IDisposable
{
    readonly int _cpus = Environment.ProcessorCount;
    long[] _prevIdle, _prevTotal;
    readonly IntPtr _cpuBuf;
    readonly Pdh.Query _q = new();
    readonly int _diskR, _diskW, _diskBusy, _diskQ, _diskLat, _netRx, _netTx, _netBw, _perf, _freq, _thermal;

    public string CpuName { get; } = ReadCpuName();
    public int PhysicalCores { get; }
    public int LogicalCores => _cpus;
    public bool HasFreq => _perf >= 0 && _freq >= 0;
    public bool HasThermal => _thermal >= 0;

    public SystemCollector()
    {
        _prevIdle = new long[_cpus]; _prevTotal = new long[_cpus];
        _cpuBuf = Marshal.AllocHGlobal(_cpus * 48 + 64);
        _diskR = _q.Add(@"\PhysicalDisk(_Total)\Disk Read Bytes/sec");
        _diskW = _q.Add(@"\PhysicalDisk(_Total)\Disk Write Bytes/sec");
        _diskBusy = _q.Add(@"\PhysicalDisk(_Total)\% Disk Time");
        _diskQ = _q.Add(@"\PhysicalDisk(_Total)\Current Disk Queue Length");
        _diskLat = _q.Add(@"\PhysicalDisk(_Total)\Avg. Disk sec/Transfer");
        _netRx = _q.Add(@"\Network Interface(*)\Bytes Received/sec");
        _netTx = _q.Add(@"\Network Interface(*)\Bytes Sent/sec");
        _netBw = _q.Add(@"\Network Interface(*)\Current Bandwidth");
        _perf = _q.Add(@"\Processor Information(_Total)\% Processor Performance");
        _freq = _q.Add(@"\Processor Information(_Total)\Processor Frequency");
        _thermal = _q.Add(@"\Thermal Zone Information(*)\Temperature");
        PhysicalCores = CountPhysicalCores();
        _q.Collect();
        ReadCores(null, out _);
    }

    static string ReadCpuName()
    {
        try
        {
            using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            return (k?.GetValue("ProcessorNameString") as string)?.Trim() ?? "CPU";
        }
        catch { return "CPU"; }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetLogicalProcessorInformation(IntPtr buf, ref int len);

    static int CountPhysicalCores()
    {
        try
        {
            int len = 0;
            GetLogicalProcessorInformation(IntPtr.Zero, ref len);
            var p = Marshal.AllocHGlobal(len);
            try
            {
                if (!GetLogicalProcessorInformation(p, ref len)) return Environment.ProcessorCount;
                int n = 0;
                for (int off = 0; off + 32 <= len; off += 32)
                    if (Marshal.ReadInt32(p, off + 8) == 0) n++; // RelationProcessorCore
                return n > 0 ? n : Environment.ProcessorCount;
            }
            finally { Marshal.FreeHGlobal(p); }
        }
        catch { return Environment.ProcessorCount; }
    }

    double ReadCores(double[]? perCore, out double total)
    {
        total = 0;
        int st = Win32.NtQuerySystemInformation(8, _cpuBuf, _cpus * 48, out _);
        if (st != 0) return 0;
        long dIdleSum = 0, dTotSum = 0;
        for (int i = 0; i < _cpus; i++)
        {
            long idle = Marshal.ReadInt64(_cpuBuf, i * 48);
            long kern = Marshal.ReadInt64(_cpuBuf, i * 48 + 8);
            long user = Marshal.ReadInt64(_cpuBuf, i * 48 + 16);
            long tot = kern + user; // kernel inclui ocioso
            long dI = idle - _prevIdle[i], dT = tot - _prevTotal[i];
            _prevIdle[i] = idle; _prevTotal[i] = tot;
            if (perCore != null) perCore[i] = dT > 0 ? Math.Clamp(100.0 * (1.0 - (double)dI / dT), 0, 100) : 0;
            dIdleSum += dI; dTotSum += dT;
        }
        total = dTotSum > 0 ? Math.Clamp(100.0 * (1.0 - (double)dIdleSum / dTotSum), 0, 100) : 0;
        return total;
    }

    public void Fill(SystemSample s)
    {
        s.CpuCores = new double[_cpus];
        ReadCores(s.CpuCores, out var tot);
        s.CpuTotal = tot;

        var ms = new Win32.MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<Win32.MEMORYSTATUSEX>() };
        if (Win32.GlobalMemoryStatusEx(ref ms)) { s.MemTotal = (long)ms.ullTotalPhys; s.MemAvail = (long)ms.ullAvailPhys; }
        if (Win32.GetPerformanceInfo(out var pi, (uint)Marshal.SizeOf<Win32.PERFORMANCE_INFORMATION>()))
        {
            long page = (long)pi.PageSize;
            s.CommitUsed = (long)pi.CommitTotal * page; s.CommitLimit = (long)pi.CommitLimit * page;
            s.Cached = (long)pi.SystemCache * page;
            s.ProcessCount = (int)pi.ProcessCount; s.ThreadCount = (int)pi.ThreadCount; s.HandleCount = (int)pi.HandleCount;
        }
        s.Uptime = TimeSpan.FromMilliseconds(Win32.GetTickCount64());

        if (_q.Collect())
        {
            s.DiskReadBps = First(_diskR); s.DiskWriteBps = First(_diskW);
            s.DiskBusyPct = Math.Min(100, First(_diskBusy)); s.DiskQueue = First(_diskQ);
            s.DiskLatencyMs = First(_diskLat) * 1000.0;

            var rx = _q.Read(_netRx); var tx = _q.Read(_netTx); var bw = _q.Read(_netBw);
            double down = 0, up = 0, cap = 0;
            foreach (var (n, v) in rx) if (UsableNic(n)) down += v;
            foreach (var (n, v) in tx) if (UsableNic(n)) up += v;
            // capacidade = maior link ativo (bits/s -> bytes/s)
            foreach (var (n, v) in bw) if (UsableNic(n)) cap = Math.Max(cap, v / 8.0);
            s.NetDownBps = down; s.NetUpBps = up; s.NetCapacityBps = cap;

            if (HasFreq)
            {
                double perf = First(_perf), nominal = First(_freq);
                if (perf > 0 && nominal > 0) s.CpuFreqMhz = nominal * perf / 100.0;
            }
            if (HasThermal)
            {
                var t = _q.Read(_thermal);
                double max = 0;
                foreach (var (_, k) in t) { var c = k - 273.15; if (c > 0 && c < 130) max = Math.Max(max, c); }
                if (max > 0) s.CpuTempC = max;
            }
        }
    }

    double First(int idx) { var r = _q.Read(idx); return r.Count > 0 ? r[0].Value : 0; }

    internal static bool UsableNic(string n)
    {
        var l = n.ToLowerInvariant();
        return !(l.Contains("isatap") || l.Contains("teredo") || l.Contains("loopback") || l.Contains("pseudo") ||
                 l.Contains("vethernet") || l.Contains("virtualbox") || l.Contains("vmware") || l.Contains("wan miniport") || l.Contains("6to4"));
    }

    public void Dispose() { _q.Dispose(); Marshal.FreeHGlobal(_cpuBuf); }
}
