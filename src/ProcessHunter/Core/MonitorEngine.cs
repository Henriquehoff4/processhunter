using System.Diagnostics;
using System.Runtime.InteropServices;
using ProcessHunter.Collectors;
using ProcessHunter.Diagnostics;

namespace ProcessHunter.Core;

public sealed class TickData
{
    public SystemSample Sys = null!;
    public List<ProcSample> Procs = new();
    public double TickMs;
    public double SelfCpu;
    public long SelfWorkingSet;
    public bool EffectiveLightMode;
    public int EffectiveIntervalMs;
}

/// <summary>Coletor contínuo em thread própria de baixa prioridade. A UI só recebe dados prontos.</summary>
public sealed class MonitorEngine : IDisposable
{
    [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, System.Text.StringBuilder sb, int max);
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int L, T, R, B; }

    public event Action<TickData>? Ticked;
    public event Action<Finding>? FindingRaised;
    public event Action<string>? WatchEvent;

    public readonly Settings Settings;
    public readonly SystemRings Rings = new();
    public readonly BottleneckDetector Detector = new();
    public readonly HistoryStore History;
    public string CpuName => _sys.CpuName;
    public int PhysicalCores => _sys.PhysicalCores;
    public int LogicalCores => _sys.LogicalCores;
    public bool HasCpuTemp => _sys.HasThermal;
    public bool HasCpuFreq => _sys.HasFreq;
    public GpuInfo LastGpu { get; private set; } = new();
    public TickData? Last { get; private set; }
    public volatile bool UiVisible = true;

    readonly ProcessCollector _pc = new();
    readonly SystemCollector _sys = new();
    readonly GpuCollector _gpu = new();
    readonly ProcInfoResolver _resolver = new();
    DeepSensorCollector? _deep;
    DeepSensors? _lastDeepSample;
    readonly Dictionary<int, ProcState> _states = new();
    readonly List<RawProc> _raw = new(512);
    readonly ManualResetEventSlim _wake = new(false);
    readonly Thread _thread;
    volatile bool _stop;
    long _prevTicks; long _tick; DateTime _lastHist = DateTime.MinValue; DateTime _lastDeep = DateTime.MinValue;
    DateTime _boot = DateTime.Now - TimeSpan.FromMilliseconds(Native.Win32.GetTickCount64());
    HashSet<string> _watchRunning = new(StringComparer.OrdinalIgnoreCase);
    bool _watchInit;
    DateTime _lastPurge = DateTime.MinValue;

    public MonitorEngine(Settings s, HistoryStore h)
    {
        Settings = s; History = h;
        _thread = new Thread(Loop) { IsBackground = true, Name = "PH-Monitor", Priority = ThreadPriority.BelowNormal };
    }

    public void Start() => _thread.Start();
    public void Wake() => _wake.Set();
    public void Refresh(ProcSample p) => _resolver.Enqueue(p.Pid, p.Details);

    void Loop()
    {
        var sw = Stopwatch.StartNew();
        _prevTicks = Stopwatch.GetTimestamp();
        while (!_stop)
        {
            long t0 = Stopwatch.GetTimestamp();
            bool light = Settings.LightMode || (Settings.AutoLightWhenFullscreen && IsFullscreenForeground());
            int interval = light ? Math.Max(2000, Settings.IntervalMs) : Settings.IntervalMs;
            try { DoTick(light, interval, t0); }
            catch (Exception e) { Debug.WriteLine("tick error: " + e); }
            double ms = (Stopwatch.GetTimestamp() - t0) * 1000.0 / Stopwatch.Frequency;
            if (Last != null) Last.TickMs = ms;
            int wait = (int)Math.Max(50, interval - ms);
            _wake.Wait(wait);
            _wake.Reset();
        }
    }

    static int ForegroundPid()
    {
        var h = GetForegroundWindow();
        if (h == IntPtr.Zero) return 0;
        GetWindowThreadProcessId(h, out var pid);
        return (int)pid;
    }

    [DllImport("user32.dll")] static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint dwFlags);
    [StructLayout(LayoutKind.Sequential)] struct MONITORINFO { public int cbSize; public RECT rcMonitor; public RECT rcWork; public uint dwFlags; }
    [DllImport("user32.dll")] static extern bool GetMonitorInfo(IntPtr hMonitor, ref MONITORINFO lpmi);

    static bool IsFullscreenForeground()
    {
        try
        {
            var h = GetForegroundWindow();
            if (h == IntPtr.Zero || !GetWindowRect(h, out var r)) return false;
            var sb = new System.Text.StringBuilder(64); GetClassName(h, sb, 64);
            var cls = sb.ToString();
            if (cls is "Progman" or "WorkerW" or "Shell_TrayWnd") return false;
            var hMon = MonitorFromWindow(h, 2 /*MONITOR_DEFAULTTONEAREST*/);
            var mi = new MONITORINFO { cbSize = Marshal.SizeOf<MONITORINFO>() };
            if (!GetMonitorInfo(hMon, ref mi)) return false;
            return r.L <= mi.rcMonitor.L && r.T <= mi.rcMonitor.T && r.R >= mi.rcMonitor.R && r.B >= mi.rcMonitor.B;
        }
        catch { return false; }
    }

    void DoTick(bool light, int interval, long t0)
    {
        var now = DateTime.Now;
        double dt100 = (t0 - _prevTicks) * 1e7 / Stopwatch.Frequency;
        double dtSec = dt100 / 1e7;
        _prevTicks = t0;
        if (dt100 <= 0) return;
        _tick++;

        var sys = new SystemSample { Time = now, ForegroundPid = ForegroundPid() };
        _sys.Fill(sys);
        var gf = _gpu.Collect(sys.Gpu, !light);
        LastGpu = sys.Gpu;
        CollectDeep(sys, now);
        if (!_pc.TryCollect(_raw)) return;

        var procs = new List<ProcSample>(_raw.Count);
        var seen = new HashSet<int>();
        int cpus = _sys.LogicalCores;
        foreach (var r in _raw)
        {
            if (r.Pid == 0) continue;
            seen.Add(r.Pid);
            if (!_states.TryGetValue(r.Pid, out var st) || st.CreateTime != r.CreateTime)
            {
                st = new ProcState { Pid = r.Pid, CreateTime = r.CreateTime, Name = r.Name, FirstSeenTick = _tick };
                if (r.CreateTime > 0) st.StartAfterBootSec = (DateTime.FromFileTime(r.CreateTime) - _boot).TotalSeconds;
                _states[r.Pid] = st;
                _resolver.Enqueue(r.Pid, st.Details);
            }
            double cpu = 0, rd = 0, wr = 0;
            if (st.HasPrev)
            {
                cpu = Math.Clamp((r.CpuTime - st.PrevCpu) / dt100 / cpus * 100.0, 0, 100);
                rd = Math.Max(0, (r.ReadBytes - st.PrevRead) / dtSec);
                wr = Math.Max(0, (r.WriteBytes - st.PrevWrite) / dtSec);
                st.IoBytesTotal += (rd + wr) * dtSec;
            }
            st.PrevCpu = r.CpuTime; st.PrevRead = r.ReadBytes; st.PrevWrite = r.WriteBytes; st.HasPrev = true;
            st.CpuSecondsTotal = r.CpuTime / 1e7;

            var p = new ProcSample
            {
                Pid = r.Pid, ParentPid = r.ParentPid, Name = r.Name, Threads = r.Threads, Handles = r.Handles, BasePriority = r.BasePriority,
                Cpu = cpu, WorkingSet = r.WorkingSet, Private = r.Private, Commit = r.Commit, IoReadBps = rd, IoWriteBps = wr,
                StartTime = r.CreateTime > 0 ? DateTime.FromFileTime(r.CreateTime) : now, CpuSecondsTotal = st.CpuSecondsTotal, Details = st.Details, State = st,
            };
            if (gf.ProcGpu.TryGetValue(r.Pid, out var g)) p.Gpu = g;
            if (gf.ProcEngineTypes.TryGetValue(r.Pid, out var eng))
                p.GpuEngines = string.Join(", ", eng.OrderByDescending(e => e.Value).Take(3).Select(e => $"{ShortEngine(e.Key)} {e.Value:0}%"));
            if (gf.ProcDedicated.TryGetValue(r.Pid, out var vd)) p.VramDedicated = vd;
            if (gf.ProcShared.TryGetValue(r.Pid, out var vs)) p.VramShared = vs;
            p.IsProtected = ProcessActions.IsProtected(r.Pid, r.Name, out _);

            st.CpuHist.Add((float)cpu); st.MemHist.Add(r.Private); st.GpuHist.Add((float)p.Gpu); st.IoHist.Add((float)(rd + wr));
            st.LeakAccum += dtSec;
            if (st.LeakAccum >= 10) { st.LeakAccum = 0; st.LeakSeries.Add(r.Private); }
            procs.Add(p);
        }
        if (_states.Count > seen.Count + 64 || _tick % 30 == 0)
            foreach (var k in _states.Keys.Where(k => !seen.Contains(k)).ToList()) _states.Remove(k);

        // totais de sistema
        sys.TopCpu = Top(procs, p => p.Cpu, "0.0") ; sys.TopMem = Top(procs, p => p.Private / 1048576.0, "0");
        sys.TopGpu = Top(procs, p => p.Gpu, "0"); sys.TopDisk = Top(procs, p => p.IoTotalBps / 1048576.0, "0.0");
        var R = Rings;
        R.Cpu.Add((float)sys.CpuTotal); R.Mem.Add((float)sys.MemPercent);
        R.Gpu.Add((float)(sys.Gpu.Utilization ?? 0));
        R.Vram.Add(sys.Gpu.VramTotal is > 0 && sys.Gpu.VramUsed.HasValue ? (float)(100.0 * sys.Gpu.VramUsed.Value / sys.Gpu.VramTotal.Value) : 0);
        R.DiskBusy.Add((float)sys.DiskBusyPct); R.DiskRead.Add((float)sys.DiskReadBps); R.DiskWrite.Add((float)sys.DiskWriteBps);
        R.NetDown.Add((float)sys.NetDownBps); R.NetUp.Add((float)sys.NetUpBps);
        R.NetPct.Add(sys.NetCapacityBps > 0 ? (float)(100.0 * (sys.NetDownBps + sys.NetUpBps) / sys.NetCapacityBps) : 0);
        R.CpuTemp.Add((float)(sys.CpuTempC ?? 0)); R.GpuTemp.Add((float)(sys.Gpu.Temperature ?? 0)); R.GpuPower.Add((float)(sys.Gpu.PowerW ?? 0));
        R.Commit.Add((float)sys.CommitPercent); R.DiskLatency.Add((float)sys.DiskLatencyMs);

        // diagnóstico (a cada ~2 s)
        if (_tick % Math.Max(1, 2000 / Math.Max(500, interval)) == 0)
        {
            var newly = Detector.Evaluate(new DetectorInput { Sys = sys, Procs = procs, Rings = R, Settings = Settings, IntervalSec = interval / 1000.0, Now = now });
            foreach (var f in newly) FindingRaised?.Invoke(f);
        }

        CheckWatched(procs);
        WriteHistory(sys, procs, now);

        var self = procs.FirstOrDefault(p => p.Pid == Environment.ProcessId);
        var td = new TickData { Sys = sys, Procs = procs, SelfCpu = self?.Cpu ?? 0, SelfWorkingSet = self?.WorkingSet ?? 0, EffectiveLightMode = light, EffectiveIntervalMs = interval };
        Last = td;
        Ticked?.Invoke(td);
    }

    /// <summary>Coleta os sensores profundos em cadência própria (mais lenta), para não onerar o tick principal.</summary>
    void CollectDeep(SystemSample sys, DateTime now)
    {
        if (!Settings.DeepSensorsEnabled)
        {
            if (_deep != null) { _deep.Dispose(); _deep = null; }
            _lastDeepSample = null;
            _lastDeep = DateTime.MinValue;
            return;
        }
        if ((now - _lastDeep).TotalMilliseconds >= Math.Max(1000, Settings.DeepSensorsIntervalMs))
        {
            _lastDeep = now;
            try
            {
                _deep ??= new DeepSensorCollector();
                var d = _deep.Collect();
                _lastDeepSample = d;
                var R = Rings;
                var temp = d.CpuPackageTempC ?? d.CpuMaxCoreTempC;
                if (temp.HasValue) R.CpuPkgTemp.Add((float)temp.Value);
                if (d.CpuPackagePowerW.HasValue) R.CpuPkgPower.Add((float)d.CpuPackagePowerW.Value);
                if (d.Fans.Count > 0)
                {
                    double fan = 0; foreach (var f in d.Fans) fan = Math.Max(fan, f.Value);
                    R.FanMax.Add((float)fan);
                }
            }
            catch (Exception ex)
            {
                // Nunca derruba o tick principal: degrada para "indisponível" (ex.: assembly LHM ausente em build sem RID).
                Debug.WriteLine("deep sensor error: " + ex);
                _lastDeepSample = new DeepSensors { Time = now, Available = false, Error = "Motor de sensores indisponível: " + ex.Message };
            }
        }

        var cur = _lastDeepSample;
        if (cur == null) return;
        sys.Deep = cur;
        var headline = cur.CpuPackageTempC ?? cur.CpuMaxCoreTempC;
        if (headline.HasValue)
        {
            sys.CpuTempC = headline.Value;
            sys.CpuTempIsDeep = true;
        }
    }

    void CheckWatched(List<ProcSample> procs)
    {
        if (Settings.WatchedProcesses.Count == 0) { _watchRunning.Clear(); _watchInit = false; return; }
        var running = new HashSet<string>(procs.Where(p => Settings.WatchedProcesses.Contains(p.Name, StringComparer.OrdinalIgnoreCase)).Select(p => p.Name), StringComparer.OrdinalIgnoreCase);
        if (_watchInit)
        {
            foreach (var n in running.Except(_watchRunning)) WatchEvent?.Invoke($"{n} foi iniciado");
            foreach (var n in _watchRunning.Except(running)) WatchEvent?.Invoke($"{n} foi encerrado");
        }
        _watchRunning = running; _watchInit = true;
    }

    static string ShortEngine(string t) => t switch { "3D" => "3D", "Compute_0" or "Compute_1" => "Compute", "Copy" => "Cópia", "VideoDecode" => "Decod. vídeo", "VideoEncode" => "Codif. vídeo", "VideoProcessing" => "Proc. vídeo", _ => t };

    static string Top(List<ProcSample> l, Func<ProcSample, double> f, string fmt)
    {
        ProcSample? best = null; double bv = 0;
        foreach (var p in l) { var v = f(p); if (v > bv) { bv = v; best = p; } }
        return best == null ? "" : $"{best.Name} ({bv.ToString(fmt, System.Globalization.CultureInfo.InvariantCulture)})";
    }

    void WriteHistory(SystemSample s, List<ProcSample> procs, DateTime now)
    {
        if (!Settings.HistoryEnabled || (now - _lastHist).TotalSeconds < 10) return;
        _lastHist = now;
        var cpuTail = Rings.Cpu.Tail(10);
        List<TopEntry> T(IEnumerable<ProcSample> src, Func<ProcSample, double> f, int n) =>
            src.Where(p => !(p.Pid <= 4)).OrderByDescending(f).Take(n).Where(p => f(p) > 0).Select(p => new TopEntry { Name = p.Name, Value = Math.Round(f(p), 1) }).ToList();
        var rec = new HistRec
        {
            UnixSec = new DateTimeOffset(now).ToUnixTimeSeconds(), Cpu = Math.Round(cpuTail.Length > 0 ? cpuTail.Average() : s.CpuTotal, 1), CpuMax = Math.Round(cpuTail.Length > 0 ? cpuTail.Max() : s.CpuTotal, 1),
            MemPct = Math.Round(s.MemPercent, 1), Gpu = s.Gpu.Utilization, VramPct = s.Gpu.VramTotal is > 0 && s.Gpu.VramUsed.HasValue ? Math.Round(100.0 * s.Gpu.VramUsed.Value / s.Gpu.VramTotal.Value, 1) : null,
            GpuTemp = s.Gpu.Temperature, CpuTemp = s.CpuTempC.HasValue ? Math.Round(s.CpuTempC.Value, 1) : null,
            DiskRead = Math.Round(s.DiskReadBps), DiskWrite = Math.Round(s.DiskWriteBps), NetDown = Math.Round(s.NetDownBps), NetUp = Math.Round(s.NetUpBps),
            TopCpu = T(procs, p => p.Cpu, 8), TopMem = T(procs, p => p.Private / 1048576.0, 8), TopGpu = T(procs, p => p.Gpu, 4), TopIo = T(procs, p => p.IoTotalBps / 1048576.0, 4),
        };
        History.Append(rec);
        if ((now - _lastPurge).TotalHours >= 6) { _lastPurge = now; History.Purge(Settings.RetentionDays); }
    }

    public IReadOnlyList<ProcSample> LastProcs => Last?.Procs ?? new();

    public void Dispose()
    {
        _stop = true; _wake.Set();
        _thread.Join(2000);
        _resolver.Dispose(); _pc.Dispose(); _sys.Dispose(); _gpu.Dispose(); _deep?.Dispose();
    }
}
