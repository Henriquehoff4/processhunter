using ProcessHunter.Core;
using ProcessHunter.Native;

namespace ProcessHunter.Collectors;

internal sealed class GpuFrame
{
    public Dictionary<int, double> ProcGpu = new();
    public Dictionary<int, Dictionary<string, double>> ProcEngineTypes = new();
    public Dictionary<int, long> ProcDedicated = new(), ProcShared = new();
}

/// <summary>NVML (dispositivo) + contadores nativos do Windows (motores e processos) via PDH. Nunca inventa valores.</summary>
internal sealed class GpuCollector : IDisposable
{
    readonly Nvml _nv = new();
    Pdh.Query? _q;
    int _eng = -1, _pDed = -1, _pShr = -1, _aDed = -1, _aShr = -1;
    DateTime _lastRebuild = DateTime.MinValue;
    string? _luid;

    public bool NvmlAvailable => _nv.Available;
    public string Name => _nv.Available ? _nv.Name : "GPU (sem NVML)";

    void Build()
    {
        _q?.Dispose();
        _q = new Pdh.Query();
        _eng = _q.Add(@"\GPU Engine(*)\Utilization Percentage");
        _pDed = _q.Add(@"\GPU Process Memory(*)\Dedicated Usage");
        _pShr = _q.Add(@"\GPU Process Memory(*)\Shared Usage");
        _aDed = _q.Add(@"\GPU Adapter Memory(*)\Dedicated Usage");
        _aShr = _q.Add(@"\GPU Adapter Memory(*)\Shared Usage");
        _q.Collect();
        _lastRebuild = DateTime.UtcNow;
    }

    public GpuFrame Collect(GpuInfo info, bool counters = true)
    {
        var f = new GpuFrame();
        var nv = _nv.Read();
        info.NvmlAvailable = _nv.Available; info.Name = Name; info.Driver = _nv.Driver; info.NvmlError = _nv.Error;
        info.Utilization = nv.Utilization; info.MemControllerUtil = nv.MemControllerUtil; info.Temperature = nv.Temperature;
        info.PowerW = nv.PowerW; info.PowerLimitW = nv.PowerLimitW; info.CoreClock = nv.CoreClock; info.MemClock = nv.MemClock;
        info.MaxCoreClock = nv.MaxCoreClock; info.MaxMemClock = nv.MaxMemClock; info.FanPercent = nv.FanPercent;
        info.Encoder = nv.Encoder; info.Decoder = nv.Decoder; info.PState = nv.PState; info.ThrottleReasons = nv.ThrottleReasons;
        info.VramTotal = nv.VramTotal; info.VramUsed = nv.VramUsed;
        if (!counters) { info.CountersOk = false; return f; }

        // Novos processos criam novas instâncias; reconstruímos a consulta periodicamente.
        if (_q == null || (DateTime.UtcNow - _lastRebuild).TotalSeconds > 45) Build();
        if (_q == null || !_q.Ok || !_q.Collect()) { info.CountersOk = false; return f; }

        // Escolhe o adaptador (LUID) cujo uso de VRAM dedicada mais se aproxima do NVML.
        var adapters = _q.Read(_aDed);
        if (adapters.Count > 0)
        {
            double target = nv.VramUsed ?? -1;
            (string Name, double Value)? best = null;
            foreach (var a in adapters)
            {
                if (best == null) { best = a; continue; }
                if (target >= 0 ? Math.Abs(a.Value - target) < Math.Abs(best.Value.Value - target) : a.Value > best.Value.Value) best = a;
            }
            _luid = ExtractLuid(best!.Value.Name);
            if (!nv.VramUsed.HasValue) info.VramUsed = (long)best.Value.Value;
        }
        foreach (var (n, v) in _q.Read(_aShr)) if (_luid == null || n.Contains(_luid)) info.SharedUsed = (info.SharedUsed ?? 0) + (long)v;

        var engineMax = new Dictionary<string, double>();
        var perEngineSum = new Dictionary<string, double>();
        var engInstances = _q.Read(_eng);
        info.CountersOk = true;
        foreach (var (name, val) in engInstances)
        {
            if (_luid != null && !name.Contains(_luid)) continue;
            int pid = ParsePid(name);
            int ti = name.LastIndexOf("engtype_", StringComparison.Ordinal);
            if (pid < 0 || ti < 0) continue;
            string type = name[(ti + 8)..];
            int pi = name.IndexOf("phys_", StringComparison.Ordinal);
            string engKey = pi >= 0 ? name[pi..] : type;
            perEngineSum[engKey] = perEngineSum.GetValueOrDefault(engKey) + val;
            if (val <= 0.01) continue;
            if (!f.ProcEngineTypes.TryGetValue(pid, out var d)) f.ProcEngineTypes[pid] = d = new();
            d[type] = d.GetValueOrDefault(type) + val;
            f.ProcGpu[pid] = Math.Max(f.ProcGpu.GetValueOrDefault(pid), val);
        }
        foreach (var (k, v) in perEngineSum)
        {
            int ti = k.LastIndexOf("engtype_", StringComparison.Ordinal);
            string type = ti >= 0 ? k[(ti + 8)..] : k;
            engineMax[type] = Math.Max(engineMax.GetValueOrDefault(type), Math.Min(100, v));
        }
        info.Engines = engineMax.OrderByDescending(e => e.Value).Select(e => (e.Key, e.Value)).ToList();

        foreach (var (n, v) in _q.Read(_pDed)) { if (Match(n, out int pid)) f.ProcDedicated[pid] = f.ProcDedicated.GetValueOrDefault(pid) + (long)v; }
        foreach (var (n, v) in _q.Read(_pShr)) { if (Match(n, out int pid)) f.ProcShared[pid] = f.ProcShared.GetValueOrDefault(pid) + (long)v; }
        return f;

        bool Match(string n, out int pid) { pid = ParsePid(n); return pid >= 0 && (_luid == null || n.Contains(_luid)); }
    }

    internal static int ParsePid(string name)
    {
        if (!name.StartsWith("pid_", StringComparison.Ordinal)) return -1;
        int e = name.IndexOf('_', 4);
        return e > 4 && int.TryParse(name.AsSpan(4, e - 4), out var pid) ? pid : -1;
    }

    internal static string? ExtractLuid(string name)
    {
        int s = name.IndexOf("luid_", StringComparison.Ordinal);
        if (s < 0) return null;
        int e = name.IndexOf("_phys", s, StringComparison.Ordinal);
        return e > s ? name[s..e] : name[s..];
    }

    public void Dispose() { _q?.Dispose(); _nv.Dispose(); }
}
