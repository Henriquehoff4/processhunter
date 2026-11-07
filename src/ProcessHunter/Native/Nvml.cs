using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcessHunter.Native;

/// <summary>Integração NVML via nvml.dll (instalado com o driver NVIDIA). Falhas são tratadas: métrica ausente = null.</summary>
internal sealed class Nvml : IDisposable
{
    [StructLayout(LayoutKind.Sequential)] struct Util { public uint gpu, memory; }
    [StructLayout(LayoutKind.Sequential)] struct Mem { public ulong total, free, used; }

    const string Lib = "nvml_ph";

    [DllImport(Lib)] static extern int nvmlInit_v2();
    [DllImport(Lib)] static extern int nvmlShutdown();
    [DllImport(Lib)] static extern int nvmlDeviceGetCount_v2(out uint c);
    [DllImport(Lib)] static extern int nvmlDeviceGetHandleByIndex_v2(uint i, out IntPtr d);
    [DllImport(Lib)] static extern int nvmlDeviceGetName(IntPtr d, StringBuilder n, uint len);
    [DllImport(Lib)] static extern int nvmlSystemGetDriverVersion(StringBuilder n, uint len);
    [DllImport(Lib)] static extern int nvmlDeviceGetUtilizationRates(IntPtr d, out Util u);
    [DllImport(Lib)] static extern int nvmlDeviceGetMemoryInfo(IntPtr d, out Mem m);
    [DllImport(Lib)] static extern int nvmlDeviceGetTemperature(IntPtr d, int sensor, out uint t);
    [DllImport(Lib)] static extern int nvmlDeviceGetPowerUsage(IntPtr d, out uint mw);
    [DllImport(Lib)] static extern int nvmlDeviceGetEnforcedPowerLimit(IntPtr d, out uint mw);
    [DllImport(Lib)] static extern int nvmlDeviceGetClockInfo(IntPtr d, int type, out uint mhz);
    [DllImport(Lib)] static extern int nvmlDeviceGetMaxClockInfo(IntPtr d, int type, out uint mhz);
    [DllImport(Lib)] static extern int nvmlDeviceGetFanSpeed(IntPtr d, out uint pct);
    [DllImport(Lib)] static extern int nvmlDeviceGetEncoderUtilization(IntPtr d, out uint u, out uint period);
    [DllImport(Lib)] static extern int nvmlDeviceGetDecoderUtilization(IntPtr d, out uint u, out uint period);
    [DllImport(Lib)] static extern int nvmlDeviceGetPerformanceState(IntPtr d, out int s);
    [DllImport(Lib)] static extern int nvmlDeviceGetCurrentClocksThrottleReasons(IntPtr d, out ulong r);

    static Nvml()
    {
        NativeLibrary.SetDllImportResolver(typeof(Nvml).Assembly, (name, asm, path) =>
        {
            if (name != Lib) return IntPtr.Zero;
            string[] cands =
            {
                "nvml.dll",
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "NVIDIA Corporation", "NVSMI", "nvml.dll"),
                Path.Combine(Environment.SystemDirectory, "nvml.dll"),
            };
            foreach (var c in cands)
                if (NativeLibrary.TryLoad(c, out var h)) return h;
            return IntPtr.Zero;
        });
    }

    IntPtr _dev;
    public bool Available { get; private set; }
    public string? Error { get; private set; }
    public string Name { get; private set; } = "";
    public string Driver { get; private set; } = "";

    public Nvml()
    {
        try
        {
            int r = nvmlInit_v2();
            if (r != 0) { Error = $"nvmlInit falhou (código {r})"; return; }
            nvmlDeviceGetCount_v2(out var count);
            if (count == 0) { Error = "Nenhuma GPU NVIDIA encontrada pelo NVML"; return; }
            nvmlDeviceGetHandleByIndex_v2(0, out _dev);
            var sb = new StringBuilder(96); nvmlDeviceGetName(_dev, sb, 96); Name = sb.ToString();
            var dv = new StringBuilder(32); nvmlSystemGetDriverVersion(dv, 32); Driver = dv.ToString();
            Available = true;
        }
        catch (Exception e) when (e is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException)
        {
            Error = "NVML (nvml.dll) indisponível: " + e.Message;
        }
    }

    static T? Try<T>(Func<(int r, T v)> f) where T : struct
    {
        try { var (r, v) = f(); return r == 0 ? v : null; } catch { return null; }
    }

    public NvmlSample Read()
    {
        var s = new NvmlSample();
        if (!Available) return s;
        var u = Try(() => { var r = nvmlDeviceGetUtilizationRates(_dev, out var x); return (r, x); });
        if (u != null) s.Utilization = u.Value.gpu;
        var m = Try(() => { var r = nvmlDeviceGetMemoryInfo(_dev, out var x); return (r, x); });
        if (m != null) { s.VramTotal = (long)m.Value.total; s.VramUsed = (long)m.Value.used; s.MemControllerUtil = u?.memory; }
        s.Temperature = Try(() => { var r = nvmlDeviceGetTemperature(_dev, 0, out var x); return (r, (double)x); });
        s.PowerW = Try(() => { var r = nvmlDeviceGetPowerUsage(_dev, out var x); return (r, x / 1000.0); });
        s.PowerLimitW = Try(() => { var r = nvmlDeviceGetEnforcedPowerLimit(_dev, out var x); return (r, x / 1000.0); });
        s.CoreClock = Try(() => { var r = nvmlDeviceGetClockInfo(_dev, 0, out var x); return (r, (double)x); });
        s.MemClock = Try(() => { var r = nvmlDeviceGetClockInfo(_dev, 2, out var x); return (r, (double)x); });
        s.MaxCoreClock = Try(() => { var r = nvmlDeviceGetMaxClockInfo(_dev, 0, out var x); return (r, (double)x); });
        s.MaxMemClock = Try(() => { var r = nvmlDeviceGetMaxClockInfo(_dev, 2, out var x); return (r, (double)x); });
        s.FanPercent = Try(() => { var r = nvmlDeviceGetFanSpeed(_dev, out var x); return (r, (double)x); });
        s.Encoder = Try(() => { var r = nvmlDeviceGetEncoderUtilization(_dev, out var x, out _); return (r, (double)x); });
        s.Decoder = Try(() => { var r = nvmlDeviceGetDecoderUtilization(_dev, out var x, out _); return (r, (double)x); });
        s.PState = Try(() => { var r = nvmlDeviceGetPerformanceState(_dev, out var x); return (r, x); });
        var th = Try(() => { var r = nvmlDeviceGetCurrentClocksThrottleReasons(_dev, out var x); return (r, x); });
        if (th != null) s.ThrottleReasons = DescribeThrottle(th.Value);
        return s;
    }

    internal static string DescribeThrottle(ulong r)
    {
        var l = new List<string>();
        if ((r & 0x4) != 0) l.Add("limite de potência (SW)");
        if ((r & 0x8) != 0) l.Add("limite térmico (HW slowdown)");
        if ((r & 0x20) != 0) l.Add("limite de potência (SW power cap)");
        if ((r & 0x40) != 0) l.Add("limite térmico (SW)");
        if ((r & 0x80) != 0) l.Add("freio de energia (HW)");
        if ((r & 0x2) != 0) l.Add("clocks de aplicação");
        return l.Count == 0 ? "nenhum" : string.Join(", ", l);
    }

    public void Dispose()
    {
        if (Available) { try { nvmlShutdown(); } catch { } Available = false; }
    }
}

internal sealed class NvmlSample
{
    public double? Utilization, MemControllerUtil, Temperature, PowerW, PowerLimitW, CoreClock, MemClock, MaxCoreClock, MaxMemClock, FanPercent, Encoder, Decoder;
    public long? VramTotal, VramUsed;
    public int? PState;
    public string? ThrottleReasons;
}
