using System.Text.Json.Serialization;

namespace ProcessHunter.Core;

/// <summary>Buffer circular thread-safe de floats (séries temporais).</summary>
public sealed class Ring
{
    readonly float[] _a;
    int _head, _count;
    readonly object _l = new();
    public Ring(int capacity) { _a = new float[capacity]; }
    public int Capacity => _a.Length;
    public int Count { get { lock (_l) return _count; } }

    public void Add(float v)
    {
        lock (_l)
        {
            _a[_head] = v;
            _head = (_head + 1) % _a.Length;
            if (_count < _a.Length) _count++;
        }
    }

    public float Last { get { lock (_l) return _count == 0 ? 0 : _a[(_head - 1 + _a.Length) % _a.Length]; } }

    /// <summary>Cópia cronológica (mais antigo primeiro).</summary>
    public float[] ToArray()
    {
        lock (_l)
        {
            var r = new float[_count];
            int start = (_head - _count + _a.Length) % _a.Length;
            for (int i = 0; i < _count; i++) r[i] = _a[(start + i) % _a.Length];
            return r;
        }
    }

    public float[] Tail(int n)
    {
        var all = ToArray();
        return all.Length <= n ? all : all[^n..];
    }
}

public enum Severity { Info = 0, Warning = 1, Critical = 2 }

/// <summary>Detalhes caros (caminho, usuário, assinatura...) resolvidos de forma assíncrona e em cache.</summary>
public sealed class ProcDetails
{
    public volatile string? Path;
    public volatile string? User;
    public volatile string? Company;
    public volatile string? Description;
    public volatile string? Version;
    public volatile string? Signer;
    public volatile SignatureState Signature = SignatureState.Pending;
    public volatile string? SignatureNote;
    public volatile string? Priority;
    public volatile bool Resolved;
    public volatile bool AccessDenied;
    public volatile System.Windows.Media.ImageSource? Icon;
}

public enum SignatureState { Pending, Valid, Invalid, Unsigned, Unknown }

/// <summary>Amostra imutável de um processo em um tick.</summary>
public sealed class ProcSample
{
    public int Pid, ParentPid, Threads, Handles, BasePriority;
    public string Name = "";
    public double Cpu;                 // % da capacidade total da máquina
    public long WorkingSet, Private, Commit;
    public double IoReadBps, IoWriteBps, IoOtherBps;
    public DateTime StartTime;
    public double Gpu;                 // % (maior motor)
    public string GpuEngines = "";
    public long VramDedicated, VramShared;
    public double CpuSecondsTotal;
    public ProcDetails Details = new();
    public ProcState State = null!;
    public bool IsProtected;
    public double IoTotalBps => IoReadBps + IoWriteBps;
}

/// <summary>Estado persistente de um processo (históricos curtos para gráficos e detecção).</summary>
public sealed class ProcState
{
    public int Pid; public long CreateTime;
    public long PrevCpu, PrevRead, PrevWrite, PrevOther;
    public bool HasPrev;
    public string Name = "";
    public readonly Ring CpuHist = new(600), MemHist = new(600), GpuHist = new(600), IoHist = new(600);
    /// <summary>Memória privada decimada (1 ponto/10 s, 1 h) para análise de vazamento.</summary>
    public readonly Ring LeakSeries = new(360);
    public double LeakAccum;
    public ProcDetails Details = new();
    public double CpuSecondsTotal;
    public double IoBytesTotal;
    public double StartAfterBootSec;
    public long FirstSeenTick;
}

public sealed class GpuInfo
{
    public bool NvmlAvailable;
    public string Name = "GPU";
    public string Driver = "";
    public string? NvmlError;
    public double? Utilization, MemControllerUtil, Temperature, PowerW, PowerLimitW, CoreClock, MemClock, MaxCoreClock, MaxMemClock, FanPercent, Encoder, Decoder;
    public long? VramTotal, VramUsed, SharedUsed;
    public int? PState;
    public string? ThrottleReasons;
    public List<(string Engine, double Util)> Engines = new();
    public bool CountersOk;
    public long? VramFree => VramTotal.HasValue && VramUsed.HasValue ? VramTotal - VramUsed : null;
}

public sealed class SystemSample
{
    public DateTime Time;
    public double CpuTotal;
    public double[] CpuCores = Array.Empty<double>();
    public double? CpuFreqMhz, CpuTempC;
    public bool CpuTempIsDeep;
    public long MemTotal, MemAvail, CommitUsed, CommitLimit, Cached;
    public double MemPercent => MemTotal == 0 ? 0 : 100.0 * (MemTotal - MemAvail) / MemTotal;
    public double CommitPercent => CommitLimit == 0 ? 0 : 100.0 * CommitUsed / CommitLimit;
    public double DiskReadBps, DiskWriteBps, DiskBusyPct, DiskQueue, DiskLatencyMs;
    public double NetDownBps, NetUpBps, NetCapacityBps;
    public int ProcessCount, ThreadCount, HandleCount;
    public TimeSpan Uptime;
    public GpuInfo Gpu = new();
    public string TopCpu = "", TopMem = "", TopGpu = "", TopDisk = "";
    public int ForegroundPid;
    /// <summary>Sensores profundos (estilo HWiNFO); nulo quando o motor está desabilitado ou ainda não coletou.</summary>
    public DeepSensors? Deep;
}

/// <summary>Leitura individual de um sensor profundo (nome + valor bruto na unidade do sensor).</summary>
public sealed class SensorReading
{
    public string Name = "";
    public double Value;
}

/// <summary>Amostra de sensores profundos (estilo HWiNFO) obtida pelo motor LibreHardwareMonitorLib.</summary>
public sealed class DeepSensors
{
    public DateTime Time;
    public bool Available;
    public bool ElevationRequired;
    public bool PawnIoMissing;
    public string? Error;

    public bool HasCpuTemp => CpuPackageTempC.HasValue || CpuMaxCoreTempC.HasValue;
    public bool NeedsElevation => ElevationRequired && !HasCpuTemp;
    public bool HasAnyReading => HasCpuTemp || CpuPackagePowerW.HasValue || CpuCoreVoltage.HasValue || CpuVid.HasValue
        || CoreTemps.Count > 0 || Fans.Count > 0 || Voltages.Count > 0 || BoardTemps.Count > 0
        || MaxDimmTempC.HasValue || StorageTemps.Count > 0;

    // CPU
    public double? CpuPackageTempC;    // temperatura do package/encapsulamento
    public double? CpuMaxCoreTempC;    // núcleo mais quente
    public double? CpuPackagePowerW;   // potência do package (RAPL)
    public double? CpuCoreVoltage;     // Vcore medido (Super I/O)
    public double? CpuVid;             // VID solicitado pela CPU (fallback quando não há Vcore medido)
    public List<SensorReading> CoreTemps = new();

    // Placa-mãe (Super I/O / Embedded Controller)
    public List<SensorReading> Fans = new();       // RPM
    public List<SensorReading> Voltages = new();   // V
    public List<SensorReading> BoardTemps = new(); // °C

    // Memória / Armazenamento
    public double? MaxDimmTempC;
    public List<SensorReading> StorageTemps = new();
}

public sealed class Finding
{
    public string Key = "";
    public Severity Severity;
    public string Category = "";
    public string Title = "";
    public string Explanation = "";
    public List<string> Evidence = new();
    public List<string> Suggestions = new();
    public string? Subject;
    public int? Pid;
    public DateTime FirstSeen, LastSeen;
    public bool Active = true;
    /// <summary>Verdadeiro quando o consumo é provavelmente legítimo (ex.: app em primeiro plano).</summary>
    public bool LikelyExpected;
}

public sealed class ProcessActionResult
{
    public bool Ok; public string Message = "";
    public static ProcessActionResult Fail(string m) => new() { Ok = false, Message = m };
    public static ProcessActionResult Success(string m) => new() { Ok = true, Message = m };
}

public static class Fmt
{
    public static string Bytes(double b)
    {
        string[] u = { "B", "KB", "MB", "GB", "TB" };
        int i = 0;
        while (b >= 1024 && i < u.Length - 1) { b /= 1024; i++; }
        return i == 0 ? $"{b:0} {u[i]}" : $"{b:0.#} {u[i]}";
    }
    public static string Rate(double bps) => Bytes(bps) + "/s";
    public static string Mbps(double bytesPerSec) => $"{bytesPerSec / 1048576.0:0.0} MB/s";
    public static string Duration(TimeSpan t)
    {
        if (t.TotalDays >= 1) return $"{(int)t.TotalDays}d {t.Hours:00}h {t.Minutes:00}m";
        if (t.TotalHours >= 1) return $"{(int)t.TotalHours}h {t.Minutes:00}m {t.Seconds:00}s";
        return $"{t.Minutes}m {t.Seconds:00}s";
    }
}
