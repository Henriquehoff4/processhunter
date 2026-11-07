using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProcessHunter.Core;

public sealed class TopEntry
{
    [JsonPropertyName("n")] public string Name { get; set; } = "";
    [JsonPropertyName("v")] public double Value { get; set; }
}

/// <summary>Registro de histórico (a cada ~10 s): métricas do sistema + maiores consumidores (permite atribuir picos a processos).</summary>
public sealed class HistRec
{
    [JsonPropertyName("t")] public long UnixSec { get; set; }
    [JsonPropertyName("cpu")] public double Cpu { get; set; }
    [JsonPropertyName("cpuMax")] public double CpuMax { get; set; }
    [JsonPropertyName("mem")] public double MemPct { get; set; }
    [JsonPropertyName("gpu")] public double? Gpu { get; set; }
    [JsonPropertyName("vram")] public double? VramPct { get; set; }
    [JsonPropertyName("gpuT")] public double? GpuTemp { get; set; }
    [JsonPropertyName("cpuT")] public double? CpuTemp { get; set; }
    [JsonPropertyName("dr")] public double DiskRead { get; set; }
    [JsonPropertyName("dw")] public double DiskWrite { get; set; }
    [JsonPropertyName("nd")] public double NetDown { get; set; }
    [JsonPropertyName("nu")] public double NetUp { get; set; }
    [JsonPropertyName("tc")] public List<TopEntry> TopCpu { get; set; } = new();
    [JsonPropertyName("tm")] public List<TopEntry> TopMem { get; set; } = new();
    [JsonPropertyName("tg")] public List<TopEntry> TopGpu { get; set; } = new();
    [JsonPropertyName("ti")] public List<TopEntry> TopIo { get; set; } = new();
    [JsonIgnore] public DateTime Time => DateTimeOffset.FromUnixTimeSeconds(UnixSec).LocalDateTime;
}

/// <summary>Armazenamento local em JSON Lines (um arquivo por dia) com retenção configurável.</summary>
public sealed class HistoryStore
{
    readonly string _dir;
    static readonly JsonSerializerOptions Opt = new() { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
    public HistoryStore(string dir) { _dir = dir; Directory.CreateDirectory(dir); }

    string FileFor(DateTime d) => Path.Combine(_dir, $"history-{d:yyyyMMdd}.jsonl");

    public void Append(HistRec r)
    {
        try { File.AppendAllText(FileFor(r.Time), JsonSerializer.Serialize(r, Opt) + "\n"); } catch { }
    }

    public List<HistRec> Load(DateTime from, DateTime to)
    {
        var res = new List<HistRec>();
        for (var d = from.Date; d <= to.Date; d = d.AddDays(1))
        {
            var f = FileFor(d);
            if (!File.Exists(f)) continue;
            try
            {
                using var fs = new FileStream(f, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                using var sr = new StreamReader(fs);
                string? line;
                while ((line = sr.ReadLine()) != null)
                {
                    if (line.Length < 5) continue;
                    try
                    {
                        var r = JsonSerializer.Deserialize<HistRec>(line);
                        if (r != null && r.Time >= from && r.Time <= to) res.Add(r);
                    }
                    catch { }
                }
            }
            catch { }
        }
        return res;
    }

    public int Purge(int retentionDays)
    {
        int n = 0;
        var limit = DateTime.Now.Date.AddDays(-retentionDays);
        foreach (var f in Directory.EnumerateFiles(_dir, "history-*.jsonl"))
        {
            var name = Path.GetFileNameWithoutExtension(f)[8..];
            if (DateTime.TryParseExact(name, "yyyyMMdd", null, System.Globalization.DateTimeStyles.None, out var d) && d < limit)
            {
                try { File.Delete(f); n++; } catch { }
            }
        }
        return n;
    }

    public long SizeBytes() => Directory.EnumerateFiles(_dir, "history-*.jsonl").Sum(f => new FileInfo(f).Length);
    public void Clear() { foreach (var f in Directory.EnumerateFiles(_dir, "history-*.jsonl")) try { File.Delete(f); } catch { } }

    /// <summary>Procura registros onde o consumidor do pico foi o processo dado (histórico por processo).</summary>
    public static List<(DateTime Time, double Cpu, double Mem, double Gpu)> ForProcess(IEnumerable<HistRec> recs, string name)
    {
        var l = new List<(DateTime, double, double, double)>();
        foreach (var r in recs)
        {
            double c = r.TopCpu.FirstOrDefault(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value ?? double.NaN;
            double m = r.TopMem.FirstOrDefault(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value ?? double.NaN;
            double g = r.TopGpu.FirstOrDefault(e => e.Name.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value ?? double.NaN;
            if (!double.IsNaN(c) || !double.IsNaN(m) || !double.IsNaN(g)) l.Add((r.Time, c, m, g));
        }
        return l;
    }

    /// <summary>Identifica o ponto de pico de uma série e o consumidor responsável registrado naquele instante.</summary>
    public static (HistRec Rec, string Culprit)? FindPeak(IReadOnlyList<HistRec> recs, Func<HistRec, double> metric, Func<HistRec, List<TopEntry>> top)
    {
        if (recs.Count == 0) return null;
        var peak = recs.MaxBy(metric)!;
        var t = top(peak).MaxBy(e => e.Value);
        return (peak, t == null ? "(sem dados de processo)" : $"{t.Name} ({t.Value:0.#})");
    }
}

public static class Exporter
{
    static string Esc(string? s)
    {
        s ??= "";
        return s.Contains(',') || s.Contains('"') || s.Contains('\n') ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }

    /// <summary>Evita injeção de fórmulas ao abrir CSV no Excel.</summary>
    internal static string Safe(string? s)
    {
        s ??= "";
        return s.Length > 0 && "=+-@".Contains(s[0]) ? "'" + s : s;
    }

    public static string ProcessesCsv(IEnumerable<ProcSample> procs)
    {
        var sb = new StringBuilder();
        sb.AppendLine("PID,PPID,Nome,CPU_%,RAM_Privada_MB,ConjuntoTrabalho_MB,GPU_%,VRAM_Dedicada_MB,ES_MBps,Threads,Handles,Caminho,Usuario,Fornecedor,Assinatura,Inicio");
        foreach (var p in procs)
            sb.AppendLine(string.Join(",", p.Pid, p.ParentPid, Esc(Safe(p.Name)), p.Cpu.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture),
                (p.Private / 1048576.0).ToString("0.0", System.Globalization.CultureInfo.InvariantCulture), (p.WorkingSet / 1048576.0).ToString("0.0", System.Globalization.CultureInfo.InvariantCulture),
                p.Gpu.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture), (p.VramDedicated / 1048576.0).ToString("0.0", System.Globalization.CultureInfo.InvariantCulture),
                (p.IoTotalBps / 1048576.0).ToString("0.00", System.Globalization.CultureInfo.InvariantCulture), p.Threads, p.Handles,
                Esc(Safe(p.Details.Path)), Esc(Safe(p.Details.User)), Esc(Safe(p.Details.Signer ?? p.Details.Company)), p.Details.Signature, p.StartTime.ToString("s")));
        return sb.ToString();
    }

    public static string HistoryCsv(IEnumerable<HistRec> recs)
    {
        var sb = new StringBuilder();
        var ci = System.Globalization.CultureInfo.InvariantCulture;
        sb.AppendLine("Hora,CPU_%,RAM_%,GPU_%,VRAM_%,GPU_C,CPU_zona_C,Disco_Leitura_MBps,Disco_Escrita_MBps,Rede_Down_MBps,Rede_Up_MBps,TopCPU,TopRAM,TopGPU");
        string F(double? d) => d.HasValue ? d.Value.ToString("0.0", ci) : "";
        string T(List<TopEntry> l) => l.Count == 0 ? "" : $"{l[0].Name} ({l[0].Value.ToString("0.#", ci)})";
        foreach (var r in recs)
            sb.AppendLine(string.Join(",", r.Time.ToString("s"), F(r.Cpu), F(r.MemPct), F(r.Gpu), F(r.VramPct), F(r.GpuTemp), F(r.CpuTemp),
                F(r.DiskRead / 1048576.0), F(r.DiskWrite / 1048576.0), F(r.NetDown / 1048576.0), F(r.NetUp / 1048576.0), Esc(Safe(T(r.TopCpu))), Esc(Safe(T(r.TopMem))), Esc(Safe(T(r.TopGpu)))));
        return sb.ToString();
    }

    public static string HistoryJson(IEnumerable<HistRec> recs) =>
        JsonSerializer.Serialize(recs, new JsonSerializerOptions { WriteIndented = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull });

    public static string ProcessesJson(IEnumerable<ProcSample> procs) =>
        JsonSerializer.Serialize(procs.Select(p => new
        {
            p.Pid, p.ParentPid, p.Name, Cpu = Math.Round(p.Cpu, 2), PrivateBytes = p.Private, p.WorkingSet, Gpu = Math.Round(p.Gpu, 1), VramDedicated = p.VramDedicated,
            IoBytesPerSec = Math.Round(p.IoTotalBps), p.Threads, p.Handles, Path = p.Details.Path, User = p.Details.User, Vendor = p.Details.Signer ?? p.Details.Company,
            Signature = p.Details.Signature.ToString(), Started = p.StartTime
        }), new JsonSerializerOptions { WriteIndented = true });

    public static string FindingsJson(IEnumerable<Finding> f) => JsonSerializer.Serialize(f, new JsonSerializerOptions { WriteIndented = true });
}

/// <summary>Comparação "antes e depois" de abrir um aplicativo (agregado por nome de processo).</summary>
public sealed class Snapshot
{
    public DateTime Time;
    public double Cpu, MemPct, Gpu, VramBytes, MemUsed;
    public Dictionary<string, (double Cpu, long Mem, long Vram, double Gpu)> ByName = new(StringComparer.OrdinalIgnoreCase);

    public static Snapshot Capture(SystemSample s, IEnumerable<ProcSample> procs)
    {
        var sn = new Snapshot { Time = s.Time, Cpu = s.CpuTotal, MemPct = s.MemPercent, MemUsed = s.MemTotal - s.MemAvail, Gpu = s.Gpu.Utilization ?? 0, VramBytes = s.Gpu.VramUsed ?? 0 };
        foreach (var p in procs)
        {
            var o = sn.ByName.GetValueOrDefault(p.Name);
            sn.ByName[p.Name] = (o.Cpu + p.Cpu, o.Mem + p.Private, o.Vram + p.VramDedicated, o.Gpu + p.Gpu);
        }
        return sn;
    }

    public record DiffRow(string Name, double DCpu, long DMem, long DVram, double DGpu, bool IsNew);

    public static List<DiffRow> Diff(Snapshot a, Snapshot b)
    {
        var rows = new List<DiffRow>();
        foreach (var (name, vb) in b.ByName)
        {
            bool had = a.ByName.TryGetValue(name, out var va);
            rows.Add(new DiffRow(name, vb.Cpu - va.Cpu, vb.Mem - va.Mem, vb.Vram - va.Vram, vb.Gpu - va.Gpu, !had));
        }
        foreach (var (name, va) in a.ByName) if (!b.ByName.ContainsKey(name)) rows.Add(new DiffRow(name, -va.Cpu, -va.Mem, -va.Vram, -va.Gpu, false));
        return rows.Where(r => Math.Abs(r.DCpu) > 0.3 || Math.Abs(r.DMem) > 20L << 20 || Math.Abs(r.DVram) > 20L << 20 || Math.Abs(r.DGpu) > 1)
                   .OrderByDescending(r => Math.Abs(r.DMem) / 1048576.0 + Math.Abs(r.DCpu) * 10 + Math.Abs(r.DVram) / 1048576.0).ToList();
    }
}
