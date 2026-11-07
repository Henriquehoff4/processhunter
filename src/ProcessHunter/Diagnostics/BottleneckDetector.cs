using ProcessHunter.Core;

namespace ProcessHunter.Diagnostics;

public sealed class LeakResult
{
    public bool Suspected;
    public double GrowthBytes, SlopeBytesPerMin, R2, MonotonicRatio, WindowMinutes;
    public string Reason = "";
}

/// <summary>Detecção de crescimento persistente de memória (heurística; nunca prova um vazamento).</summary>
public static class LeakAnalysis
{
    public static LeakResult Analyze(float[] bytes, double stepSeconds, double minWindowMinutes = 10, double minGrowthBytes = 150e6, double minGrowthRatio = 0.2)
    {
        var r = new LeakResult();
        int n = bytes.Length;
        r.WindowMinutes = n * stepSeconds / 60.0;
        if (r.WindowMinutes < minWindowMinutes) { r.Reason = "Janela de observação insuficiente"; return r; }

        double sx = 0, sy = 0, sxx = 0, sxy = 0, syy = 0;
        int up = 0, down = 0;
        for (int i = 0; i < n; i++)
        {
            double x = i * stepSeconds / 60.0, y = bytes[i];
            sx += x; sy += y; sxx += x * x; sxy += x * y; syy += y * y;
            if (i > 0) { if (bytes[i] > bytes[i - 1] * 1.0005) up++; else if (bytes[i] < bytes[i - 1] * 0.995) down++; }
        }
        double den = n * sxx - sx * sx;
        if (den <= 0) return r;
        double slope = (n * sxy - sx * sy) / den;
        double varY = n * syy - sy * sy;
        double r2 = varY <= 0 ? 0 : Math.Pow(n * sxy - sx * sy, 2) / (den * varY);
        double first = Avg(bytes, 0, Math.Max(1, n / 10)), last = Avg(bytes, n - Math.Max(1, n / 10), n);
        r.GrowthBytes = last - first; r.SlopeBytesPerMin = slope; r.R2 = r2;
        r.MonotonicRatio = (up + down) == 0 ? 0 : (double)up / (up + down);

        bool growth = r.GrowthBytes >= minGrowthBytes && first > 0 && r.GrowthBytes / first >= minGrowthRatio;
        // Crescimento persistente: ajuste linear forte, poucas quedas relevantes (um app que libera memória periodicamente não é vazamento).
        r.Suspected = growth && slope > 0 && r2 >= 0.85 && down <= Math.Max(1, n / 25);
        r.Reason = r.Suspected ? "Crescimento contínuo sem liberações relevantes" :
                   !growth ? "Crescimento abaixo do limiar" : "Memória oscila/libera — padrão compatível com cache ou coleta de lixo";
        return r;
    }

    static double Avg(float[] a, int s, int e) { double t = 0; for (int i = s; i < e; i++) t += a[i]; return e > s ? t / (e - s) : 0; }
}

public sealed class SystemRings
{
    public readonly Ring Cpu = new(3600), Mem = new(3600), Gpu = new(3600), Vram = new(3600), DiskBusy = new(3600), NetPct = new(3600),
        DiskRead = new(3600), DiskWrite = new(3600), NetDown = new(3600), NetUp = new(3600), CpuTemp = new(3600), GpuTemp = new(3600),
        GpuPower = new(3600), Commit = new(3600), DiskLatency = new(3600),
        CpuPkgTemp = new(3600), CpuPkgPower = new(3600), FanMax = new(3600);
}

public sealed class DetectorInput
{
    public SystemSample Sys = null!;
    public IReadOnlyList<ProcSample> Procs = Array.Empty<ProcSample>();
    public SystemRings Rings = null!;
    public Settings Settings = new();
    public double IntervalSec = 1;
    public DateTime Now = DateTime.Now;
}

/// <summary>Motor de regras com histerese: um achado só aparece após persistir, e some após cessar. Explica, mostra evidências e sugere ações.</summary>
public sealed class BottleneckDetector
{
    readonly Dictionary<string, DateTime> _since = new();
    readonly Dictionary<string, Finding> _active = new();
    readonly List<Finding> _resolved = new();
    public double ClearAfterSeconds = 15;

    static readonly HashSet<string> Ignore = new(StringComparer.OrdinalIgnoreCase) { "System", "Ociosidade do Sistema", "System Idle Process", "Registry", "Memory Compression", "MemCompression", "Secure System" };

    /// <summary>Notas de contexto: explicam por que certos consumos costumam ser legítimos.</summary>
    static readonly Dictionary<string, string> Notes = new(StringComparer.OrdinalIgnoreCase)
    {
        ["MsMpEng.exe"] = "É o antivírus Microsoft Defender. Varreduras agendadas elevam CPU/disco temporariamente; é comportamento esperado.",
        ["TiWorker.exe"] = "Instalador de atualizações do Windows (Windows Update). Costuma terminar sozinho.",
        ["TrustedInstaller.exe"] = "Serviço de instalação de atualizações do Windows.",
        ["SearchIndexer.exe"] = "Indexador de pesquisa do Windows; trabalha mais após mudanças grandes em arquivos.",
        ["vmmem"] = "Memória da máquina virtual (WSL2/Hyper-V). O consumo é definido pelas VMs; ajuste o arquivo .wslconfig se necessário.",
        ["vmmemWSL"] = "Memória do WSL2. Ajuste limites em .wslconfig.",
        ["dwm.exe"] = "Compositor de janelas do Windows; usa GPU proporcional à quantidade/animação de janelas e monitores.",
        ["chrome.exe"] = "Navegador com múltiplos processos (abas/extensões). O total soma vários processos.",
        ["msedge.exe"] = "Navegador com múltiplos processos (abas/extensões). O total soma vários processos.",
        ["firefox.exe"] = "Navegador com múltiplos processos (abas/extensões).",
    };

    static readonly string[] HeavyByDesign =
    {
        "afterfx", "aerender", "adobe media encoder", "premiere", "photoshop", "blender", "ffmpeg", "handbrake", "davinci", "resolve",
        "ollama", "llama", "lm studio", "lmstudio", "comfyui", "python", "stable", "obs64", "unrealeditor", "unity", "cinebench", "7z", "winrar"
    };

    public static string? NoteFor(string name) => Notes.TryGetValue(name, out var n) ? n : null;

    public static bool IsHeavyByDesign(string name)
    {
        var l = name.ToLowerInvariant();
        return HeavyByDesign.Any(h => l.Contains(h));
    }

    public IReadOnlyList<Finding> Active => _active.Values.OrderByDescending(f => f.Severity).ThenBy(f => f.FirstSeen).ToList();
    public IReadOnlyList<Finding> Resolved => _resolved;

    public List<Finding> Evaluate(DetectorInput inp)
    {
        var cands = new List<(Finding F, double HoldSec)>();
        Rules(inp, cands);
        var seen = new HashSet<string>();
        var newly = new List<Finding>();
        foreach (var (f, hold) in cands)
        {
            if (!seen.Add(f.Key)) continue;
            if (!_since.TryGetValue(f.Key, out var since)) _since[f.Key] = since = inp.Now;
            if ((inp.Now - since).TotalSeconds < hold && !_active.ContainsKey(f.Key)) continue;
            f.LastSeen = inp.Now;
            if (_active.TryGetValue(f.Key, out var ex))
            {
                f.FirstSeen = ex.FirstSeen;
                _active[f.Key] = f;
            }
            else { f.FirstSeen = inp.Now; _active[f.Key] = f; newly.Add(f); }
        }
        foreach (var k in _since.Keys.Where(k => !seen.Contains(k)).ToList())
        {
            if (_active.TryGetValue(k, out var f) && (inp.Now - f.LastSeen).TotalSeconds < ClearAfterSeconds) continue;
            _since.Remove(k);
            if (_active.Remove(k, out var gone)) { gone.Active = false; _resolved.Insert(0, gone); if (_resolved.Count > 200) _resolved.RemoveAt(_resolved.Count - 1); }
        }
        return newly;
    }

    // ---------- helpers ----------
    static double AvgTail(Ring r, int n)
    {
        var t = r.Tail(n); if (t.Length < Math.Max(2, n * 0.7)) return 0;
        double s = 0; foreach (var v in t) s += v; return s / t.Length;
    }

    static string P(ProcSample p) => $"{p.Name} (PID {p.Pid})";

    void Rules(DetectorInput i, List<(Finding, double)> c)
    {
        var s = i.Sys; var st = i.Settings; var R = i.Rings;
        int n30 = Math.Max(3, (int)(30 / i.IntervalSec)), n60 = Math.Max(5, (int)(60 / i.IntervalSec)), n15 = Math.Max(3, (int)(15 / i.IntervalSec));
        var procs = i.Procs.Where(p => !Ignore.Contains(p.Name)).ToList();
        var fg = s.ForegroundPid;

        // ---- saturação de CPU ----
        double cpu30 = AvgTail(R.Cpu, n30);
        if (cpu30 >= st.CpuWarnPercent)
        {
            var top = procs.OrderByDescending(p => p.Cpu).Take(3).ToList();
            c.Add((new Finding
            {
                Key = "sat-cpu", Severity = Severity.Warning, Category = "CPU", Title = "CPU saturada",
                Explanation = $"A CPU ficou em média {cpu30:0}% nos últimos 30 s. Quando todos os núcleos estão ocupados, o sistema pode engasgar, mas isso é normal durante renders e compilações.",
                Evidence = top.Select(p => $"{P(p)}: {p.Cpu:0.0}% da CPU").Prepend($"Média 30 s: {cpu30:0}% em {s.CpuCores.Length} threads lógicos").ToList(),
                Suggestions = new() { "Se não for uma tarefa pesada intencional, finalize ou pause o maior consumidor listado.", "Reduza a prioridade de tarefas em segundo plano (Baixa/Abaixo do normal).", "Verifique se a temperatura não está causando redução de frequência." },
                LikelyExpected = top.Count > 0 && (top[0].Pid == fg || IsHeavyByDesign(top[0].Name))
            }, 10));
        }

        // ---- RAM ----
        double mem30 = AvgTail(R.Mem, n30);
        if (mem30 >= st.RamWarnPercent)
        {
            var top = procs.OrderByDescending(p => p.Private).Take(3).ToList();
            c.Add((new Finding
            {
                Key = "sat-mem", Severity = mem30 >= 95 ? Severity.Critical : Severity.Warning, Category = "Memória", Title = "Memória RAM quase esgotada",
                Explanation = $"{mem30:0}% da RAM física está em uso. Com pouca memória livre o Windows passa a usar o arquivo de paginação (disco), o que causa lentidão perceptível.",
                Evidence = top.Select(p => $"{P(p)}: {Fmt.Bytes(p.Private)} privados").Prepend($"Disponível: {Fmt.Bytes(s.MemAvail)} de {Fmt.Bytes(s.MemTotal)}").ToList(),
                Suggestions = new() { "Feche aplicativos ou abas que você não está usando.", "Reinicie apps que acumulam memória há muito tempo (veja alertas de vazamento).", "Considere ampliar a RAM se isso for rotina." }
            }, 5));
        }
        if (s.CommitLimit > 0 && s.CommitPercent >= 90)
            c.Add((new Finding
            {
                Key = "sat-commit", Severity = s.CommitPercent >= 97 ? Severity.Critical : Severity.Warning, Category = "Memória", Title = "Memória comprometida perto do limite",
                Explanation = "O total de memória prometida aos programas se aproxima do limite (RAM + arquivo de paginação). Se chegar a 100%, programas podem falhar ao alocar memória.",
                Evidence = new() { $"Comprometida: {Fmt.Bytes(s.CommitUsed)} / {Fmt.Bytes(s.CommitLimit)} ({s.CommitPercent:0}%)" },
                Suggestions = new() { "Verifique se o arquivo de paginação está em gerenciamento automático.", "Feche aplicativos que reservam muita memória." }
            }, 10));

        foreach (var p in procs)
        {
            bool isFg = p.Pid == fg;
            bool heavy = IsHeavyByDesign(p.Name);
            Notes.TryGetValue(p.Name, out var note);

            // ---- CPU por processo ----
            double pc = AvgTail(p.State.CpuHist, n30);
            if (pc >= 25)
            {
                bool expected = isFg || heavy || note != null;
                c.Add((new Finding
                {
                    Key = $"cpu:{p.Pid}", Pid = p.Pid, Subject = p.Name, Category = "CPU",
                    Severity = expected ? Severity.Info : (pc >= 50 ? Severity.Critical : Severity.Warning),
                    Title = expected ? $"{p.Name}: uso alto de CPU (provavelmente esperado)" : $"{p.Name} consumindo muita CPU",
                    Explanation = $"{p.Name} usou em média {pc:0}% da capacidade total da CPU nos últimos 30 s." +
                                  (isFg ? " Está em primeiro plano — uso alto é normal enquanto você trabalha nele." : "") +
                                  (note != null ? " " + note : "") +
                                  (heavy && !isFg ? " Este tipo de aplicativo (render, IA, codificação) costuma usar muita CPU por natureza." : "") +
                                  " Alto consumo, sozinho, não indica defeito nem software malicioso.",
                    Evidence = new() { $"CPU média 30 s: {pc:0.0}%", $"Threads: {p.Threads}", $"Em execução há {Fmt.Duration(i.Now - p.StartTime)}", p.Details.Path ?? "Caminho indisponível" },
                    Suggestions = expected
                        ? new() { "Nenhuma ação necessária se a tarefa é intencional.", "Para liberar CPU para outras tarefas, reduza a prioridade do processo." }
                        : new() { "Verifique se o aplicativo está travado (sem resposta) e reinicie-o.", "Reduza a prioridade (Abaixo do normal) em vez de finalizar.", "Atualize o aplicativo/drivers; procure extensões ou plugins problemáticos." },
                    LikelyExpected = expected
                }, 5));
            }
            else if (!isFg && AvgTail(p.State.CpuHist, n60) >= 5 && !heavy && note == null && p.Pid > 4)
            {
                double bg = AvgTail(p.State.CpuHist, n60);
                c.Add((new Finding
                {
                    Key = $"bg:{p.Pid}", Pid = p.Pid, Subject = p.Name, Category = "Segundo plano", Severity = Severity.Info,
                    Title = $"{p.Name} usa CPU em segundo plano",
                    Explanation = $"{p.Name} não está em primeiro plano mas manteve {bg:0.0}% da CPU por 1 minuto. Muitos programas sincronizam, indexam ou atualizam em segundo plano; só é problema se persistir sem motivo.",
                    Evidence = new() { $"CPU média 60 s: {bg:0.0}%", p.Details.Path ?? "Caminho indisponível" },
                    Suggestions = new() { "Se não precisa do aplicativo agora, feche-o completamente (inclusive da bandeja).", "Desative-o da inicialização, se não for necessário." }
                }, 20));
            }

            // ---- RAM por processo ----
            long limit = Math.Max(2L << 30, s.MemTotal / 7);
            if (p.Private >= limit)
            {
                bool expected = isFg || heavy || note != null;
                c.Add((new Finding
                {
                    Key = $"mem:{p.Pid}", Pid = p.Pid, Subject = p.Name, Category = "Memória", Severity = expected ? Severity.Info : Severity.Warning,
                    Title = $"{p.Name} usa muita RAM ({Fmt.Bytes(p.Private)})",
                    Explanation = $"{p.Name} mantém {Fmt.Bytes(p.Private)} de memória privada ({100.0 * p.Private / Math.Max(1, s.MemTotal):0}% da RAM)." + (note != null ? " " + note : "") +
                                  " Aplicativos podem manter caches grandes de propósito para ganhar velocidade.",
                    Evidence = new() { $"Memória privada: {Fmt.Bytes(p.Private)}", $"Conjunto de trabalho: {Fmt.Bytes(p.WorkingSet)}", $"Comprometida: {Fmt.Bytes(p.Commit)}" },
                    Suggestions = new() { "Se o sistema estiver lento, reinicie este aplicativo para recuperar memória.", "Feche projetos/abas que não está usando." },
                    LikelyExpected = expected
                }, 10));
            }

            // ---- vazamento ----
            var leak = p.State.LeakSeries.Count >= 60 ? LeakAnalysis.Analyze(p.State.LeakSeries.ToArray(), 10) : new LeakResult();
            if (leak.Suspected && p.Pid > 4)
                c.Add((new Finding
                {
                    Key = $"leak:{p.Pid}", Pid = p.Pid, Subject = p.Name, Category = "Vazamento", Severity = Severity.Warning,
                    Title = $"{p.Name}: possível vazamento de memória",
                    Explanation = $"A memória privada de {p.Name} cresceu de forma contínua por {leak.WindowMinutes:0} min, sem liberações relevantes (ajuste linear R²={leak.R2:0.00}). Isso é um indício, não prova: alguns apps crescem enquanto carregam dados ou enchem caches.",
                    Evidence = new() { $"Crescimento: +{Fmt.Bytes(leak.GrowthBytes)} em {leak.WindowMinutes:0} min", $"Taxa: {Fmt.Bytes(leak.SlopeBytesPerMin)}/min", $"Memória atual: {Fmt.Bytes(p.Private)}" },
                    Suggestions = new() { "Salve seu trabalho e reinicie o aplicativo para liberar a memória.", "Verifique se há atualização do aplicativo, plugin ou driver.", "Se o crescimento voltar rápido após reiniciar, reporte ao fornecedor." }
                }, 0));

            // ---- VRAM por processo ----
            if (s.Gpu.VramTotal is > 0 && p.VramDedicated >= s.Gpu.VramTotal * 0.5)
            {
                bool expected = isFg || heavy;
                c.Add((new Finding
                {
                    Key = $"vram:{p.Pid}", Pid = p.Pid, Subject = p.Name, Category = "VRAM", Severity = expected ? Severity.Info : Severity.Warning,
                    Title = $"{p.Name} ocupa {100.0 * p.VramDedicated / s.Gpu.VramTotal.Value:0}% da VRAM",
                    Explanation = $"{p.Name} usa {Fmt.Bytes(p.VramDedicated)} da VRAM dedicada. Jogos, renders e modelos de IA reservam VRAM de propósito; o problema ocorre apenas quando a VRAM acaba e dados passam para a RAM, reduzindo o desempenho.",
                    Evidence = new() { $"VRAM do processo: {Fmt.Bytes(p.VramDedicated)}", $"VRAM total: {Fmt.Bytes(s.Gpu.VramTotal.Value)}" },
                    Suggestions = new() { "Reduza texturas/resolução ou o tamanho do modelo/lote.", "Feche outros aplicativos que usam a GPU." },
                    LikelyExpected = expected
                }, 10));
            }

            // ---- Disco por processo ----
            double io = AvgTail(p.State.IoHist, n30);
            if (io >= 30e6)
                c.Add((new Finding
                {
                    Key = $"io:{p.Pid}", Pid = p.Pid, Subject = p.Name, Category = "Disco", Severity = (isFg || heavy || note != null) ? Severity.Info : Severity.Warning,
                    Title = $"{p.Name}: atividade intensa de E/S ({io / 1048576.0:0} MB/s)",
                    Explanation = $"{p.Name} moveu em média {io / 1048576.0:0} MB/s de dados (arquivos, dispositivos e pipes) nos últimos 30 s. Cópias, instalações, renders e downloads causam isso normalmente." + (note != null ? " " + note : ""),
                    Evidence = new() { $"E/S média 30 s: {io / 1048576.0:0.0} MB/s", $"Leitura atual: {Fmt.Rate(p.IoReadBps)} / Escrita: {Fmt.Rate(p.IoWriteBps)}" },
                    Suggestions = new() { "Aguarde a tarefa terminar se ela for intencional.", "Se não for, verifique sincronização (OneDrive/antivírus/indexação) e pause-a." },
                    LikelyExpected = isFg || heavy || note != null
                }, 10));

            // ---- Inicialização lenta ----
            if (p.State.StartAfterBootSec is > 0 and <= 300 && p.State.CpuSecondsTotal >= 30 && s.Uptime.TotalHours < 2)
                c.Add((new Finding
                {
                    Key = $"startup:{p.Pid}", Pid = p.Pid, Subject = p.Name, Category = "Inicialização", Severity = Severity.Info,
                    Title = $"{p.Name} pesou na inicialização",
                    Explanation = $"{p.Name} iniciou {p.State.StartAfterBootSec:0} s após o boot e já consumiu {p.State.CpuSecondsTotal:0} s de CPU. Programas que iniciam com o Windows competem por CPU/disco justamente quando você quer começar a usar o PC.",
                    Evidence = new() { $"Iniciado {p.State.StartAfterBootSec:0} s após o boot", $"CPU acumulada: {p.State.CpuSecondsTotal:0} s", $"E/S acumulada: {Fmt.Bytes(p.State.IoBytesTotal)}" },
                    Suggestions = new() { "Em 'Inicialização', desative-o se não precisar dele logo ao ligar.", "Ou atrase seu início (tarefa agendada com atraso)." }
                }, 0));
        }

        // ---- VRAM global ----
        if (s.Gpu.VramTotal is > 0 && s.Gpu.VramUsed.HasValue)
        {
            double pct = 100.0 * s.Gpu.VramUsed.Value / s.Gpu.VramTotal.Value;
            if (pct >= st.VramWarnPercent)
            {
                var top = procs.OrderByDescending(p => p.VramDedicated).Take(3).Where(p => p.VramDedicated > 0).ToList();
                c.Add((new Finding
                {
                    Key = "sat-vram", Severity = pct >= 97 ? Severity.Critical : Severity.Warning, Category = "VRAM", Title = "VRAM quase esgotada",
                    Explanation = $"{pct:0}% da VRAM está ocupada. Ao esgotar, o driver passa dados para a RAM (memória compartilhada), causando quedas de FPS, engasgos e lentidão em IA/renders.",
                    Evidence = top.Select(p => $"{P(p)}: {Fmt.Bytes(p.VramDedicated)}").Prepend($"{Fmt.Bytes(s.Gpu.VramUsed.Value)} de {Fmt.Bytes(s.Gpu.VramTotal.Value)}").ToList(),
                    Suggestions = new() { "Feche aplicativos com aceleração de GPU que não está usando (navegadores, overlays).", "Reduza texturas/qualidade, resolução ou tamanho do modelo/lote.", "Quantize o modelo de IA ou use offload parcial." }
                }, 5));
            }
        }

        // ---- GPU ----
        double gpu30 = AvgTail(R.Gpu, n30);
        if (gpu30 >= 95)
        {
            var top = procs.Where(p => p.Gpu > 1).OrderByDescending(p => p.Gpu).Take(3).ToList();
            bool exp = top.Count > 0 && (top[0].Pid == fg || IsHeavyByDesign(top[0].Name));
            c.Add((new Finding
            {
                Key = "sat-gpu", Severity = exp ? Severity.Info : Severity.Warning, Category = "GPU", Title = exp ? "GPU em uso máximo (esperado)" : "GPU saturada",
                Explanation = $"A GPU ficou em média {gpu30:0}% por 30 s. Em jogos, renders e inferência de IA, 95–100% significa que a GPU está sendo bem aproveitada — não é defeito." + (exp ? "" : " Se você não está executando algo pesado, investigue o consumidor listado."),
                Evidence = top.Select(p => $"{P(p)}: {p.Gpu:0}% ({p.GpuEngines})").Prepend($"Média 30 s: {gpu30:0}%").ToList(),
                Suggestions = new() { "Limite o FPS (V-Sync/limitador) para reduzir carga e calor.", "Feche aplicativos que usam GPU em segundo plano." }, LikelyExpected = exp
            }, 10));
        }
        if (s.Gpu.Temperature is double gt && gt >= st.GpuTempWarn)
            c.Add((new Finding
            {
                Key = "temp-gpu", Severity = gt >= st.GpuTempWarn + 5 ? Severity.Critical : Severity.Warning, Category = "Temperatura", Title = $"GPU quente ({gt:0} °C)",
                Explanation = "A temperatura da GPU está elevada. Em carga contínua é comum chegar a 70–80 °C; acima disso o driver reduz clocks (throttling) e o desempenho cai.",
                Evidence = new() { $"Temperatura: {gt:0} °C", $"Ventoinha: {(s.Gpu.FanPercent.HasValue ? s.Gpu.FanPercent.Value.ToString("0") + "%" : "indisponível")}", $"Motivos de throttling: {s.Gpu.ThrottleReasons ?? "indisponível"}" },
                Suggestions = new() { "Melhore o fluxo de ar do gabinete e limpe filtros/ventoinhas.", "Ajuste a curva de ventoinha ou aplique undervolt.", "Limite FPS/potência." }
            }, 10));
        if (s.CpuTempC is double ct && ct >= st.CpuTempWarn)
            c.Add((new Finding
            {
                Key = "temp-cpu", Severity = Severity.Warning, Category = "Temperatura",
                Title = s.CpuTempIsDeep ? $"CPU quente ({ct:0} °C)" : $"Zona térmica ACPI elevada ({ct:0} °C)",
                Explanation = s.CpuTempIsDeep
                    ? "A temperatura da CPU, lida direto do sensor do processador, está alta. Perto do limite térmico a CPU reduz o clock (throttling) e o desempenho cai."
                    : "A zona térmica ACPI reportada pelo Windows está alta. Atenção: este sensor não é necessariamente a temperatura dos núcleos da CPU; use uma ferramenta de sensores dedicada para confirmar.",
                Evidence = new() { s.CpuTempIsDeep ? $"Temperatura da CPU: {ct:0} °C" : $"Zona térmica: {ct:0} °C" }, Suggestions = new() { "Verifique cooler, pasta térmica e fluxo de ar." }
            }, 10));

        // ---- Disco ----
        double busy = AvgTail(R.DiskBusy, n30);
        double lat = AvgTail(R.DiskLatency, n30);
        if (busy >= 90 || (lat >= 50 && s.DiskQueue >= 2))
        {
            var top = procs.OrderByDescending(p => p.IoTotalBps).Take(3).Where(p => p.IoTotalBps > 1e5).ToList();
            c.Add((new Finding
            {
                Key = "sat-disk", Severity = Severity.Warning, Category = "Disco", Title = "Armazenamento saturado",
                Explanation = $"O disco ficou ocupado {busy:0}% do tempo (latência média {lat:0} ms). Quando o disco satura, abrir programas e arquivos fica lento, mesmo com CPU livre.",
                Evidence = top.Select(p => $"{P(p)}: {Fmt.Rate(p.IoTotalBps)}").Prepend($"Fila: {s.DiskQueue:0.0} · Leitura {Fmt.Rate(s.DiskReadBps)} · Escrita {Fmt.Rate(s.DiskWriteBps)}").ToList(),
                Suggestions = new() { "Aguarde a conclusão de cópias/atualizações/varreduras em andamento.", "Verifique a saúde do disco (SMART) se a lentidão for frequente.", "Mantenha pelo menos 15% de espaço livre em SSDs." }
            }, 10));
        }

        // ---- Rede ----
        if (s.NetCapacityBps > 0)
        {
            double pct = 100.0 * (AvgTail(R.NetDown, n15) + AvgTail(R.NetUp, n15)) / s.NetCapacityBps;
            if (pct >= 90)
                c.Add((new Finding
                {
                    Key = "sat-net", Severity = Severity.Warning, Category = "Rede", Title = "Link de rede saturado",
                    Explanation = $"O tráfego está em ~{pct:0}% da capacidade do link ({Fmt.Mbps(s.NetCapacityBps)}). Downloads, backups e streaming podem estar competindo por banda. O consumo por processo requer ETW (administrador) e não é medido nesta versão.",
                    Evidence = new() { $"Download: {Fmt.Mbps(s.NetDownBps)} · Upload: {Fmt.Mbps(s.NetUpBps)}" },
                    Suggestions = new() { "Pause downloads/sincronizações que não são urgentes.", "Verifique atualizações automáticas em andamento." }
                }, 5));
        }
    }
}
