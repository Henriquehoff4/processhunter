using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using Microsoft.Win32;
using ProcessHunter.Collectors;
using ProcessHunter.Core;
using ProcessHunter.Dialogs;
using ProcessHunter.Native;
using ProcessHunter.ViewModels;

namespace ProcessHunter;

public partial class MainWindow : Window
{
    readonly Settings _settings;
    readonly HistoryStore _history;
    readonly MonitorEngine _engine;
    readonly OverlayWindow _overlay;
    readonly TrayIcon _trayIcon;

    readonly ObservableCollection<ProcessItemViewModel> _processItems = new();
    readonly Dictionary<int, ProcessItemViewModel> _procVmMap = new();
    ICollectionView? _procView;

    Snapshot? _snapshotA;
    bool _isClosingReal;
    string _activeFilterChip = "All";
    int _currentTab = 0;
    bool _isReady;

    public MainWindow()
    {
        TitleBar.ApplyWarmDark(this);
        Settings.InitDataDir();
        _settings = Settings.Load();
        _history = new HistoryStore(Path.Combine(Settings.DataDir, "history"));
        _engine = new MonitorEngine(_settings, _history);
        _overlay = new OverlayWindow();

        InitializeComponent();

        // System Tray Icon
        _trayIcon = new TrayIcon(this, "ProcessHunter — Ultimate System Monitor");
        _trayIcon.DoubleClicked += () => ShowAndRestore();
        _trayIcon.RightClicked += () => ShowTrayMenu();

        // Configura DataGrid de Processos
        _procView = CollectionViewSource.GetDefaultView(_processItems);
        _procView.Filter = FilterProcessItem;
        GridProcesses.ItemsSource = _procView;

        // Eventos do Motor
        _engine.Ticked += OnEngineTicked;
        _engine.FindingRaised += OnFindingRaised;
        _engine.WatchEvent += OnWatchEvent;

        // Carrega configurações na UI
        LoadSettingsToUi();

        _isReady = true;

        _engine.Start();
    }

    void LoadSettingsToUi()
    {
        TxtCpuModel.Text = _engine.CpuName;
        TxtCpuCoresInfo.Text = $"{_engine.PhysicalCores} núcleos físicos · {_engine.LogicalCores} threads";
        GpuTabName.Text = _engine.LastGpu.Name;

        // Intervalo
        foreach (ComboBoxItem item in CmbInterval.Items)
        {
            if (int.TryParse(item.Tag?.ToString(), out var v) && v == _settings.IntervalMs)
            {
                CmbInterval.SelectedItem = item;
                break;
            }
        }
        foreach (ComboBoxItem item in CfgInterval.Items)
        {
            if (int.TryParse(item.Tag?.ToString(), out var v) && v == _settings.IntervalMs)
            {
                CfgInterval.SelectedItem = item;
                break;
            }
        }

        BtnLightMode.IsChecked = _settings.LightMode;
        CfgAutoLight.IsChecked = _settings.AutoLightWhenFullscreen;
        CfgMinimizeTray.IsChecked = _settings.MinimizeToTray;
        CfgOverlay.IsChecked = _settings.OverlayEnabled;
        CfgNotifications.IsChecked = _settings.NotificationsEnabled;
        CfgDeepSensors.IsChecked = _settings.DeepSensorsEnabled;

        foreach (var w in _settings.WatchedProcesses) ListWatched.Items.Add(w);

        if (_settings.OverlayEnabled) _overlay.Show();
    }

    void OnEngineTicked(TickData data)
    {
        Dispatcher.BeginInvoke(() =>
        {
            try
            {
                UpdateUi(data);
            }
            catch { }
        });
    }

    void UpdateUi(TickData data)
    {
        var sys = data.Sys;

        // 1. Ticker no Header
        HdrCpu.Text = $"{sys.CpuTotal:0.0}%";
        HdrRam.Text = $"{sys.MemPercent:0.0}%";
        HdrGpu.Text = sys.Gpu.Utilization.HasValue ? $"{sys.Gpu.Utilization.Value:0}%" : "—";
        if (sys.Gpu.VramTotal is > 0 && sys.Gpu.VramUsed.HasValue)
        {
            double vpct = 100.0 * sys.Gpu.VramUsed.Value / sys.Gpu.VramTotal.Value;
            HdrVram.Text = $"{vpct:0}%";
        }
        else
        {
            HdrVram.Text = "—";
        }
        HdrDisk.Text = $"{((sys.DiskReadBps + sys.DiskWriteBps) / 1048576.0):0.0} MB/s";
        HdrNet.Text = $"{((sys.NetDownBps + sys.NetUpBps) / 1048576.0):0.0} MB/s";

        // 2. HUD Overlay
        if (_overlay.IsVisible) _overlay.UpdateMetrics(sys);

        // 3. Status Bar
        StatusUptime.Text = $"Tempo de Atividade: {Fmt.Duration(sys.Uptime)}";
        StatusProcs.Text = $"Processos: {sys.ProcessCount}";
        StatusThreads.Text = $"Threads: {sys.ThreadCount}";
        StatusHandles.Text = $"Handles: {sys.HandleCount}";
        StatusTickTime.Text = $"Coleta: {data.TickMs:0.0} ms";
        TxtSelfOverhead.Text = $"CPU: {data.SelfCpu:0.0}% · RAM: {Fmt.Bytes(data.SelfWorkingSet)}";

        // Atualiza a Tab ativa
        switch (_currentTab)
        {
            case 0:
                UpdateOverviewTab(sys, data);
                break;
            case 1:
                UpdateProcessesTab(data.Procs);
                break;
            case 2:
                UpdateGpuTab(sys.Gpu, data.Procs);
                break;
            case 3:
                UpdateSensorsTab(sys.Deep);
                break;
            case 4:
                UpdateBottlenecksTab();
                break;
            case 5:
                UpdateHistoryTab();
                break;
        }

        // Sempre atualiza o badge de alertas
        int activeFindings = _engine.Detector.Active.Count;
        if (activeFindings > 0)
        {
            BadgeFindings.Visibility = Visibility.Visible;
            TxtFindingsCount.Text = activeFindings.ToString();
        }
        else
        {
            BadgeFindings.Visibility = Visibility.Collapsed;
        }
    }

    void UpdateOverviewTab(SystemSample sys, TickData data)
    {
        // CPU
        TxtCpuPct.Text = $"{sys.CpuTotal:0.0}%";
        TxtCpuFreq.Text = sys.CpuFreqMhz.HasValue ? $"{sys.CpuFreqMhz.Value / 1000.0:0.00} GHz" : "—";
        TxtCpuTemp.Text = sys.CpuTempC.HasValue ? $"{(sys.CpuTempIsDeep ? "Temp CPU" : "Temp ACPI")}: {sys.CpuTempC.Value:0} °C" : "Temp: N/A";
        SpkCpu.Values = _engine.Rings.Cpu.Tail(60);
        CoreView.Cores = sys.CpuCores;

        // RAM
        TxtRamTotal.Text = $"Total: {Fmt.Bytes(sys.MemTotal)}";
        TxtRamPct.Text = $"{sys.MemPercent:0.0}%";
        TxtRamAvail.Text = $"Disponível: {Fmt.Bytes(sys.MemAvail)}";
        TxtCommit.Text = $"Comprometida: {Fmt.Bytes(sys.CommitUsed)} / {Fmt.Bytes(sys.CommitLimit)} ({sys.CommitPercent:0}%)";
        TxtCache.Text = $"Cache: {Fmt.Bytes(sys.Cached)}";
        SpkRam.Values = _engine.Rings.Mem.Tail(60);

        // GPU
        TxtGpuName.Text = sys.Gpu.Name;
        TxtGpuPct.Text = sys.Gpu.Utilization.HasValue ? $"{sys.Gpu.Utilization.Value:0}%" : "0%";
        TxtGpuPower.Text = sys.Gpu.PowerW.HasValue ? $"{sys.Gpu.PowerW.Value:0} W" : "—";
        TxtGpuTempOverview.Text = sys.Gpu.Temperature.HasValue ? $"{sys.Gpu.Temperature.Value:0} °C" : "—";
        TxtVramOverview.Text = sys.Gpu.VramTotal.HasValue && sys.Gpu.VramUsed.HasValue
            ? $"VRAM: {Fmt.Bytes(sys.Gpu.VramUsed.Value)} / {Fmt.Bytes(sys.Gpu.VramTotal.Value)}"
            : "VRAM: —";
        TxtGpuClocks.Text = sys.Gpu.CoreClock.HasValue ? $"Clock: {sys.Gpu.CoreClock.Value:0} MHz" : "Clock: —";
        SpkGpu.Values = _engine.Rings.Gpu.Tail(60);

        // Discos
        double totalDisk = sys.DiskReadBps + sys.DiskWriteBps;
        TxtDiskSpeed.Text = $"{totalDisk / 1048576.0:0.0} MB/s";
        TxtDiskActive.Text = $"Ativo: {sys.DiskBusyPct:0}%";
        TxtDiskRW.Text = $"R: {sys.DiskReadBps / 1048576.0:0.0} MB/s · W: {sys.DiskWriteBps / 1048576.0:0.0} MB/s";
        TxtDiskLat.Text = $"Latência: {sys.DiskLatencyMs:0.#} ms (Fila: {sys.DiskQueue:0.#})";
        var diskTail = _engine.Rings.DiskRead.Tail(60);
        var diskWriteTail = _engine.Rings.DiskWrite.Tail(60);
        float[] diskSum = new float[diskTail.Length];
        for (int i = 0; i < diskTail.Length; i++)
            diskSum[i] = (float)((diskTail[i] + (i < diskWriteTail.Length ? diskWriteTail[i] : 0)) / 1048576.0);
        SpkDisk.Values = diskSum;

        // Rede
        double totalNet = sys.NetDownBps + sys.NetUpBps;
        TxtNetSpeed.Text = $"{totalNet / 1048576.0:0.0} MB/s";
        TxtNetDownUp.Text = $"Down: {sys.NetDownBps / 1048576.0:0.0} MB/s · Up: {sys.NetUpBps / 1048576.0:0.0} MB/s";
        TxtNetCapacity.Text = sys.NetCapacityBps > 0 ? $"Link: {Fmt.Mbps(sys.NetCapacityBps)}" : "Link: N/A";
        var netDownTail = _engine.Rings.NetDown.Tail(60);
        var netUpTail = _engine.Rings.NetUp.Tail(60);
        float[] netSum = new float[netDownTail.Length];
        for (int i = 0; i < netDownTail.Length; i++)
            netSum[i] = (float)((netDownTail[i] + (i < netUpTail.Length ? netUpTail[i] : 0)) / 1048576.0);
        SpkNet.Values = netSum;

        // Maiores consumidores
        TxtTopCpu.Text = string.IsNullOrEmpty(sys.TopCpu) ? "—" : sys.TopCpu;
        TxtTopRam.Text = string.IsNullOrEmpty(sys.TopMem) ? "—" : sys.TopMem + " MB";
        TxtTopGpu.Text = string.IsNullOrEmpty(sys.TopGpu) ? "—" : sys.TopGpu + "%";
        TxtTopDisk.Text = string.IsNullOrEmpty(sys.TopDisk) ? "—" : sys.TopDisk + " MB/s";
    }

    void UpdateProcessesTab(IReadOnlyList<ProcSample> procs)
    {
        var seen = new HashSet<int>();
        bool isTree = BtnTreeMode.IsChecked == true;

        if (isTree)
        {
            // Constrói hierarquia de pais e filhos
            var byPid = procs.ToDictionary(p => p.Pid);
            var roots = procs.Where(p => !byPid.ContainsKey(p.ParentPid) || p.ParentPid == 0 || p.ParentPid == p.Pid).ToList();

            var treeOrder = new List<(ProcSample Sample, int Level)>();
            void Walk(ProcSample node, int lvl)
            {
                treeOrder.Add((node, lvl));
                var children = procs.Where(p => p.ParentPid == node.Pid && p.Pid != node.Pid);
                foreach (var c in children) Walk(c, lvl + 1);
            }
            foreach (var r in roots) Walk(r, 0);

            for (int i = 0; i < treeOrder.Count; i++)
            {
                var (s, lvl) = treeOrder[i];
                seen.Add(s.Pid);
                if (_procVmMap.TryGetValue(s.Pid, out var vm))
                {
                    vm.Level = lvl;
                    vm.Update(s);
                }
                else
                {
                    vm = new ProcessItemViewModel(s, lvl);
                    _procVmMap[s.Pid] = vm;
                    _processItems.Add(vm);
                }
            }
        }
        else
        {
            foreach (var s in procs)
            {
                seen.Add(s.Pid);
                if (_procVmMap.TryGetValue(s.Pid, out var vm))
                {
                    vm.Level = 0;
                    vm.Update(s);
                }
                else
                {
                    vm = new ProcessItemViewModel(s, 0);
                    _procVmMap[s.Pid] = vm;
                    _processItems.Add(vm);
                }
            }
        }

        // Remove processos finalizados
        for (int i = _processItems.Count - 1; i >= 0; i--)
        {
            if (!seen.Contains(_processItems[i].Pid))
            {
                _procVmMap.Remove(_processItems[i].Pid);
                _processItems.RemoveAt(i);
            }
        }

        _procView?.Refresh();
    }

    bool FilterProcessItem(object obj)
    {
        if (obj is not ProcessItemViewModel item) return false;

        // Filtro por texto
        string query = TxtSearchProc.Text.Trim();
        if (!string.IsNullOrEmpty(query))
        {
            bool match = item.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                         item.Pid.ToString().Contains(query) ||
                         item.UserText.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                         item.PathText.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                         item.VendorText.Contains(query, StringComparison.OrdinalIgnoreCase);
            if (!match) return false;
        }

        // Filtro por Chip
        return _activeFilterChip switch
        {
            "Apps" => item.Sample.Threads > 2 && !item.IsProtected && !string.IsNullOrEmpty(item.Sample.Details.Path),
            "Bg" => !item.IsProtected && item.Cpu < 0.5,
            "Gpu" => item.Gpu > 0.05 || item.VramDedicated > 0,
            "HighCpu" => item.Cpu >= 10.0,
            "Windows" => item.IsProtected || item.UserText.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase),
            _ => true
        };
    }

    void UpdateGpuTab(GpuInfo gpu, IReadOnlyList<ProcSample> procs)
    {
        GpuTabName.Text = gpu.Name;
        GpuTabDriver.Text = string.IsNullOrEmpty(gpu.Driver) ? "Driver: N/A" : $"Driver: {gpu.Driver}";
        GpuTabStatus.Text = gpu.NvmlAvailable ? "NVML Nativo Ativo + Contadores de Motor Direct3D" : (gpu.NvmlError ?? "NVML Indisponível");

        GpuDetailPct.Text = gpu.Utilization.HasValue ? $"{gpu.Utilization.Value:0}%" : "0%";
        GpuMemCtrlPct.Text = gpu.MemControllerUtil.HasValue ? $"Contr. Memória: {gpu.MemControllerUtil.Value:0}%" : "Contr. Memória: —";

        if (gpu.VramTotal.HasValue && gpu.VramUsed.HasValue)
        {
            double vpct = 100.0 * gpu.VramUsed.Value / gpu.VramTotal.Value;
            GpuDetailVram.Text = $"{Fmt.Bytes(gpu.VramUsed.Value)} / {Fmt.Bytes(gpu.VramTotal.Value)}";
            GpuVramBarText.Text = $"{Fmt.Bytes(gpu.VramUsed.Value)} de {Fmt.Bytes(gpu.VramTotal.Value)} ({vpct:0}%)";
            PbVram.Value = vpct;
        }
        else
        {
            GpuDetailVram.Text = "—";
            GpuVramBarText.Text = "Informações de VRAM indisponíveis";
            PbVram.Value = 0;
        }
        GpuDetailVramShared.Text = gpu.SharedUsed.HasValue ? $"Compartilhada: {Fmt.Bytes(gpu.SharedUsed.Value)}" : "Compartilhada: 0 MB";

        GpuDetailCoreClock.Text = gpu.CoreClock.HasValue ? $"{gpu.CoreClock.Value:0} MHz" : "—";
        GpuDetailMemClock.Text = gpu.MemClock.HasValue ? $"Memória: {gpu.MemClock.Value:0} MHz" : "Memória: —";

        GpuDetailTemp.Text = gpu.Temperature.HasValue ? $"{gpu.Temperature.Value:0} °C" : "—";
        GpuDetailPower.Text = gpu.PowerW.HasValue ? $"{gpu.PowerW.Value:0} W" : "—";
        GpuDetailFan.Text = gpu.FanPercent.HasValue ? $"Ventoinha: {gpu.FanPercent.Value:0}%" : "Ventoinha: —";
        GpuTabPState.Text = gpu.PState.HasValue ? $"Estado: P{gpu.PState.Value}" : "Estado: —";
        GpuTabThrottle.Text = string.IsNullOrEmpty(gpu.ThrottleReasons) ? "Throttling: Nenhum" : $"Throttling: {gpu.ThrottleReasons}";

        // Motores
        var engVm = gpu.Engines.Select(e => new { Engine = e.Engine, Util = e.Util, UtilText = $"{e.Util:0.#}%" }).ToList();
        ListGpuEngines.ItemsSource = engVm;

        // Processos usando GPU
        var gpuProcs = procs.Where(p => p.Gpu > 0.1 || p.VramDedicated > 0)
                            .OrderByDescending(p => p.Gpu)
                            .ThenByDescending(p => p.VramDedicated)
                            .Take(20)
                            .Select(p => new ProcessItemViewModel(p))
                            .ToList();
        GridGpuProcesses.ItemsSource = gpuProcs;
    }

    void UpdateSensorsTab(DeepSensors? d)
    {
        if (d == null)
        {
            SensorBanner.Visibility = Visibility.Collapsed;
            SensorStatus.Text = _settings.DeepSensorsEnabled
                ? "Inicializando motor de sensores..."
                : "Sensores profundos desabilitados.";
            return;
        }

        bool needsElevation = d.NeedsElevation && !d.PawnIoMissing;
        if (!d.Available || d.NeedsElevation)
        {
            SensorBanner.Visibility = Visibility.Visible;
            SensorBannerText.Text = needsElevation
                ? "Os sensores ring-0 (temperatura por núcleo, ventoinhas e tensões) exigem que o ProcessHunter seja executado como administrador."
                : (d.Error ?? "Motor de sensores indisponível neste hardware.");
            BtnElevate.Visibility = needsElevation ? Visibility.Visible : Visibility.Collapsed;
        }
        else
        {
            SensorBanner.Visibility = Visibility.Collapsed;
        }

        double? headline = d.CpuPackageTempC ?? d.CpuMaxCoreTempC;
        SensorCpuTemp.Text = headline.HasValue ? $"{headline.Value:0} °C" : "—";
        SensorCpuTempSub.Text = d.CpuPackageTempC.HasValue ? "Temperatura do package"
            : d.CpuMaxCoreTempC.HasValue ? "Núcleo mais quente (Tctl/Tdie)" : "Sem leitura de temperatura da CPU";
        SensorCoreTempMax.Text = d.CpuMaxCoreTempC.HasValue ? $"Núcleo máx.: {d.CpuMaxCoreTempC.Value:0} °C" : "Núcleo máx.: —";
        SensorCpuPower.Text = d.CpuPackagePowerW.HasValue ? $"{d.CpuPackagePowerW.Value:0.#} W" : "—";

        double? volt = d.CpuCoreVoltage ?? d.CpuVid;
        SensorCoreVoltage.Text = volt.HasValue ? $"{volt.Value:0.###} V" : "—";
        SensorCoreVoltageSub.Text = d.CpuCoreVoltage.HasValue ? "Vcore medido pelo chip Super I/O da placa."
            : d.CpuVid.HasValue ? "VID pedido pela CPU; a placa não expõe o Vcore medido."
            : "Sem leitura de tensão do núcleo.";
        SensorDimmTemp.Text = d.MaxDimmTempC.HasValue ? $"{d.MaxDimmTempC.Value:0} °C" : "—";

        SetSensorList(ListCoreTemps, EmptyCoreTemps, d.CoreTemps, "°C");
        SetSensorList(ListFans, EmptyFans, d.Fans, "RPM");
        SetSensorList(ListVoltages, EmptyVoltages, d.Voltages, "V");
        SetSensorList(ListBoardTemps, EmptyBoardTemps, d.BoardTemps, "°C");
        SetSensorList(ListStorageTemps, EmptyStorageTemps, d.StorageTemps, "°C");

        SensorStatus.Text = d.Available
            ? $"LibreHardwareMonitorLib ativo · {d.CoreTemps.Count} núcleos · {d.Fans.Count} ventoinhas · {d.Voltages.Count} tensões"
            : (d.Error ?? (d.NeedsElevation ? "Aguardando permissão de administrador." : "Indisponível"));
    }

    static void SetSensorList(ItemsControl list, UIElement empty, List<SensorReading> readings, string unit)
    {
        string Fmt(double v) => unit == "V" ? $"{v:0.###} V" : unit == "RPM" ? $"{v:0} RPM" : $"{v:0} °C";
        list.ItemsSource = readings.Select(r => new { r.Name, Text = Fmt(r.Value) }).ToList();
        empty.Visibility = readings.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    void BtnElevate_Click(object sender, RoutedEventArgs e)
    {
        Process? started = null;
        try
        {
            started = Process.Start(new ProcessStartInfo
            {
                FileName = Environment.ProcessPath!,
                Arguments = "--elevated",
                UseShellExecute = true,
                Verb = "runas"
            });
        }
        catch { }

        if (started == null)
        {
            MessageBox.Show("A elevação foi cancelada ou não pôde ser iniciada. Execute o ProcessHunter como administrador para liberar os sensores profundos.",
                "Sensores Profundos", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        ExitApplication();
    }

    void CfgDeepSensors_Changed(object sender, RoutedEventArgs e)
    {
        if (!_isReady || _settings == null) return;
        _settings.DeepSensorsEnabled = CfgDeepSensors.IsChecked == true;
        _settings.Save();
    }

    void UpdateBottlenecksTab()
    {
        var active = _engine.Detector.Active;
        if (active.Count == 0)
        {
            BannerHealth.Background = (Brush)FindResource("OkSoftBrush");
            BannerHealth.BorderBrush = (Brush)FindResource("OkTileBrush");
            IconHealth.Text = "\uE73E";
            IconHealth.Foreground = (Brush)FindResource("OkBrush");
            TxtHealthTitle.Text = "Sistema Saudável — Nenhum Gargalo Detectado";
            TxtHealthSub.Text = "CPU, memória, GPU, VRAM e discos estão operando dentro das margens ideais.";
        }
        else
        {
            bool hasCrit = active.Any(a => a.Severity == Severity.Critical);
            BannerHealth.Background = (Brush)FindResource(hasCrit ? "DangerSoftBrush" : "WarnSoftBrush");
            BannerHealth.BorderBrush = (Brush)FindResource(hasCrit ? "DangerLineBrush" : "WarnBrush");
            IconHealth.Text = "\uE7BA";
            IconHealth.Foreground = (Brush)FindResource(hasCrit ? "DangerBrush" : "WarnBrush");
            TxtHealthTitle.Text = $"{active.Count} Alerta(s) / Possíveis Gargalos Ativos";
            TxtHealthSub.Text = "Analise as evidências abaixo para compreender o diagnóstico antes de tomar qualquer ação.";
        }

        var findingsVm = active.Select(f => new
        {
            f.Category,
            f.Title,
            f.Explanation,
            f.Evidence,
            f.Suggestions,
            LastSeenText = $"Ativo há {Fmt.Duration(DateTime.Now - f.FirstSeen)}"
        }).ToList();
        ListFindings.ItemsSource = findingsVm;
    }

    void UpdateHistoryTab()
    {
        HistSpkCpu.Values = _engine.Rings.Cpu.Tail(300);
        HistSpkRam.Values = _engine.Rings.Mem.Tail(300);
        HistSpkGpu.Values = _engine.Rings.Gpu.Tail(300);

        var drTail = _engine.Rings.DiskRead.Tail(300);
        var dwTail = _engine.Rings.DiskWrite.Tail(300);
        float[] dSum = new float[drTail.Length];
        for (int i = 0; i < drTail.Length; i++)
            dSum[i] = (float)((drTail[i] + (i < dwTail.Length ? dwTail[i] : 0)) / 1048576.0);
        HistSpkDisk.Values = dSum;

        // Picos
        float maxCpu = HistSpkCpu.Values?.Length > 0 ? HistSpkCpu.Values.Max() : 0;
        HistPeakCpu.Text = $"Pico Recente: {maxCpu:0.#}%";
        float maxRam = HistSpkRam.Values?.Length > 0 ? HistSpkRam.Values.Max() : 0;
        HistPeakRam.Text = $"Pico Recente: {maxRam:0.#}%";
        float maxGpu = HistSpkGpu.Values?.Length > 0 ? HistSpkGpu.Values.Max() : 0;
        HistPeakGpu.Text = $"Pico Recente: {maxGpu:0.#}%";
        float maxDisk = dSum.Length > 0 ? dSum.Max() : 0;
        HistPeakDisk.Text = $"Pico Recente: {maxDisk:0.#} MB/s";

        TxtStorageSize.Text = $"Espaço utilizado pelo histórico: {Fmt.Bytes(_history.SizeBytes())}";
    }

    // ==================== NAVEGAÇÃO ====================
    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (sender is not RadioButton rb || !int.TryParse(rb.Tag?.ToString(), out int tab)) return;
        _currentTab = tab;

        if (TabOverview == null || TabProcesses == null || TabGpu == null || TabSensors == null ||
            TabBottlenecks == null || TabHistory == null || TabServices == null || TabSettings == null)
            return;

        TabOverview.Visibility = tab == 0 ? Visibility.Visible : Visibility.Collapsed;
        TabProcesses.Visibility = tab == 1 ? Visibility.Visible : Visibility.Collapsed;
        TabGpu.Visibility = tab == 2 ? Visibility.Visible : Visibility.Collapsed;
        TabSensors.Visibility = tab == 3 ? Visibility.Visible : Visibility.Collapsed;
        TabBottlenecks.Visibility = tab == 4 ? Visibility.Visible : Visibility.Collapsed;
        TabHistory.Visibility = tab == 5 ? Visibility.Visible : Visibility.Collapsed;
        TabServices.Visibility = tab == 6 ? Visibility.Visible : Visibility.Collapsed;
        TabSettings.Visibility = tab == 7 ? Visibility.Visible : Visibility.Collapsed;

        if (tab == 6) RefreshServicesAndStartup();
    }

    // ==================== AÇÕES DE PROCESSOS ====================
    private void TxtSearchProc_TextChanged(object sender, TextChangedEventArgs e) => _procView?.Refresh();

    private void FilterChip_Click(object sender, RoutedEventArgs e)
    {
        if (sender == FilterAll) _activeFilterChip = "All";
        else if (sender == FilterApps) _activeFilterChip = "Apps";
        else if (sender == FilterBg) _activeFilterChip = "Bg";
        else if (sender == FilterGpu) _activeFilterChip = "Gpu";
        else if (sender == FilterHighCpu) _activeFilterChip = "HighCpu";
        else if (sender == FilterWindows) _activeFilterChip = "Windows";
        _procView?.Refresh();
    }

    private void BtnTreeMode_Click(object sender, RoutedEventArgs e)
    {
        _procVmMap.Clear();
        _processItems.Clear();
        if (_engine.Last != null) UpdateProcessesTab(_engine.Last.Procs);
    }

    private void GridProcesses_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (GridProcesses.SelectedItem is ProcessItemViewModel sel)
        {
            PanelProcDetails.Visibility = Visibility.Visible;
            ImgSelIcon.Source = sel.Icon;
            TxtSelTitle.Text = $"{sel.Name} (PID {sel.Pid})";
            TxtSelRuntime.Text = $"Em execução há {sel.RuntimeText} · Prioridade: {sel.Priority}";
            TxtSelPath.Text = sel.PathText;
            TxtSelSigNote.Text = sel.Sample.Details.SignatureNote ?? sel.SignatureText;
        }
        else
        {
            PanelProcDetails.Visibility = Visibility.Collapsed;
        }
    }

    private void GridProcesses_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (GridProcesses.SelectedItem is ProcessItemViewModel sel)
            ProcessActions.OpenLocation(sel.Sample.Details.Path);
    }

    private void BtnEndTask_Click(object sender, RoutedEventArgs e) => KillSelected(false);
    private void CtxKill_Click(object sender, RoutedEventArgs e) => KillSelected(false);
    private void CtxKillTree_Click(object sender, RoutedEventArgs e) => KillSelected(true);
    private void BtnSelKill_Click(object sender, RoutedEventArgs e) => KillSelected(false);

    void KillSelected(bool isTree)
    {
        if (GridProcesses.SelectedItem is not ProcessItemViewModel sel)
        {
            MessageBox.Show("Selecione um processo na tabela.", "ProcessHunter", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (ProcessActions.IsProtected(sel.Pid, sel.Name, out var reason))
        {
            MessageBox.Show($"Este processo não pode ser finalizado pelo ProcessHunter.\n\nMotivo:\n{reason}",
                "Ação Bloqueada — Processo Crítico", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (_settings.ConfirmKill)
        {
            var dlg = new ConfirmKillDialog(sel.Name, sel.Pid, isTree) { Owner = this };
            if (dlg.ShowDialog() != true || !dlg.Confirmed) return;
        }

        var res = ProcessActions.Kill(sel.Pid, sel.Name, isTree);
        if (!res.Ok)
            MessageBox.Show(res.Message, "Não foi possível finalizar", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private void CtxPriority_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not MenuItem mi || GridProcesses.SelectedItem is not ProcessItemViewModel sel) return;
        if (!Enum.TryParse<ProcessPriorityClass>(mi.Tag?.ToString(), out var cls)) return;

        var res = ProcessActions.SetPriority(sel.Pid, sel.Name, cls);
        if (!res.Ok) MessageBox.Show(res.Message, "Alterar Prioridade", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void CtxOpenLocation_Click(object sender, RoutedEventArgs e)
    {
        if (GridProcesses.SelectedItem is ProcessItemViewModel sel) ProcessActions.OpenLocation(sel.Sample.Details.Path);
    }

    private void BtnSelOpenFolder_Click(object sender, RoutedEventArgs e) => CtxOpenLocation_Click(sender, e);

    private void CtxProperties_Click(object sender, RoutedEventArgs e)
    {
        if (GridProcesses.SelectedItem is ProcessItemViewModel sel && !string.IsNullOrEmpty(sel.Sample.Details.Path))
            Win32.ShowProperties(sel.Sample.Details.Path);
    }

    private void BtnSelProperties_Click(object sender, RoutedEventArgs e) => CtxProperties_Click(sender, e);

    private void CtxCopyName_Click(object sender, RoutedEventArgs e)
    {
        if (GridProcesses.SelectedItem is ProcessItemViewModel sel) Clipboard.SetText(sel.Name);
    }

    private void CtxCopyPid_Click(object sender, RoutedEventArgs e)
    {
        if (GridProcesses.SelectedItem is ProcessItemViewModel sel) Clipboard.SetText(sel.Pid.ToString());
    }

    private void CtxCopyPath_Click(object sender, RoutedEventArgs e)
    {
        if (GridProcesses.SelectedItem is ProcessItemViewModel sel && !string.IsNullOrEmpty(sel.Sample.Details.Path))
            Clipboard.SetText(sel.Sample.Details.Path);
    }

    private void BtnExportProcs_Click(object sender, RoutedEventArgs e)
    {
        var sfd = new SaveFileDialog { Filter = "Arquivo CSV (*.csv)|*.csv", FileName = $"processos-{DateTime.Now:yyyyMMdd-HHmm}.csv" };
        if (sfd.ShowDialog() == true)
        {
            File.WriteAllText(sfd.FileName, Exporter.ProcessesCsv(_engine.LastProcs));
            MessageBox.Show("Tabela de processos exportada com sucesso!", "Exportação Concluída", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    // ==================== COMPARADOR ANTES E DEPOIS ====================
    private void BtnCaptureA_Click(object sender, RoutedEventArgs e)
    {
        if (_engine.Last == null) return;
        _snapshotA = Snapshot.Capture(_engine.Last.Sys, _engine.Last.Procs);
        BtnCaptureB.IsEnabled = true;
        TxtSnapshotStatus.Text = $"Ponto A capturado às {_snapshotA.Time:HH:mm:ss} ({_snapshotA.ByName.Count} processos). Abra o aplicativo desejado e clique no Ponto B.";
    }

    private void BtnCaptureB_Click(object sender, RoutedEventArgs e)
    {
        if (_snapshotA == null || _engine.Last == null) return;
        var snapshotB = Snapshot.Capture(_engine.Last.Sys, _engine.Last.Procs);
        var diff = Snapshot.Diff(_snapshotA, snapshotB);

        var diffVm = diff.Select(d => new
        {
            d.Name,
            DCpuText = $"{(d.DCpu >= 0 ? "+" : "")}{d.DCpu:0.0}%",
            DMemText = $"{(d.DMem >= 0 ? "+" : "")}{Fmt.Bytes(d.DMem)}",
            DVramText = $"{(d.DVram >= 0 ? "+" : "")}{Fmt.Bytes(d.DVram)}",
            DGpuText = $"{(d.DGpu >= 0 ? "+" : "")}{d.DGpu:0}%",
            NewText = d.IsNew ? "Sim" : "Não"
        }).ToList();

        GridSnapshotDiff.ItemsSource = diffVm;
        GridSnapshotDiff.Visibility = Visibility.Visible;
        TxtSnapshotStatus.Text = $"Diferença calculada: {_snapshotA.Time:HH:mm:ss} vs {snapshotB.Time:HH:mm:ss} ({diff.Count} processos com alteração relevante).";
    }

    // ==================== EXPORTAÇÕES ====================
    private void BtnExportHistCsv_Click(object sender, RoutedEventArgs e)
    {
        var sfd = new SaveFileDialog { Filter = "Arquivo CSV (*.csv)|*.csv", FileName = $"historico-{DateTime.Now:yyyyMMdd}.csv" };
        if (sfd.ShowDialog() == true)
        {
            var data = _history.Load(DateTime.Now.AddDays(-_settings.RetentionDays), DateTime.Now);
            File.WriteAllText(sfd.FileName, Exporter.HistoryCsv(data));
            MessageBox.Show("Histórico exportado com sucesso em CSV!", "ProcessHunter", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void BtnExportHistJson_Click(object sender, RoutedEventArgs e)
    {
        var sfd = new SaveFileDialog { Filter = "Arquivo JSON (*.json)|*.json", FileName = $"historico-{DateTime.Now:yyyyMMdd}.json" };
        if (sfd.ShowDialog() == true)
        {
            var data = _history.Load(DateTime.Now.AddDays(-_settings.RetentionDays), DateTime.Now);
            File.WriteAllText(sfd.FileName, Exporter.HistoryJson(data));
            MessageBox.Show("Histórico exportado com sucesso em JSON!", "ProcessHunter", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void BtnExportFindings_Click(object sender, RoutedEventArgs e)
    {
        var sfd = new SaveFileDialog { Filter = "Arquivo JSON (*.json)|*.json", FileName = $"diagnostico-{DateTime.Now:yyyyMMdd}.json" };
        if (sfd.ShowDialog() == true)
        {
            File.WriteAllText(sfd.FileName, Exporter.FindingsJson(_engine.Detector.Active));
            MessageBox.Show("Diagnósticos exportados em JSON!", "ProcessHunter", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void BtnClearHist_Click(object sender, RoutedEventArgs e)
    {
        if (MessageBox.Show("Deseja realmente limpar todo o histórico local?", "Confirmar Limpeza", MessageBoxButton.YesNo, MessageBoxImage.Question) == MessageBoxResult.Yes)
        {
            _history.Clear();
            UpdateHistoryTab();
        }
    }

    // ==================== SERVIÇOS & INICIALIZAÇÃO ====================
    void RefreshServicesAndStartup()
    {
        Task.Run(() =>
        {
            var srv = ServicesProvider.GetAll();
            var stp = StartupProvider.GetAll().Select(s => new
            {
                s.Name,
                s.Command,
                s.Location,
                s.Scope,
                EnabledText = s.Enabled ? "Habilitado" : "Desabilitado"
            }).ToList();

            Dispatcher.BeginInvoke(() =>
            {
                GridServices.ItemsSource = srv;
                GridStartup.ItemsSource = stp;
            });
        });
    }

    private void RadioServicesSubTab_Click(object sender, RoutedEventArgs e)
    {
        bool isSrv = RadioServices.IsChecked == true;
        GridServices.Visibility = isSrv ? Visibility.Visible : Visibility.Collapsed;
        GridStartup.Visibility = isSrv ? Visibility.Collapsed : Visibility.Visible;
    }

    private void BtnRefreshServices_Click(object sender, RoutedEventArgs e) => RefreshServicesAndStartup();

    // ==================== HUD OVERLAY & TRAY ====================
    private void BtnToggleOverlay_Click(object sender, RoutedEventArgs e) => ToggleOverlay();

    void ToggleOverlay()
    {
        if (_overlay.IsVisible) _overlay.Hide();
        else _overlay.Show();
        _settings.OverlayEnabled = _overlay.IsVisible;
        CfgOverlay.IsChecked = _overlay.IsVisible;
        _settings.Save();
    }

    void ShowAndRestore()
    {
        Show();
        WindowState = WindowState.Normal;
        Activate();
    }

    void ShowTrayMenu()
    {
        var menu = new ContextMenu();
        var miOpen = new MenuItem { Header = "Abrir ProcessHunter" };
        miOpen.Click += (s, e) => ShowAndRestore();
        var miHud = new MenuItem { Header = "Exibir / Ocultar HUD Overlay" };
        miHud.Click += (s, e) => ToggleOverlay();
        var miExit = new MenuItem { Header = "Sair" };
        miExit.Click += (s, e) => ExitApplication();
        menu.Items.Add(miOpen);
        menu.Items.Add(miHud);
        menu.Items.Add(new Separator());
        menu.Items.Add(miExit);
        menu.IsOpen = true;
    }

    void ExitApplication()
    {
        _isClosingReal = true;
        _trayIcon.Dispose();
        _engine.Dispose();
        _overlay.Close();
        Close();
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_isClosingReal && _settings.MinimizeToTray)
        {
            e.Cancel = true;
            Hide();
            if (_settings.NotificationsEnabled)
                _trayIcon.ShowNotification("ProcessHunter", "ProcessHunter continua monitorando em segundo plano.", 1);
        }
        else
        {
            _trayIcon.Dispose();
            _engine.Dispose();
            _overlay.Close();
            base.OnClosing(e);
        }
    }

    void OnFindingRaised(Finding f)
    {
        if (!_settings.NotificationsEnabled) return;
        Dispatcher.BeginInvoke(() =>
        {
            int flag = f.Severity == Severity.Critical ? 3 : f.Severity == Severity.Warning ? 2 : 1;
            _trayIcon.ShowNotification(f.Title, f.Explanation, flag);
        });
    }

    void OnWatchEvent(string msg)
    {
        if (!_settings.NotificationsEnabled) return;
        Dispatcher.BeginInvoke(() =>
        {
            _trayIcon.ShowNotification("Processo Monitorado", msg, 1);
        });
    }

    // ==================== CONFIGURAÇÕES ====================
    private void BtnLightMode_Click(object sender, RoutedEventArgs e)
    {
        if (!_isReady) return;
        _settings.LightMode = BtnLightMode.IsChecked == true;
        _settings.Save();
    }

    private void CmbInterval_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_isReady || _settings == null || _engine == null) return;
        if (CmbInterval.SelectedItem is ComboBoxItem item && int.TryParse(item.Tag?.ToString(), out int ms))
        {
            _settings.IntervalMs = ms;
            _settings.Save();
            _engine.Wake();
        }
    }

    private void CfgInterval_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_isReady || _settings == null || _engine == null) return;
        if (CfgInterval.SelectedItem is ComboBoxItem item && int.TryParse(item.Tag?.ToString(), out int ms))
        {
            _settings.IntervalMs = ms;
            _settings.Save();
            _engine.Wake();
        }
    }

    private void CfgRetention_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_isReady || _settings == null) return;
        if (CfgRetention.SelectedItem is ComboBoxItem item && int.TryParse(item.Tag?.ToString(), out int days))
        {
            _settings.RetentionDays = days;
            _settings.Save();
        }
    }

    private void CfgOverlay_Changed(object sender, RoutedEventArgs e)
    {
        if (!_isReady || _settings == null || _overlay == null) return;
        bool on = CfgOverlay.IsChecked == true;
        _settings.OverlayEnabled = on;
        _settings.Save();
        if (on && !_overlay.IsVisible) _overlay.Show();
        else if (!on && _overlay.IsVisible) _overlay.Hide();
    }

    private void Cfg_Changed(object sender, RoutedEventArgs e)
    {
        if (!_isReady || _settings == null) return;
        _settings.AutoLightWhenFullscreen = CfgAutoLight.IsChecked == true;
        _settings.MinimizeToTray = CfgMinimizeTray.IsChecked == true;
        _settings.NotificationsEnabled = CfgNotifications.IsChecked == true;
        _settings.Save();
    }

    private void BtnAddWatch_Click(object sender, RoutedEventArgs e)
    {
        string name = TxtAddWatch.Text.Trim();
        if (string.IsNullOrEmpty(name)) return;
        if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) name += ".exe";
        if (!_settings.WatchedProcesses.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            _settings.WatchedProcesses.Add(name);
            ListWatched.Items.Add(name);
            _settings.Save();
            TxtAddWatch.Clear();
        }
    }

    private void BtnRemoveWatch_Click(object sender, RoutedEventArgs e)
    {
        if (ListWatched.SelectedItem is string sel)
        {
            _settings.WatchedProcesses.Remove(sel);
            ListWatched.Items.Remove(sel);
            _settings.Save();
        }
    }
}
