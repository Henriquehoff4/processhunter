using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProcessHunter.Core;

public sealed class Settings
{
    public int IntervalMs { get; set; } = 1000;
    public bool LightMode { get; set; }
    public bool AutoLightWhenFullscreen { get; set; } = true;
    public int RetentionDays { get; set; } = 7;
    public bool HistoryEnabled { get; set; } = true;
    public bool CompactMode { get; set; }
    public bool MinimizeToTray { get; set; } = true;
    public bool StartWithWindows { get; set; }
    public bool NotificationsEnabled { get; set; } = true;
    public bool OverlayEnabled { get; set; }
    public double OverlayOpacity { get; set; } = 0.85;
    public int CpuTempWarn { get; set; } = 85;
    public int GpuTempWarn { get; set; } = 83;
    public int RamWarnPercent { get; set; } = 90;
    public int VramWarnPercent { get; set; } = 90;
    public int CpuWarnPercent { get; set; } = 90;
    public bool ConfirmKill { get; set; } = true;
    public bool DeepSensorsEnabled { get; set; } = true;
    public int DeepSensorsIntervalMs { get; set; } = 2000;
    public List<string> WatchedProcesses { get; set; } = new();
    public double WindowLeft { get; set; } = double.NaN;
    public double WindowTop { get; set; } = double.NaN;
    public double WindowWidth { get; set; } = 1400;
    public double WindowHeight { get; set; } = 860;

    public static readonly int[] AllowedIntervals = { 500, 1000, 2000, 5000 };

    [JsonIgnore] public static string DataDir { get; private set; } = "";
    [JsonIgnore] static string FilePath => Path.Combine(DataDir, "settings.json");

    public static void InitDataDir()
    {
        // Modo portátil: arquivo "portable.flag" ao lado do executável.
        var baseDir = AppContext.BaseDirectory;
        DataDir = File.Exists(Path.Combine(baseDir, "portable.flag"))
            ? Path.Combine(baseDir, "data")
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ProcessHunter");
        Directory.CreateDirectory(DataDir);
    }

    public static Settings Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var s = JsonSerializer.Deserialize<Settings>(File.ReadAllText(FilePath));
                if (s != null) { s.Sanitize(); return s; }
            }
        }
        catch { /* arquivo corrompido: usa padrões */ }
        return new Settings();
    }

    public void Sanitize()
    {
        if (!AllowedIntervals.Contains(IntervalMs)) IntervalMs = 1000;
        RetentionDays = Math.Clamp(RetentionDays, 1, 365);
        OverlayOpacity = Math.Clamp(OverlayOpacity, 0.3, 1.0);
        WatchedProcesses ??= new();
    }

    public void Save()
    {
        try
        {
            var tmp = FilePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(tmp, FilePath, true);
        }
        catch { }
    }
}
