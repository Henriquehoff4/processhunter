using System.IO;
using ProcessHunter.Core;
using Xunit;

namespace ProcessHunter.Tests;

public class HistoryAndExporterTests
{
    [Fact]
    public void ExporterSafe_PreventsExcelFormulaInjection()
    {
        Assert.Equal("'=cmd|' /C calc'!A0", Exporter.Safe("=cmd|' /C calc'!A0"));
        Assert.Equal("'+123", Exporter.Safe("+123"));
        Assert.Equal("'-456", Exporter.Safe("-456"));
        Assert.Equal("'@echo", Exporter.Safe("@echo"));
        Assert.Equal("explorer.exe", Exporter.Safe("explorer.exe"));
    }

    [Fact]
    public void HistoryStore_AppendsAndLoadsWithinRange()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "PH_Test_Hist_" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new HistoryStore(tempDir);
            var now = DateTime.Now;

            var rec1 = new HistRec
            {
                UnixSec = new DateTimeOffset(now.AddMinutes(-5)).ToUnixTimeSeconds(),
                Cpu = 15.2,
                MemPct = 45.0
            };
            var rec2 = new HistRec
            {
                UnixSec = new DateTimeOffset(now).ToUnixTimeSeconds(),
                Cpu = 88.5,
                MemPct = 52.0,
                TopCpu = new List<TopEntry> { new TopEntry { Name = "render.exe", Value = 70.0 } }
            };

            store.Append(rec1);
            store.Append(rec2);

            var loaded = store.Load(now.AddHours(-1), now.AddHours(1));
            Assert.Equal(2, loaded.Count);

            var peak = HistoryStore.FindPeak(loaded, r => r.Cpu, r => r.TopCpu);
            Assert.NotNull(peak);
            Assert.Equal(88.5, peak.Value.Rec.Cpu);
            Assert.Contains("render.exe", peak.Value.Culprit);
        }
        finally
        {
            if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true);
        }
    }

    [Fact]
    public void SnapshotDiff_CalculatesResourceIncrementsAccurately()
    {
        var snapA = new Snapshot
        {
            Time = DateTime.Now.AddMinutes(-1),
            Cpu = 10,
            MemPct = 30,
            ByName = new Dictionary<string, (double Cpu, long Mem, long Vram, double Gpu)>(StringComparer.OrdinalIgnoreCase)
            {
                ["existing.exe"] = (5.0, 100_000_000, 0, 0)
            }
        };

        var snapB = new Snapshot
        {
            Time = DateTime.Now,
            Cpu = 70,
            MemPct = 45,
            ByName = new Dictionary<string, (double Cpu, long Mem, long Vram, double Gpu)>(StringComparer.OrdinalIgnoreCase)
            {
                ["existing.exe"] = (10.0, 150_000_000, 0, 0),
                ["new_app.exe"] = (55.0, 800_000_000, 500_000_000, 40.0)
            }
        };

        var diff = Snapshot.Diff(snapA, snapB);

        var newAppDiff = diff.FirstOrDefault(d => d.Name == "new_app.exe");
        Assert.NotNull(newAppDiff);
        Assert.True(newAppDiff.IsNew);
        Assert.Equal(55.0, newAppDiff.DCpu);
        Assert.Equal(800_000_000, newAppDiff.DMem);
        Assert.Equal(500_000_000, newAppDiff.DVram);
        Assert.Equal(40.0, newAppDiff.DGpu);
    }
}
