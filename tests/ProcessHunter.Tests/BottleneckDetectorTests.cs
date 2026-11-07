using ProcessHunter.Core;
using ProcessHunter.Diagnostics;
using Xunit;

namespace ProcessHunter.Tests;

public class BottleneckDetectorTests
{
    [Fact]
    public void IsHeavyByDesign_RecognizesCreativeAndAiWorkloads()
    {
        Assert.True(BottleneckDetector.IsHeavyByDesign("afterfx.exe"));
        Assert.True(BottleneckDetector.IsHeavyByDesign("aerender.exe"));
        Assert.True(BottleneckDetector.IsHeavyByDesign("blender.exe"));
        Assert.True(BottleneckDetector.IsHeavyByDesign("ollama_app.exe"));
        Assert.True(BottleneckDetector.IsHeavyByDesign("comfyui.exe"));
        Assert.False(BottleneckDetector.IsHeavyByDesign("notepad.exe"));
    }

    [Fact]
    public void ContextNote_ExplainsAntivirusAndSystemBehavior()
    {
        var note = BottleneckDetector.NoteFor("MsMpEng.exe");
        Assert.NotNull(note);
        Assert.Contains("Microsoft Defender", note);

        var dwmNote = BottleneckDetector.NoteFor("dwm.exe");
        Assert.NotNull(dwmNote);
        Assert.Contains("GPU", dwmNote);
    }

    [Fact]
    public void CpuSaturation_DetectsSustainedLoad()
    {
        var detector = new BottleneckDetector();
        var rings = new SystemRings();

        // Alimenta 40 amostras com CPU em 98%
        for (int i = 0; i < 40; i++) rings.Cpu.Add(98.0f);

        var sys = new SystemSample
        {
            CpuTotal = 98.0,
            CpuCores = new double[] { 98, 98, 98, 98 }
        };

        var input = new DetectorInput
        {
            Sys = sys,
            Procs = new List<ProcSample>(),
            Rings = rings,
            Settings = new Settings { CpuWarnPercent = 90 },
            IntervalSec = 1.0,
            Now = DateTime.Now
        };

        detector.Evaluate(input);
        // Avança tempo para simular histerese (12 segundos depois)
        input.Now = input.Now.AddSeconds(12);
        detector.Evaluate(input);

        Assert.Contains(detector.Active, f => f.Category == "CPU" && f.Title.Contains("saturada"));
    }

    [Fact]
    public void RamSaturation_DetectsLowMemory()
    {
        var detector = new BottleneckDetector();
        var rings = new SystemRings();

        for (int i = 0; i < 40; i++) rings.Mem.Add(94.0f);

        var sys = new SystemSample
        {
            MemTotal = 32L * 1024 * 1024 * 1024,
            MemAvail = 1L * 1024 * 1024 * 1024
        };

        var input = new DetectorInput
        {
            Sys = sys,
            Procs = new List<ProcSample>(),
            Rings = rings,
            Settings = new Settings { RamWarnPercent = 90 },
            IntervalSec = 1.0,
            Now = DateTime.Now
        };

        detector.Evaluate(input);
        input.Now = input.Now.AddSeconds(8);
        detector.Evaluate(input);

        Assert.Contains(detector.Active, f => f.Category == "Memória");
    }
}
