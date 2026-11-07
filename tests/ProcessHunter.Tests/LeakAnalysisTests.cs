using ProcessHunter.Diagnostics;
using Xunit;

namespace ProcessHunter.Tests;

public class LeakAnalysisTests
{
    [Fact]
    public void MonotonicGrowth_IsDetectedAsSuspectedLeak()
    {
        // 60 pontos (1 a cada 10s = 10 minutos de monitoramento)
        // Memória cresce linearmente de 100 MB para 400 MB (+300 MB)
        int points = 60;
        float[] series = new float[points];
        for (int i = 0; i < points; i++)
        {
            series[i] = 100_000_000f + i * 5_000_000f; // +5 MB a cada 10s
        }

        var res = LeakAnalysis.Analyze(series, stepSeconds: 10, minWindowMinutes: 10, minGrowthBytes: 150e6, minGrowthRatio: 0.2);

        Assert.True(res.Suspected);
        Assert.True(res.R2 >= 0.85, $"R2 deveria ser alto, foi {res.R2}");
        Assert.True(res.SlopeBytesPerMin > 0);
        Assert.True(res.GrowthBytes >= 150_000_000);
    }

    [Fact]
    public void GarbageCollectionPattern_IsNotFlaggedAsLeak()
    {
        // Memória sobe e é liberada ciclicamente (padrão típico de GC / cache saudável)
        int points = 60;
        float[] series = new float[points];
        for (int i = 0; i < points; i++)
        {
            int phase = i % 10;
            series[i] = 100_000_000f + phase * 20_000_000f;
        }

        var res = LeakAnalysis.Analyze(series, stepSeconds: 10, minWindowMinutes: 10, minGrowthBytes: 50e6, minGrowthRatio: 0.2);

        Assert.False(res.Suspected);
    }

    [Fact]
    public void ShortWindow_ReturnsInsufficientWindow()
    {
        // Apenas 2 minutos de amostragem
        float[] series = new float[12];
        for (int i = 0; i < series.Length; i++) series[i] = 100_000_000f + i * 10_000_000f;

        var res = LeakAnalysis.Analyze(series, stepSeconds: 10, minWindowMinutes: 10);

        Assert.False(res.Suspected);
        Assert.Contains("insuficiente", res.Reason, StringComparison.OrdinalIgnoreCase);
    }
}
