using ProcessHunter.Collectors;
using ProcessHunter.Core;
using Xunit;

namespace ProcessHunter.Tests;

public class CollectorsTests
{
    [Fact]
    public void ProcessCollector_CollectsRealProcessesViaNtQuery()
    {
        using var pc = new ProcessCollector();
        var raw = new List<RawProc>();

        bool ok = pc.TryCollect(raw);

        Assert.True(ok, "NtQuerySystemInformation deveria coletar com sucesso");
        Assert.True(raw.Count > 10, "Deveria haver pelo menos 10 processos no sistema operacional");
        Assert.Contains(raw, p => p.Pid == 4); // Processo System
        Assert.Contains(raw, p => p.Name.Contains("explorer", StringComparison.OrdinalIgnoreCase) || p.Pid == Environment.ProcessId);
    }

    [Fact]
    public void SystemCollector_ReadsRealMetricsWithoutWmi()
    {
        using var sc = new SystemCollector();
        var sample = new SystemSample();

        sc.Fill(sample);

        Assert.True(sample.CpuCores.Length > 0, "Deveria haver pelo menos 1 núcleo de CPU detectado");
        Assert.True(sample.MemTotal > 0, "Memória total física deveria ser maior que 0");
        Assert.True(sample.MemAvail > 0, "Memória disponível física deveria ser maior que 0");
        Assert.True(sample.Uptime.TotalSeconds > 0, "Tempo de atividade do computador deveria ser positivo");
        Assert.False(string.IsNullOrWhiteSpace(sc.CpuName), "Nome do processador deveria ser preenchido");
    }

    [Fact]
    public void ServicesProvider_EnumeratesWindowsServices()
    {
        var services = ServicesProvider.GetAll();

        Assert.NotEmpty(services);
        // Serviços padrão essenciais do Windows
        Assert.Contains(services, s => s.Name.Equals("RpcSs", StringComparison.OrdinalIgnoreCase) ||
                                       s.Name.Equals("Dnscache", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void StartupProvider_ReadsStartupPrograms()
    {
        var startup = StartupProvider.GetAll();
        // Não quebra se a máquina tiver poucos itens de inicialização, apenas valida a execução segura
        Assert.NotNull(startup);
    }
}
