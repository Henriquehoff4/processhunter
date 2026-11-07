using ProcessHunter.Collectors;
using Xunit;

namespace ProcessHunter.Tests;

public class ProcessActionsTests
{
    [Theory]
    [InlineData(0, "System")]
    [InlineData(4, "System")]
    [InlineData(100, "smss.exe")]
    [InlineData(200, "csrss.exe")]
    [InlineData(300, "wininit.exe")]
    [InlineData(400, "services.exe")]
    [InlineData(500, "lsass.exe")]
    [InlineData(600, "explorer.exe")]
    [InlineData(700, "dwm.exe")]
    [InlineData(800, "MsMpEng.exe")]
    public void CriticalProcesses_AreProtectedFromTermination(int pid, string name)
    {
        bool protectedResult = ProcessActions.IsProtected(pid, name, out string reason);
        Assert.True(protectedResult, $"Processo {name} (PID {pid}) deveria estar protegido!");
        Assert.False(string.IsNullOrWhiteSpace(reason), "Deveria haver uma explicação para a proteção");

        // Executar Kill deve falhar imediatamente sem tentar encerrar o processo do Windows
        var killResult = ProcessActions.Kill(pid, name, tree: false);
        Assert.False(killResult.Ok);
        Assert.Contains("Bloqueado", killResult.Message);
    }

    [Fact]
    public void CurrentProcess_IsProtectedFromSelfTermination()
    {
        int myPid = Environment.ProcessId;
        bool isProt = ProcessActions.IsProtected(myPid, "ProcessHunter.exe", out string reason);
        Assert.True(isProt);
        Assert.Contains("próprio ProcessHunter", reason);
    }

    [Fact]
    public void NonCriticalProcess_IsNotProtected()
    {
        bool isProt = ProcessActions.IsProtected(99999, "my_custom_tool.exe", out _);
        Assert.False(isProt);
    }
}
