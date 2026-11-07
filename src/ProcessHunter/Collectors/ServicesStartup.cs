using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using ProcessHunter.Core;
using ProcessHunter.Native;

namespace ProcessHunter.Collectors;

public sealed record ServiceRow(string Name, string Display, string State, string StartType, int Pid, string Type);
public sealed record StartupRow(string Name, string Command, string Location, bool Enabled, string Scope);

internal static class ServicesProvider
{
    [DllImport("advapi32.dll", SetLastError = true)] static extern IntPtr OpenSCManagerW(string? m, string? d, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool CloseServiceHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool EnumServicesStatusExW(IntPtr h, int infoLevel, uint type, uint state, IntPtr buf, uint size, out uint needed, out uint count, ref uint resume, string? group);

    public static List<ServiceRow> GetAll()
    {
        var list = new List<ServiceRow>();
        var scm = OpenSCManagerW(null, null, 0x0004 /*ENUMERATE_SERVICE*/);
        if (scm == IntPtr.Zero) return list;
        try
        {
            uint resume = 0, needed = 0, count = 0;
            EnumServicesStatusExW(scm, 0, 0x30 /*WIN32*/, 3 /*ALL*/, IntPtr.Zero, 0, out needed, out count, ref resume, null);
            var buf = Marshal.AllocHGlobal((int)needed + 4096);
            try
            {
                resume = 0;
                if (!EnumServicesStatusExW(scm, 0, 0x30, 3, buf, needed + 4096, out _, out count, ref resume, null)) return list;
                int entry = 56;
                using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
                for (int i = 0; i < count; i++)
                {
                    var p = buf + i * entry;
                    var name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(p)) ?? "";
                    var disp = Marshal.PtrToStringUni(Marshal.ReadIntPtr(p, 8)) ?? "";
                    int type = Marshal.ReadInt32(p, 16), state = Marshal.ReadInt32(p, 20), pid = Marshal.ReadInt32(p, 44);
                    string start = "—";
                    try
                    {
                        using var k = root?.OpenSubKey(name);
                        if (k?.GetValue("Start") is int s)
                        {
                            start = s switch { 0 => "Boot", 1 => "Sistema", 2 => "Automático", 3 => "Manual", 4 => "Desativado", _ => "?" };
                            if (s == 2 && k.GetValue("DelayedAutostart") is int dl && dl == 1) start = "Automático (atrasado)";
                        }
                    }
                    catch { }
                    string st = state switch { 1 => "Parado", 2 => "Iniciando", 3 => "Parando", 4 => "Em execução", 5 => "Continuando", 6 => "Pausando", 7 => "Pausado", _ => "?" };
                    string tp = (type & 0x20) != 0 ? "Compartilhado" : (type & 0x10) != 0 ? "Próprio" : "Driver/Outro";
                    list.Add(new ServiceRow(name, disp, st, start, pid, tp));
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        finally { CloseServiceHandle(scm); }
        return list;
    }
}

internal static class StartupProvider
{
    static readonly (RegistryHive Hive, string Key, string Approved, string Scope)[] Runs =
    {
        (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", "Usuário"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run", "Máquina"),
        (RegistryHive.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32", "Máquina (32 bits)"),
    };

    public static List<StartupRow> GetAll()
    {
        var list = new List<StartupRow>();
        foreach (var (hive, key, approved, scope) in Runs)
        {
            try
            {
                using var bk = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
                using var k = bk.OpenSubKey(key);
                using var ak = bk.OpenSubKey(approved);
                if (k == null) continue;
                foreach (var n in k.GetValueNames())
                {
                    bool en = IsEnabled(ak?.GetValue(n) as byte[]);
                    list.Add(new StartupRow(n, k.GetValue(n)?.ToString() ?? "", (hive == RegistryHive.CurrentUser ? "HKCU" : "HKLM") + @"\Run", en, scope));
                }
            }
            catch { }
        }
        AddFolder(list, Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Pasta Inicializar (usuário)", "Usuário");
        AddFolder(list, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Pasta Inicializar (todos)", "Máquina");
        return list;
    }

    internal static bool IsEnabled(byte[]? data) => data == null || data.Length == 0 || (data[0] & 1) == 0 ? true : false;

    static void AddFolder(List<StartupRow> list, string dir, string loc, string scope)
    {
        try
        {
            if (!Directory.Exists(dir)) return;
            foreach (var f in Directory.EnumerateFiles(dir))
                if (!f.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase)) list.Add(new StartupRow(Path.GetFileNameWithoutExtension(f), f, loc, true, scope));
        }
        catch { }
    }
}

/// <summary>Ações sobre processos, com proteção de processos críticos. Nunca é chamada automaticamente.</summary>
public static class ProcessActions
{
    static readonly HashSet<string> CriticalNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe",
        "svchost.exe", "dwm.exe", "fontdrvhost.exe", "Memory Compression", "MemCompression", "Secure System", "sihost.exe",
        "ctfmon.exe", "explorer.exe", "MsMpEng.exe", "NisSrv.exe", "SecurityHealthService.exe", "wudfhost.exe", "audiodg.exe",
        "spoolsv.exe", "taskhostw.exe", "RuntimeBroker.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe", "SearchHost.exe",
        "Ociosidade do Sistema", "System Idle Process", "conhost.exe", "LsaIso.exe", "WmiPrvSE.exe", "dllhost.exe"
    };

    /// <summary>"Crítico" = encerrar derruba o Windows, a sessão ou a segurança; ou o próprio ProcessHunter.</summary>
    public static bool IsProtected(int pid, string name, out string reason)
    {
        reason = "";
        if (pid <= 4) { reason = "Processo central do kernel do Windows."; return true; }
        if (pid == Environment.ProcessId) { reason = "Este é o próprio ProcessHunter."; return true; }
        if (CriticalNames.Contains(name))
        {
            reason = name.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase)
                ? "Shell do Windows (barra de tarefas e área de trabalho). Reinicie-o pelo Gerenciador de Tarefas do Windows, se necessário."
                : "Componente crítico do Windows ou da segurança; encerrá-lo pode causar tela azul, perda de sessão ou desproteção.";
            return true;
        }
        return false;
    }

    public static ProcessActionResult Kill(int pid, string name, bool tree)
    {
        if (IsProtected(pid, name, out var why)) return ProcessActionResult.Fail("Bloqueado: " + why);
        try
        {
            using var p = Process.GetProcessById(pid);
            if (p.StartTime > DateTime.Now) return ProcessActionResult.Fail("PID reutilizado.");
            p.Kill(tree);
            return ProcessActionResult.Success($"Processo {name} ({pid}) encerrado.");
        }
        catch (ArgumentException) { return ProcessActionResult.Fail("O processo já não existe."); }
        catch (Exception e) { return ProcessActionResult.Fail("Falha ao encerrar: " + e.Message + " (pode exigir execução como administrador)"); }
    }

    public static ProcessActionResult SetPriority(int pid, string name, ProcessPriorityClass cls)
    {
        if (pid <= 4) return ProcessActionResult.Fail("Processo do sistema.");
        if (cls == ProcessPriorityClass.RealTime) return ProcessActionResult.Fail("Prioridade 'Tempo real' foi desativada por segurança: pode travar o sistema.");
        uint v = cls switch
        {
            ProcessPriorityClass.Idle => 0x40, ProcessPriorityClass.BelowNormal => 0x4000, ProcessPriorityClass.Normal => 0x20,
            ProcessPriorityClass.AboveNormal => 0x8000, ProcessPriorityClass.High => 0x80, _ => 0x20
        };
        var h = Win32.OpenProcess(Win32.PROCESS_SET_INFORMATION | Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return ProcessActionResult.Fail("Acesso negado (processo de outro usuário/protegido).");
        try { return Win32.SetPriorityClass(h, v) ? ProcessActionResult.Success("Prioridade alterada.") : ProcessActionResult.Fail("Windows recusou a alteração."); }
        finally { Win32.CloseHandle(h); }
    }

    public static void OpenLocation(string? path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
        Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
    }
}
