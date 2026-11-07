using System.Diagnostics;
using System.IO;
using System.Windows;
using ProcessHunter.Core;

namespace ProcessHunter;

public partial class App : System.Windows.Application
{
    private static Mutex? _singleInstanceMutex;
    private static bool _ownsMutex;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Garante instância única por sessão
        const string mutexName = @"Local\ProcessHunter_SingleInstance_Mutex_Session";
        bool afterElevation = e.Args.Contains("--elevated");
        _singleInstanceMutex = new Mutex(false, mutexName);
        try { _ownsMutex = _singleInstanceMutex.WaitOne(afterElevation ? 10000 : 0); }
        catch (AbandonedMutexException) { _ownsMutex = true; }
        if (!_ownsMutex)
        {
            MessageBox.Show("O ProcessHunter já está em execução no seu computador.\nVerifique a bandeja do sistema (System Tray) ao lado do relógio do Windows.",
                "ProcessHunter Já em Execução", MessageBoxButton.OK, MessageBoxImage.Information);
            Shutdown();
            return;
        }

        // Tratamento global de exceções não tratadas
        AppDomain.CurrentDomain.UnhandledException += (s, args) =>
        {
            LogCrash(args.ExceptionObject as Exception);
        };

        DispatcherUnhandledException += (s, args) =>
        {
            LogCrash(args.Exception);
            MessageBox.Show($"Ocorreu um erro no ProcessHunter:\n\n{args.Exception?.Message}\n\nDetalhes gravados em %APPDATA%\\ProcessHunter\\crash.log",
                "Erro — ProcessHunter", MessageBoxButton.OK, MessageBoxImage.Error);
            args.Handled = true;
        };
    }

    private static void LogCrash(Exception? ex)
    {
        if (ex == null) return;
        try
        {
            string crashDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ProcessHunter");
            Directory.CreateDirectory(crashDir);
            string crashFile = Path.Combine(crashDir, "crash.log");
            File.AppendAllText(crashFile, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {ex}\n\n");
        }
        catch { }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_ownsMutex) { try { _singleInstanceMutex?.ReleaseMutex(); } catch { } }
        _singleInstanceMutex?.Dispose();
        base.OnExit(e);
    }
}
