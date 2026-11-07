using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows;
using Microsoft.Win32;

namespace ProcessHunter.Installer;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        TitleBar.ApplyWarmDark(this);
        InitializeComponent();
        string defaultPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Programs", "ProcessHunter");
        TxtPath.Text = defaultPath;
    }

    private void BtnCancel_Click(object sender, RoutedEventArgs e) => Close();

    private async void BtnInstall_Click(object sender, RoutedEventArgs e)
    {
        string targetDir = TxtPath.Text.Trim();
        if (string.IsNullOrEmpty(targetDir)) return;

        BtnInstall.IsEnabled = false;
        BtnCancel.IsEnabled = false;
        PbStatus.Visibility = Visibility.Visible;
        TxtStatus.Text = "Extraindo arquivos do ProcessHunter...";

        // Captura o estado dos checkboxes na thread da UI antes de partir
        // para a thread de segundo plano (controles WPF não podem ser lidos
        // de outra thread).
        bool createDesktop = ChkDesktop.IsChecked == true;
        bool createStartMenu = ChkStartMenu.IsChecked == true;

        try
        {
            await Task.Run(() =>
            {
                Directory.CreateDirectory(targetDir);
                string exePath = Path.Combine(targetDir, "ProcessHunter.exe");

                // Extrai recurso embutido
                var asm = Assembly.GetExecutingAssembly();
                string? resName = asm.GetManifestResourceNames().FirstOrDefault(n => n.EndsWith("ProcessHunter.exe", StringComparison.OrdinalIgnoreCase));
                if (resName != null)
                {
                    using var stream = asm.GetManifestResourceStream(resName);
                    if (stream != null)
                    {
                        using var fs = new FileStream(exePath, FileMode.Create, FileAccess.Write);
                        stream.CopyTo(fs);
                    }
                }

                // Cria Desinstalador simples
                string uninstallerPath = Path.Combine(targetDir, "Uninstall.cmd");
                File.WriteAllText(uninstallerPath, $@"@echo off
taskkill /F /IM ProcessHunter.exe >nul 2>&1
timeout /t 1 /nobreak >nul
reg delete ""HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\ProcessHunter"" /f >nul 2>&1
del /q ""{Environment.GetFolderPath(Environment.SpecialFolder.Desktop)}\ProcessHunter.lnk"" >nul 2>&1
del /q ""{Environment.GetFolderPath(Environment.SpecialFolder.StartMenu)}\Programs\ProcessHunter.lnk"" >nul 2>&1
rmdir /s /q ""{targetDir}"" >nul 2>&1
echo ProcessHunter foi desinstalado com sucesso.
pause
");

                // Atalhos via WScript
                if (createDesktop)
                {
                    string desktopLink = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "ProcessHunter.lnk");
                    CreateShortcut(desktopLink, exePath, targetDir);
                }

                if (createStartMenu)
                {
                    string startMenu = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.StartMenu), "Programs");
                    Directory.CreateDirectory(startMenu);
                    string startLink = Path.Combine(startMenu, "ProcessHunter.lnk");
                    CreateShortcut(startLink, exePath, targetDir);
                }

                // Registro no Adicionar/Remover Programas
                RegisterUninstall(targetDir, exePath, uninstallerPath);
            });

            TxtStatus.Text = "Instalação concluída com sucesso!";

            if (ChkLaunch.IsChecked == true)
            {
                string exePath = Path.Combine(targetDir, "ProcessHunter.exe");
                if (File.Exists(exePath))
                {
                    Process.Start(new ProcessStartInfo(exePath) { UseShellExecute = true });
                }
            }

            MessageBox.Show("ProcessHunter foi instalado com sucesso!", "ProcessHunter", MessageBoxButton.OK, MessageBoxImage.Information);
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show("Erro durante a instalação: " + ex.Message, "Falha na Instalação", MessageBoxButton.OK, MessageBoxImage.Error);
            BtnInstall.IsEnabled = true;
            BtnCancel.IsEnabled = true;
            PbStatus.Visibility = Visibility.Collapsed;
        }
    }

    static void CreateShortcut(string shortcutPath, string targetPath, string workingDir)
    {
        try
        {
            Type? shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return;
            dynamic? shell = Activator.CreateInstance(shellType);
            if (shell == null) return;
            dynamic shortcut = shell.CreateShortcut(shortcutPath);
            shortcut.TargetPath = targetPath;
            shortcut.WorkingDirectory = workingDir;
            shortcut.Description = "ProcessHunter — Ultimate System Monitor";
            shortcut.Save();
        }
        catch { }
    }

    static void RegisterUninstall(string installDir, string exePath, string uninstallerPath)
    {
        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\ProcessHunter");
            key.SetValue("DisplayName", "ProcessHunter — Ultimate System Monitor");
            key.SetValue("DisplayVersion", "1.0.0");
            key.SetValue("Publisher", "ProcessHunter");
            key.SetValue("InstallLocation", installDir);
            key.SetValue("DisplayIcon", exePath);
            key.SetValue("UninstallString", $"cmd.exe /c \"{uninstallerPath}\"");
            key.SetValue("NoModify", 1);
            key.SetValue("NoRepair", 1);
        }
        catch { }
    }
}
