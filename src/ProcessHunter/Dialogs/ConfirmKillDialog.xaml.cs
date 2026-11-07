using System.Windows;

namespace ProcessHunter.Dialogs;

public partial class ConfirmKillDialog : Window
{
    public bool Confirmed { get; private set; }

    public ConfirmKillDialog(string processName, int pid, bool isTree)
    {
        InitializeComponent();
        TxtProcName.Text = isTree ? $"Árvore de Processos: {processName}" : $"Processo: {processName}";
        TxtPid.Text = $"PID: {pid} · Encerrar dependentes: {(isTree ? "Sim (Árvore completa)" : "Não")}";
        if (isTree)
        {
            TxtSub.Text = "Todos os processos filhos associados também serão finalizados.";
        }
    }

    private void BtnCancel_Click(object sender, RoutedEventArgs e)
    {
        Confirmed = false;
        DialogResult = false;
        Close();
    }

    private void BtnConfirm_Click(object sender, RoutedEventArgs e)
    {
        Confirmed = true;
        DialogResult = true;
        Close();
    }
}
