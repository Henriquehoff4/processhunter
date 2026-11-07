using System.Windows;
using System.Windows.Input;
using ProcessHunter.Core;

namespace ProcessHunter;

public partial class OverlayWindow : Window
{
    public OverlayWindow()
    {
        InitializeComponent();
        Left = SystemParameters.WorkArea.Right - Width - 30;
        Top = 30;
    }

    public void UpdateMetrics(SystemSample sys)
    {
        TxtCpu.Text = $"{sys.CpuTotal:0}%";
        TxtRam.Text = $"{sys.MemPercent:0}%";
        TxtGpu.Text = sys.Gpu.Utilization.HasValue ? $"{sys.Gpu.Utilization.Value:0}%" : "—";
        if (sys.Gpu.VramTotal is > 0 && sys.Gpu.VramUsed.HasValue)
        {
            double vpct = 100.0 * sys.Gpu.VramUsed.Value / sys.Gpu.VramTotal.Value;
            TxtVram.Text = $"{vpct:0}%";
        }
        else
        {
            TxtVram.Text = "—";
        }

        TxtTemp.Text = sys.Gpu.Temperature.HasValue ? $"{sys.Gpu.Temperature.Value:0}°" : "—";
        TxtDisk.Text = $"{((sys.DiskReadBps + sys.DiskWriteBps) / 1048576.0):0.#}M";
    }

    private void Border_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ChangedButton == MouseButton.Left)
        {
            DragMove();
        }
    }

    private void BtnClose_Click(object sender, RoutedEventArgs e)
    {
        Hide();
    }
}
