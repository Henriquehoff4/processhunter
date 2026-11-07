using System.Globalization;
using System.Windows;
using System.Windows.Media;
using Brush = System.Windows.Media.Brush;
using Pen = System.Windows.Media.Pen;
using Point = System.Windows.Point;

namespace ProcessHunter.Controls;

/// <summary>
/// Visualizador de todos os núcleos lógicos da CPU em grade compacta e ultra rápida.
/// </summary>
public sealed class MultiCoreView : FrameworkElement
{
    public static readonly DependencyProperty CoresProperty =
        DependencyProperty.Register(nameof(Cores), typeof(double[]), typeof(MultiCoreView),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public double[]? Cores { get => (double[]?)GetValue(CoresProperty); set => SetValue(CoresProperty, value); }

    static readonly Brush BgTile = new SolidColorBrush(Color.FromArgb(255, 40, 34, 28));
    static readonly Brush BorderTile = new SolidColorBrush(Color.FromArgb(255, 52, 44, 37));
    static readonly Brush LowBrush = new SolidColorBrush(Color.FromArgb(150, 98, 184, 166));
    static readonly Brush MidBrush = new SolidColorBrush(Color.FromArgb(150, 166, 194, 94));
    static readonly Brush HighBrush = new SolidColorBrush(Color.FromArgb(170, 233, 176, 74));
    static readonly Brush CritBrush = new SolidColorBrush(Color.FromArgb(190, 240, 102, 92));
    static readonly Brush TextMuted = new SolidColorBrush(Color.FromArgb(255, 242, 232, 218));
    static readonly Pen TilePen = new(BorderTile, 1.0);
    static readonly Typeface Tf = new(new FontFamily("Segoe UI Variable Text, Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal);

    static MultiCoreView()
    {
        BgTile.Freeze();
        BorderTile.Freeze();
        LowBrush.Freeze();
        MidBrush.Freeze();
        HighBrush.Freeze();
        CritBrush.Freeze();
        TextMuted.Freeze();
        TilePen.Freeze();
    }

    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc);
        var cores = Cores;
        if (cores == null || cores.Length == 0) return;

        double w = ActualWidth;
        double h = ActualHeight;
        if (w < 10 || h < 10) return;

        int total = cores.Length;
        // Calcula colunas e linhas ideais
        int cols = total <= 8 ? total : total <= 16 ? 8 : total <= 24 ? 8 : 12;
        int rows = (int)Math.Ceiling((double)total / cols);

        double gap = 4.0;
        double tileW = Math.Max(10, (w - gap * (cols - 1)) / cols);
        double tileH = Math.Max(10, (h - gap * (rows - 1)) / rows);

        for (int i = 0; i < total; i++)
        {
            int r = i / cols;
            int c = i % cols;
            double x = c * (tileW + gap);
            double y = r * (tileH + gap);

            double pct = Math.Clamp(cores[i], 0, 100);
            Brush fillBrush = pct >= 90 ? CritBrush : pct >= 70 ? HighBrush : pct >= 30 ? MidBrush : LowBrush;

            // Fundo do tile
            Rect tileRect = new(x, y, tileW, tileH);
            dc.DrawRoundedRectangle(BgTile, TilePen, tileRect, 4, 4);

            // Barra de preenchimento vertical (de baixo para cima)
            double fillHeight = (pct / 100.0) * (tileH - 2);
            if (fillHeight > 0)
            {
                Rect fillRect = new(x + 1, y + tileH - 1 - fillHeight, tileW - 2, fillHeight);
                dc.DrawRoundedRectangle(fillBrush, null, fillRect, 2, 2);
            }

            // Label de porcentagem e índice do núcleo se houver espaço
            if (tileW >= 32 && tileH >= 22)
            {
                string text = $"{pct:0}%";
                var ft = new FormattedText(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, Tf, 9.5, TextMuted, 1.0);
                dc.DrawText(ft, new Point(x + (tileW - ft.Width) / 2, y + (tileH - ft.Height) / 2));
            }
        }
    }
}
