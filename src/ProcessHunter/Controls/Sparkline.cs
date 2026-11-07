using System.Globalization;
using System.Windows;
using System.Windows.Media;
using Brush = System.Windows.Media.Brush;
using Pen = System.Windows.Media.Pen;
using Point = System.Windows.Point;

namespace ProcessHunter.Controls;

/// <summary>
/// Controle de alta performance para gráficos em tempo real via Direct DrawingContext.
/// Zero alocações pesadas, suporte a gradiente de fundo, linhas de grade e valor máximo fixo ou automático.
/// </summary>
public sealed class Sparkline : FrameworkElement
{
    public static readonly DependencyProperty ValuesProperty =
        DependencyProperty.Register(nameof(Values), typeof(float[]), typeof(Sparkline),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty StrokeProperty =
        DependencyProperty.Register(nameof(Stroke), typeof(Brush), typeof(Sparkline),
            new FrameworkPropertyMetadata(new SolidColorBrush(Color.FromRgb(232, 120, 75)), FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty FillBrushProperty =
        DependencyProperty.Register(nameof(FillBrush), typeof(Brush), typeof(Sparkline),
            new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty StrokeThicknessProperty =
        DependencyProperty.Register(nameof(StrokeThickness), typeof(double), typeof(Sparkline),
            new FrameworkPropertyMetadata(1.5, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty MaxValueProperty =
        DependencyProperty.Register(nameof(MaxValue), typeof(double), typeof(Sparkline),
            new FrameworkPropertyMetadata(100.0, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty MinValueProperty =
        DependencyProperty.Register(nameof(MinValue), typeof(double), typeof(Sparkline),
            new FrameworkPropertyMetadata(0.0, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty AutoScaleProperty =
        DependencyProperty.Register(nameof(AutoScale), typeof(bool), typeof(Sparkline),
            new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ShowGridLinesProperty =
        DependencyProperty.Register(nameof(ShowGridLines), typeof(bool), typeof(Sparkline),
            new FrameworkPropertyMetadata(true, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty ShowCurrentValueProperty =
        DependencyProperty.Register(nameof(ShowCurrentValue), typeof(bool), typeof(Sparkline),
            new FrameworkPropertyMetadata(false, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty UnitProperty =
        DependencyProperty.Register(nameof(Unit), typeof(string), typeof(Sparkline),
            new FrameworkPropertyMetadata("%", FrameworkPropertyMetadataOptions.AffectsRender));

    public float[]? Values { get => (float[]?)GetValue(ValuesProperty); set => SetValue(ValuesProperty, value); }
    public Brush Stroke { get => (Brush)GetValue(StrokeProperty); set => SetValue(StrokeProperty, value); }
    public Brush? FillBrush { get => (Brush?)GetValue(FillBrushProperty); set => SetValue(FillBrushProperty, value); }
    public double StrokeThickness { get => (double)GetValue(StrokeThicknessProperty); set => SetValue(StrokeThicknessProperty, value); }
    public double MaxValue { get => (double)GetValue(MaxValueProperty); set => SetValue(MaxValueProperty, value); }
    public double MinValue { get => (double)GetValue(MinValueProperty); set => SetValue(MinValueProperty, value); }
    public bool AutoScale { get => (bool)GetValue(AutoScaleProperty); set => SetValue(AutoScaleProperty, value); }
    public bool ShowGridLines { get => (bool)GetValue(ShowGridLinesProperty); set => SetValue(ShowGridLinesProperty, value); }
    public bool ShowCurrentValue { get => (bool)GetValue(ShowCurrentValueProperty); set => SetValue(ShowCurrentValueProperty, value); }
    public string Unit { get => (string)GetValue(UnitProperty); set => SetValue(UnitProperty, value); }

    static readonly Pen GridPen;
    static readonly Brush TextBrush = new SolidColorBrush(Color.FromArgb(215, 184, 170, 154));
    static readonly Typeface Tf = new(new FontFamily("Segoe UI Variable Text, Segoe UI"), FontStyles.Normal, FontWeights.Normal, FontStretches.Normal);

    static Sparkline()
    {
        GridPen = new Pen(new SolidColorBrush(Color.FromArgb(24, 255, 235, 214)), 1.0);
        GridPen.Freeze();
        TextBrush.Freeze();
    }

    protected override void OnRender(DrawingContext dc)
    {
        base.OnRender(dc);
        double w = ActualWidth;
        double h = ActualHeight;
        if (w <= 2 || h <= 2) return;

        // Linhas sutis de grade
        if (ShowGridLines)
        {
            dc.DrawLine(GridPen, new Point(0, h * 0.25), new Point(w, h * 0.25));
            dc.DrawLine(GridPen, new Point(0, h * 0.50), new Point(w, h * 0.50));
            dc.DrawLine(GridPen, new Point(0, h * 0.75), new Point(w, h * 0.75));
        }

        var data = Values;
        if (data == null || data.Length < 2) return;

        double min = MinValue;
        double max = MaxValue;
        if (AutoScale)
        {
            float dmin = float.MaxValue, dmax = float.MinValue;
            for (int i = 0; i < data.Length; i++)
            {
                if (data[i] < dmin) dmin = data[i];
                if (data[i] > dmax) dmax = data[i];
            }
            if (dmax > dmin)
            {
                min = Math.Max(0, dmin * 0.9);
                max = dmax * 1.1;
            }
            else
            {
                max = Math.Max(1.0, dmax * 1.2);
            }
        }
        double range = Math.Max(0.0001, max - min);

        int count = data.Length;
        double stepX = w / (count - 1);

        var strokePen = new Pen(Stroke, StrokeThickness);
        strokePen.StartLineCap = PenLineCap.Round;
        strokePen.EndLineCap = PenLineCap.Round;
        strokePen.LineJoin = PenLineJoin.Round;

        var geom = new StreamGeometry();
        using (var ctx = geom.Open())
        {
            Point firstPt = new(0, Math.Clamp(h - ((data[0] - min) / range) * h, 0, h));
            ctx.BeginFigure(firstPt, false, false);

            for (int i = 1; i < count; i++)
            {
                double px = i * stepX;
                double py = Math.Clamp(h - ((data[i] - min) / range) * h, 0, h);
                ctx.LineTo(new Point(px, py), true, false);
            }
        }
        geom.Freeze();

        // Área sob a curva (gradiente ou semitransparente)
        Brush? fill = FillBrush;
        if (fill == null && Stroke is SolidColorBrush scb)
        {
            var c = scb.Color;
            var lgb = new LinearGradientBrush
            {
                StartPoint = new Point(0, 0),
                EndPoint = new Point(0, 1),
                GradientStops = new GradientStopCollection
                {
                    new GradientStop(Color.FromArgb(72, c.R, c.G, c.B), 0.0),
                    new GradientStop(Color.FromArgb(5, c.R, c.G, c.B), 1.0)
                }
            };
            lgb.Freeze();
            fill = lgb;
        }

        if (fill != null)
        {
            var areaGeom = new StreamGeometry();
            using (var actx = areaGeom.Open())
            {
                Point firstPt = new(0, Math.Clamp(h - ((data[0] - min) / range) * h, 0, h));
                actx.BeginFigure(new Point(0, h), true, true);
                actx.LineTo(firstPt, true, false);
                for (int i = 1; i < count; i++)
                {
                    double px = i * stepX;
                    double py = Math.Clamp(h - ((data[i] - min) / range) * h, 0, h);
                    actx.LineTo(new Point(px, py), true, false);
                }
                actx.LineTo(new Point(w, h), true, false);
            }
            areaGeom.Freeze();
            dc.DrawGeometry(fill, null, areaGeom);
        }

        dc.DrawGeometry(null, strokePen, geom);

        // Ponto mais recente (último)
        if (count > 0)
        {
            float lastVal = data[^1];
            double lastX = w;
            double lastY = Math.Clamp(h - ((lastVal - min) / range) * h, 0, h);
            dc.DrawEllipse(Stroke, null, new Point(lastX - 1, lastY), 2.5, 2.5);

            if (ShowCurrentValue)
            {
                string text = $"{lastVal:0.#} {Unit}".Trim();
                var ft = new FormattedText(text, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, Tf, 10.5, TextBrush, 1.0);
                double tx = Math.Max(4, w - ft.Width - 6);
                double ty = Math.Clamp(lastY - 14, 2, h - ft.Height - 2);
                dc.DrawText(ft, new Point(tx, ty));
            }
        }
    }
}
