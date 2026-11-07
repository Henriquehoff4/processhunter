using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;
using Brush = System.Windows.Media.Brush;
using Brushes = System.Windows.Media.Brushes;
using ProcessHunter.Core;

namespace ProcessHunter.ViewModels;

public sealed class ProcessItemViewModel : INotifyPropertyChanged
{
    ProcSample _sample;
    int _level;
    bool _isExpanded = true;
    bool _hasChildren;

    public ProcessItemViewModel(ProcSample sample, int level = 0)
    {
        _sample = sample;
        _level = level;
    }

    public ProcSample Sample => _sample;

    public void Update(ProcSample s)
    {
        _sample = s;
        OnPropertyChanged(nameof(Cpu));
        OnPropertyChanged(nameof(CpuText));
        OnPropertyChanged(nameof(PrivateBytes));
        OnPropertyChanged(nameof(RamText));
        OnPropertyChanged(nameof(WorkingSetText));
        OnPropertyChanged(nameof(Gpu));
        OnPropertyChanged(nameof(GpuText));
        OnPropertyChanged(nameof(GpuEngines));
        OnPropertyChanged(nameof(VramText));
        OnPropertyChanged(nameof(DiskText));
        OnPropertyChanged(nameof(Threads));
        OnPropertyChanged(nameof(Handles));
        OnPropertyChanged(nameof(Priority));
        OnPropertyChanged(nameof(RuntimeText));
        OnPropertyChanged(nameof(Icon));
        OnPropertyChanged(nameof(PathText));
        OnPropertyChanged(nameof(UserText));
        OnPropertyChanged(nameof(VendorText));
        OnPropertyChanged(nameof(SignatureText));
        OnPropertyChanged(nameof(SignatureColor));
    }

    public int Pid => _sample.Pid;
    public int ParentPid => _sample.ParentPid;
    public string Name => _sample.Name;
    public int Level { get => _level; set { if (_level != value) { _level = value; OnPropertyChanged(); OnPropertyChanged(nameof(IndentPadding)); } } }
    public double IndentPadding => _level * 16.0;
    public bool HasChildren { get => _hasChildren; set { if (_hasChildren != value) { _hasChildren = value; OnPropertyChanged(); OnPropertyChanged(nameof(ExpanderGlyph)); } } }
    public bool IsExpanded { get => _isExpanded; set { if (_isExpanded != value) { _isExpanded = value; OnPropertyChanged(); OnPropertyChanged(nameof(ExpanderGlyph)); } } }
    public string ExpanderGlyph => _hasChildren ? (_isExpanded ? "▾" : "▸") : " ";

    public double Cpu => _sample.Cpu;
    public string CpuText => _sample.Cpu > 0.05 ? $"{_sample.Cpu:0.0}%" : "0.0%";
    public long PrivateBytes => _sample.Private;
    public string RamText => Fmt.Bytes(_sample.Private);
    public string WorkingSetText => Fmt.Bytes(_sample.WorkingSet);
    public double Gpu => _sample.Gpu;
    public string GpuText => _sample.Gpu > 0.1 ? $"{_sample.Gpu:0.#}%" : "—";
    public string GpuEngines => _sample.GpuEngines;
    public long VramDedicated => _sample.VramDedicated;
    public string VramText => _sample.VramDedicated > 0 ? Fmt.Bytes(_sample.VramDedicated) : "—";
    public double DiskBytesPerSec => _sample.IoTotalBps;
    public string DiskText => _sample.IoTotalBps > 1024 ? $"{_sample.IoTotalBps / 1048576.0:0.0} MB/s" : "0.0 MB/s";
    public string NetText => "— (ETW admin)";
    public int Threads => _sample.Threads;
    public int Handles => _sample.Handles;
    public string Priority => _sample.Details.Priority ?? "Normal";
    public string RuntimeText => Fmt.Duration(DateTime.Now - _sample.StartTime);
    public ImageSource? Icon => _sample.Details.Icon;
    public string PathText => _sample.Details.Path ?? (_sample.Pid <= 4 ? "Kernel" : "(sem acesso)");
    public string UserText => _sample.Details.User ?? "(carregando...)";
    public string VendorText => _sample.Details.Company ?? _sample.Details.Signer ?? (_sample.Pid <= 4 ? "Microsoft Windows" : "—");
    public bool IsProtected => _sample.IsProtected;

    public string SignatureText => _sample.Details.Signature switch
    {
        SignatureState.Valid => "Válida",
        SignatureState.Invalid => "Não confiável",
        SignatureState.Unsigned => "Sem assinatura",
        SignatureState.Pending => "Verificando...",
        _ => "—"
    };

    static Brush Frozen(byte r, byte g, byte b) { var br = new SolidColorBrush(Color.FromRgb(r, g, b)); br.Freeze(); return br; }
    static readonly Brush SigOk = Frozen(166, 194, 94);
    static readonly Brush SigBad = Frozen(240, 117, 106);
    static readonly Brush SigNone = Frozen(151, 137, 120);

    public Brush SignatureColor => _sample.Details.Signature switch
    {
        SignatureState.Valid => SigOk,
        SignatureState.Invalid => SigBad,
        SignatureState.Unsigned => SigNone,
        _ => SigNone
    };

    public event PropertyChangedEventHandler? PropertyChanged;
    void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
