using System.Diagnostics;
using System.Text.RegularExpressions;
using LibreHardwareMonitor.Hardware;
using Microsoft.Win32;
using ProcessHunter.Core;

namespace ProcessHunter.Collectors;

/// <summary>
/// Motor de sensores profundos (estilo HWiNFO) baseado em LibreHardwareMonitorLib (MPL-2.0) sobre o
/// driver de kernel PawnIO. Lê temperatura por núcleo/package, potência RAPL, tensões, RPM de
/// ventoinhas e sensores da placa-mãe via acesso ring-0. A biblioteca embute apenas os módulos do
/// PawnIO; o driver em si precisa estar instalado no Windows. Exige administrador para os sensores
/// MSR/EC/SMBus (o coletor reporta <see cref="DeepSensors.ElevationRequired"/>).
/// </summary>
internal sealed class DeepSensorCollector : IDisposable
{
    static readonly Regex CoreName = new(@"^(?:[PE]-)?Core #\d+$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    readonly bool _elevated;
    Computer? _computer;
    UpdateVisitor? _visitor;
    string? _failReason;

    public bool IsElevated => _elevated;

    public DeepSensorCollector() => _elevated = IsAdministrator();

    static bool IsAdministrator()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    static bool IsPawnIoInstalled()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\PawnIO");
            return k != null;
        }
        catch { return true; }
    }

    void EnsureOpen()
    {
        if (_computer != null || _failReason != null) return;
        try
        {
            var c = new Computer
            {
                IsCpuEnabled = true,
                IsMemoryEnabled = true,
                IsMotherboardEnabled = true,
                IsStorageEnabled = true,
                IsControllerEnabled = false,
                IsGpuEnabled = false,
                IsNetworkEnabled = false,
            };
            c.Open();
            _computer = c;
            _visitor = new UpdateVisitor();
        }
        catch (Exception ex)
        {
            _failReason = ex.Message;
            Debug.WriteLine("DeepSensorCollector open failed: " + ex);
        }
    }

    public DeepSensors Collect()
    {
        var d = new DeepSensors { Time = DateTime.Now, ElevationRequired = !_elevated, PawnIoMissing = !IsPawnIoInstalled() };
        EnsureOpen();
        if (_computer == null)
        {
            d.Available = false;
            d.Error = _failReason ?? "Não foi possível inicializar o motor de sensores.";
            return d;
        }

        try
        {
            _computer.Accept(_visitor!);
            foreach (var hw in _computer.Hardware) Walk(hw, d);
        }
        catch (Exception ex)
        {
            d.Error = ex.Message;
        }

        d.Available = d.HasAnyReading;
        if (!d.Available && d.Error == null)
        {
            d.Error = d.PawnIoMissing
                ? "O driver PawnIO não está instalado. Instale o PawnIO para liberar os sensores da CPU e da placa-mãe."
                : _elevated
                    ? "O motor abriu, mas nenhum sensor respondeu. A Integridade de Memória (HVCI) pode estar bloqueando o driver PawnIO."
                    : null;
        }
        return d;
    }

    static void Walk(IHardware hw, DeepSensors d)
    {
        foreach (var s in hw.Sensors)
        {
            var val = s.Value;
            if (val.HasValue) Add(hw.HardwareType, hw.Name, s.SensorType, s.Name ?? "", val.Value, d);
        }
        foreach (var sub in hw.SubHardware) Walk(sub, d);
    }

    static bool ValidTemp(float v) => v > 0 && v < 150;

    internal static void Add(HardwareType type, string hardwareName, SensorType sensor, string rawName, float v, DeepSensors d)
    {
        if (float.IsNaN(v) || float.IsInfinity(v)) return;
        string name = rawName.Trim();

        switch (type)
        {
            case HardwareType.Cpu:
                if (sensor == SensorType.Temperature)
                {
                    if (!ValidTemp(v) || name.Contains("Distance to TjMax", StringComparison.OrdinalIgnoreCase)) return;
                    if (name.Contains("Package", StringComparison.Ordinal)) d.CpuPackageTempC ??= v;
                    else if (name.Contains("Core Max", StringComparison.Ordinal) || name.Contains("Tctl", StringComparison.Ordinal) || name.Contains("Tdie", StringComparison.Ordinal))
                        d.CpuMaxCoreTempC = Max(d.CpuMaxCoreTempC, v);
                    else if (CoreName.IsMatch(name))
                        d.CoreTemps.Add(new SensorReading { Name = name, Value = v });
                }
                else if (sensor == SensorType.Power)
                {
                    if (v > 0 && (name.Contains("Package", StringComparison.Ordinal) || name.Contains("PPT", StringComparison.Ordinal)))
                        d.CpuPackagePowerW ??= v;
                }
                else if (sensor == SensorType.Voltage)
                {
                    if (v > 0 && name.Contains("Core", StringComparison.Ordinal)) d.CpuVid = Max(d.CpuVid, v);
                }
                break;

            case HardwareType.SuperIO:
            case HardwareType.EmbeddedController:
            case HardwareType.Motherboard:
                if (sensor == SensorType.Fan)
                {
                    if (v >= 0) d.Fans.Add(new SensorReading { Name = name, Value = v });
                }
                else if (sensor == SensorType.Voltage)
                {
                    if (v <= 0) return;
                    d.Voltages.Add(new SensorReading { Name = name, Value = v });
                    if (IsVcore(name)) d.CpuCoreVoltage ??= v;
                }
                else if (sensor == SensorType.Temperature)
                {
                    if (ValidTemp(v)) d.BoardTemps.Add(new SensorReading { Name = name, Value = v });
                }
                break;

            case HardwareType.Memory:
                if (sensor == SensorType.Temperature && ValidTemp(v)) d.MaxDimmTempC = Max(d.MaxDimmTempC, v);
                break;

            case HardwareType.Storage:
                if (sensor == SensorType.Temperature && ValidTemp(v))
                {
                    string label = name.Equals("Temperature", StringComparison.OrdinalIgnoreCase) || name.Length == 0
                        ? hardwareName
                        : hardwareName + " · " + name;
                    d.StorageTemps.Add(new SensorReading { Name = label, Value = v });
                }
                break;
        }
    }

    static bool IsVcore(string name)
    {
        string n = name.Replace(" ", "");
        return n.Equals("Vcore", StringComparison.OrdinalIgnoreCase) || n.Equals("CPUVcore", StringComparison.OrdinalIgnoreCase);
    }

    static double? Max(double? a, double b) => a.HasValue ? Math.Max(a.Value, b) : b;

    public void Dispose()
    {
        try { _computer?.Close(); } catch { }
        _computer = null;
    }

    sealed class UpdateVisitor : IVisitor
    {
        public void VisitComputer(IComputer computer) => computer.Traverse(this);
        public void VisitHardware(IHardware hardware)
        {
            hardware.Update();
            foreach (var sub in hardware.SubHardware) sub.Accept(this);
        }
        public void VisitSensor(ISensor sensor) { }
        public void VisitParameter(IParameter parameter) { }
    }
}
