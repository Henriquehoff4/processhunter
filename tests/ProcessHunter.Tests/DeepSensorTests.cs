using LibreHardwareMonitor.Hardware;
using ProcessHunter.Collectors;
using ProcessHunter.Core;
using Xunit;

namespace ProcessHunter.Tests;

public class DeepSensorTests
{
    static void Cpu(DeepSensors d, SensorType t, string name, float v) =>
        DeepSensorCollector.Add(HardwareType.Cpu, "Intel Core i5-14400F", t, name, v, d);

    [Fact]
    public void IntelHybrid_PerCoreNames_AreRecognised_AndTjMaxDistanceIgnored()
    {
        var d = new DeepSensors();
        Cpu(d, SensorType.Temperature, "P-Core #1", 48);
        Cpu(d, SensorType.Temperature, "P-Core #2", 51);
        Cpu(d, SensorType.Temperature, "E-Core #1", 45);
        Cpu(d, SensorType.Temperature, "P-Core #1 Distance to TjMax", 52);
        Cpu(d, SensorType.Temperature, "Core Average", 49);
        Cpu(d, SensorType.Temperature, "Core Max", 51);
        Cpu(d, SensorType.Temperature, "CPU Package", 53);

        Assert.Equal(new[] { "P-Core #1", "P-Core #2", "E-Core #1" }, d.CoreTemps.Select(c => c.Name));
        Assert.Equal(53, d.CpuPackageTempC);
        Assert.Equal(51, d.CpuMaxCoreTempC);
    }

    [Fact]
    public void Intel_NonHybrid_CoreNumberedNames_AreRecognised()
    {
        var d = new DeepSensors();
        Cpu(d, SensorType.Temperature, "Core #1", 40);
        Cpu(d, SensorType.Temperature, "Core #1 Distance to TjMax", 60);
        Assert.Single(d.CoreTemps);
        Assert.Equal(40, d.CoreTemps[0].Value);
    }

    [Fact]
    public void Amd_TctlTdie_FeedsMaxCoreTemp()
    {
        var d = new DeepSensors();
        DeepSensorCollector.Add(HardwareType.Cpu, "AMD Ryzen", SensorType.Temperature, "Core (Tctl/Tdie)", 61, d);
        DeepSensorCollector.Add(HardwareType.Cpu, "AMD Ryzen", SensorType.Temperature, "CCD1 (Tdie)", 58, d);
        Assert.Equal(61, d.CpuMaxCoreTempC);
        Assert.Empty(d.CoreTemps);
    }

    [Fact]
    public void ZeroPower_FromUnelevatedRead_IsNotReported()
    {
        var d = new DeepSensors();
        Cpu(d, SensorType.Power, "CPU Package", 0);
        Cpu(d, SensorType.Power, "CPU Cores", 0);
        Assert.Null(d.CpuPackagePowerW);
    }

    [Fact]
    public void Power_PackageOnly_IsReported()
    {
        var d = new DeepSensors();
        Cpu(d, SensorType.Power, "CPU Cores", 31);
        Cpu(d, SensorType.Power, "CPU Package", 38.5f);
        Assert.Equal(38.5, d.CpuPackagePowerW!.Value, 3);
    }

    [Fact]
    public void Vcore_PrefersMeasuredSuperIo_AndKeepsVidAsFallback()
    {
        var d = new DeepSensors();
        Cpu(d, SensorType.Voltage, "Core #1", 1.18f);
        Cpu(d, SensorType.Voltage, "Core #2", 1.22f);
        DeepSensorCollector.Add(HardwareType.SuperIO, "IT8689E", SensorType.Voltage, "Voltage #3", 1.05f, d);
        Assert.Null(d.CpuCoreVoltage);
        Assert.Equal(1.22, d.CpuVid!.Value, 3);

        DeepSensorCollector.Add(HardwareType.SuperIO, "IT8689E", SensorType.Voltage, "Vcore", 1.1f, d);
        Assert.Equal(1.1, d.CpuCoreVoltage!.Value, 3);
        Assert.Equal(2, d.Voltages.Count);
    }

    [Theory]
    [InlineData(0f)]
    [InlineData(-128f)]
    [InlineData(255f)]
    public void BogusTemperatures_AreDiscarded(float bogus)
    {
        var d = new DeepSensors();
        DeepSensorCollector.Add(HardwareType.SuperIO, "IT8689E", SensorType.Temperature, "Temperature #4", bogus, d);
        DeepSensorCollector.Add(HardwareType.Storage, "Disk", SensorType.Temperature, "Temperature", bogus, d);
        DeepSensorCollector.Add(HardwareType.Memory, "DIMM #1", SensorType.Temperature, "Temperature", bogus, d);
        Cpu(d, SensorType.Temperature, "CPU Package", bogus);
        Assert.Empty(d.BoardTemps);
        Assert.Empty(d.StorageTemps);
        Assert.Null(d.MaxDimmTempC);
        Assert.Null(d.CpuPackageTempC);
        Assert.False(d.HasAnyReading);
    }

    [Fact]
    public void StorageTemps_AreLabelledWithTheDriveName()
    {
        var d = new DeepSensors();
        DeepSensorCollector.Add(HardwareType.Storage, "Samsung SSD 980", SensorType.Temperature, "Temperature", 41, d);
        DeepSensorCollector.Add(HardwareType.Storage, "WD Blue SN570", SensorType.Temperature, "Temperature", 38, d);
        DeepSensorCollector.Add(HardwareType.Storage, "WD Blue SN570", SensorType.Temperature, "Temperature 2", 44, d);
        Assert.Equal(new[] { "Samsung SSD 980", "WD Blue SN570", "WD Blue SN570 · Temperature 2" }, d.StorageTemps.Select(s => s.Name));
    }

    [Fact]
    public void Fans_KeepZeroRpm_ButDropNegative()
    {
        var d = new DeepSensors();
        DeepSensorCollector.Add(HardwareType.SuperIO, "IT8689E", SensorType.Fan, "Fan #1", 1200, d);
        DeepSensorCollector.Add(HardwareType.SuperIO, "IT8689E", SensorType.Fan, "Fan #2", 0, d);
        DeepSensorCollector.Add(HardwareType.SuperIO, "IT8689E", SensorType.Fan, "Fan #3", -1, d);
        Assert.Equal(2, d.Fans.Count);
    }

    [Fact]
    public void NeedsElevation_OnlyWhenUnelevatedAndNoCpuTemp()
    {
        var d = new DeepSensors { ElevationRequired = true };
        Assert.True(d.NeedsElevation);
        Cpu(d, SensorType.Temperature, "CPU Package", 50);
        Assert.False(d.NeedsElevation);
        Assert.True(d.HasAnyReading);
    }

    [Fact]
    public void Collector_RunsWithoutThrowing_AndNeverInventsValues()
    {
        using var c = new DeepSensorCollector();
        var d = c.Collect();
        Assert.NotNull(d);
        if (!c.IsElevated)
        {
            Assert.True(d.ElevationRequired);
            Assert.Null(d.CpuPackagePowerW);
            Assert.Empty(d.CoreTemps);
        }
    }
}
