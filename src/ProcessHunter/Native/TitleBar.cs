using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace ProcessHunter.Native;

public static class TitleBar
{
    [DllImport("dwmapi.dll")]
    static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    const int UseImmersiveDarkMode = 20;
    const int BorderColor = 34;
    const int CaptionColor = 35;
    const int TextColor = 36;

    static int Bgr(byte r, byte g, byte b) => r | (g << 8) | (b << 16);

    public static void ApplyWarmDark(Window window)
    {
        window.SourceInitialized += (_, _) =>
        {
            try
            {
                var hwnd = new WindowInteropHelper(window).Handle;
                int on = 1;
                DwmSetWindowAttribute(hwnd, UseImmersiveDarkMode, ref on, sizeof(int));
                int caption = Bgr(0x15, 0x11, 0x0E);
                DwmSetWindowAttribute(hwnd, CaptionColor, ref caption, sizeof(int));
                int border = Bgr(0x34, 0x2C, 0x25);
                DwmSetWindowAttribute(hwnd, BorderColor, ref border, sizeof(int));
                int text = Bgr(0xF2, 0xE8, 0xDA);
                DwmSetWindowAttribute(hwnd, TextColor, ref text, sizeof(int));
            }
            catch { }
        };
    }
}
