using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace ProcessHunter.Native;

public sealed class TrayIcon : IDisposable
{
    const int NIM_ADD = 0x00000000;
    const int NIM_MODIFY = 0x00000001;
    const int NIM_DELETE = 0x00000002;
    const int NIM_SETVERSION = 0x00000004;

    const int NIF_MESSAGE = 0x00000001;
    const int NIF_ICON = 0x00000002;
    const int NIF_TIP = 0x00000004;
    const int NIF_INFO = 0x00000010;

    const int WM_USER = 0x0400;
    const int WM_TRAY = WM_USER + 101;
    const int WM_LBUTTONDBLCLK = 0x0203;
    const int WM_RBUTTONUP = 0x0205;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct NOTIFYICONDATA
    {
        public int cbSize;
        public IntPtr hWnd;
        public uint uID;
        public uint uFlags;
        public uint uCallbackMessage;
        public IntPtr hIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szTip;
        public int dwState;
        public int dwStateMask;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szInfo;
        public uint uTimeoutOrVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
        public string szInfoTitle;
        public int dwInfoFlags;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    static extern bool Shell_NotifyIconW(int dwMessage, ref NOTIFYICONDATA lpData);

    [DllImport("user32.dll")]
    static extern IntPtr LoadIcon(IntPtr hInstance, IntPtr lpIconName);

    readonly Window _owner;
    HwndSource? _source;
    bool _added;
    IntPtr _hIcon;

    public event Action? DoubleClicked;
    public event Action? RightClicked;

    public TrayIcon(Window owner, string tip = "ProcessHunter — Ultimate System Monitor")
    {
        _owner = owner;
        _owner.Loaded += (s, e) => Init(tip);
    }

    void Init(string tip)
    {
        var helper = new WindowInteropHelper(_owner);
        _source = HwndSource.FromHwnd(helper.Handle);
        _source?.AddHook(WndProc);

        try
        {
            var iconUri = new Uri("pack://application:,,,/Assets/app.ico");
            using var stream = Application.GetResourceStream(iconUri)?.Stream;
            if (stream != null)
            {
                using var sysIcon = new System.Drawing.Icon(stream);
                _hIcon = sysIcon.Handle;
            }
        }
        catch { }

        if (_hIcon == IntPtr.Zero)
        {
            _hIcon = LoadIcon(IntPtr.Zero, (IntPtr)32512 /*IDI_APPLICATION*/);
        }

        var nid = new NOTIFYICONDATA
        {
            cbSize = Marshal.SizeOf<NOTIFYICONDATA>(),
            hWnd = helper.Handle,
            uID = 1,
            uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage = WM_TRAY,
            hIcon = _hIcon,
            szTip = tip.Length > 127 ? tip[..127] : tip
        };

        _added = Shell_NotifyIconW(NIM_ADD, ref nid);
    }

    public void ShowNotification(string title, string message, int infoFlags = 1 /*1=Info, 2=Warn, 3=Error*/)
    {
        var helper = new WindowInteropHelper(_owner);
        if (helper.Handle == IntPtr.Zero || !_added) return;

        var nid = new NOTIFYICONDATA
        {
            cbSize = Marshal.SizeOf<NOTIFYICONDATA>(),
            hWnd = helper.Handle,
            uID = 1,
            uFlags = NIF_INFO,
            szInfoTitle = title.Length > 63 ? title[..63] : title,
            szInfo = message.Length > 255 ? message[..255] : message,
            dwInfoFlags = infoFlags
        };
        Shell_NotifyIconW(NIM_MODIFY, ref nid);
    }

    IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_TRAY)
        {
            int action = lParam.ToInt32();
            if (action == WM_LBUTTONDBLCLK)
            {
                DoubleClicked?.Invoke();
                handled = true;
            }
            else if (action == WM_RBUTTONUP)
            {
                RightClicked?.Invoke();
                handled = true;
            }
        }
        return IntPtr.Zero;
    }

    public void Dispose()
    {
        if (_added)
        {
            var helper = new WindowInteropHelper(_owner);
            var nid = new NOTIFYICONDATA
            {
                cbSize = Marshal.SizeOf<NOTIFYICONDATA>(),
                hWnd = helper.Handle,
                uID = 1
            };
            Shell_NotifyIconW(NIM_DELETE, ref nid);
            _added = false;
        }
    }
}
