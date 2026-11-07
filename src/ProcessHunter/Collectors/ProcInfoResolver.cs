using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media.Imaging;
using ProcessHunter.Core;
using ProcessHunter.Native;
using Microsoft.Win32.SafeHandles;

namespace ProcessHunter.Collectors;

/// <summary>Verificação de assinatura digital (Authenticode embutida + catálogos do Windows) via WinVerifyTrust.</summary>
internal static class SignatureVerifier
{
    [StructLayout(LayoutKind.Sequential)] struct WINTRUST_FILE_INFO { public uint cb; public IntPtr path, hFile, known; }
    [StructLayout(LayoutKind.Sequential)]
    struct WINTRUST_CATALOG_INFO
    {
        public uint cb, version; public IntPtr catPath, memberTag, memberPath, hMember, hash; public uint hashLen; public IntPtr catCtx, hCatAdmin;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct WINTRUST_DATA
    {
        public uint cb; public IntPtr policy, sip; public uint uiChoice, revoke, unionChoice; public IntPtr pUnion; public uint stateAction; public IntPtr hState, url;
        public uint provFlags, uiContext; public IntPtr sigSettings;
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CATALOG_INFO { public uint cb; [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string file; }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)] static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);
    [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminAcquireContext(out IntPtr h, IntPtr sub, uint flags);
    [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminReleaseContext(IntPtr h, uint flags);
    [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr file, ref uint cb, byte[]? hash, uint flags);
    [DllImport("wintrust.dll", SetLastError = true)] static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint cb, uint flags, ref IntPtr prev);
    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool CryptCATCatalogInfoFromContext(IntPtr cat, ref CATALOG_INFO info, uint flags);
    [DllImport("wintrust.dll", SetLastError = true)] static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr cat, uint flags);

    static Guid GenericVerify = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    const uint FLAGS = 0x10 | 0x1000; // sem revogação online / apenas cache

    static int Verify(WINTRUST_DATA d) => WinVerifyTrust(IntPtr.Zero, ref GenericVerify, ref d);

    public static (SignatureState State, string? Signer, string Note) Check(string path)
    {
        try
        {
            int r = VerifyFile(path);
            if (r == 0) return (SignatureState.Valid, EmbeddedSigner(path), "Assinatura Authenticode válida");
            var cat = VerifyCatalog(path, out string? catName);
            if (cat == 0) return (SignatureState.Valid, null, "Assinado via catálogo do Windows (" + catName + ")");
            uint u = (uint)r;
            if (u is 0x800B0100 or 0x800B0003 or 0x800B0001) return (SignatureState.Unsigned, null, "Sem assinatura digital (fato informativo; não indica malware)");
            return (SignatureState.Invalid, EmbeddedSigner(path), $"Assinatura presente porém não confiável (0x{u:X8})");
        }
        catch (Exception e) { return (SignatureState.Unknown, null, "Não foi possível verificar: " + e.Message); }
    }

    static int VerifyFile(string path)
    {
        var fi = new WINTRUST_FILE_INFO { cb = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), path = Marshal.StringToHGlobalUni(path) };
        IntPtr pf = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fi, pf, false);
            return Verify(new WINTRUST_DATA { cb = (uint)Marshal.SizeOf<WINTRUST_DATA>(), uiChoice = 2, unionChoice = 1, pUnion = pf, provFlags = FLAGS });
        }
        finally { Marshal.FreeHGlobal(fi.path); Marshal.FreeHGlobal(pf); }
    }

    static int VerifyCatalog(string path, out string? catName)
    {
        catName = null;
        IntPtr admin = IntPtr.Zero, catCtx = IntPtr.Zero;
        try
        {
            if (!CryptCATAdminAcquireContext(out admin, IntPtr.Zero, 0)) return -1;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            uint cb = 64; var hash = new byte[64];
            if (!CryptCATAdminCalcHashFromFileHandle(fs.SafeFileHandle.DangerousGetHandle(), ref cb, hash, 0)) return -1;
            var h = new byte[cb]; Array.Copy(hash, h, cb);
            IntPtr prev = IntPtr.Zero;
            catCtx = CryptCATAdminEnumCatalogFromHash(admin, h, cb, 0, ref prev);
            if (catCtx == IntPtr.Zero) return -1;
            var ci = new CATALOG_INFO { cb = (uint)Marshal.SizeOf<CATALOG_INFO>(), file = "" };
            if (!CryptCATCatalogInfoFromContext(catCtx, ref ci, 0)) return -1;
            catName = Path.GetFileName(ci.file);
            string tag = Convert.ToHexString(h);
            var cat = new WINTRUST_CATALOG_INFO
            {
                cb = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(), catPath = Marshal.StringToHGlobalUni(ci.file),
                memberTag = Marshal.StringToHGlobalUni(tag), memberPath = Marshal.StringToHGlobalUni(path),
                hMember = fs.SafeFileHandle.DangerousGetHandle(), hash = Marshal.AllocHGlobal((int)cb), hashLen = cb, hCatAdmin = admin
            };
            Marshal.Copy(h, 0, cat.hash, (int)cb);
            IntPtr pc = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            try
            {
                Marshal.StructureToPtr(cat, pc, false);
                return Verify(new WINTRUST_DATA { cb = (uint)Marshal.SizeOf<WINTRUST_DATA>(), uiChoice = 2, unionChoice = 2, pUnion = pc, provFlags = FLAGS });
            }
            finally { Marshal.FreeHGlobal(cat.catPath); Marshal.FreeHGlobal(cat.memberTag); Marshal.FreeHGlobal(cat.memberPath); Marshal.FreeHGlobal(cat.hash); Marshal.FreeHGlobal(pc); }
        }
        catch { return -1; }
        finally
        {
            if (catCtx != IntPtr.Zero && admin != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin, catCtx, 0);
            if (admin != IntPtr.Zero) CryptCATAdminReleaseContext(admin, 0);
        }
    }

    static string? EmbeddedSigner(string path)
    {
        try
        {
#pragma warning disable SYSLIB0057
            var c = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
#pragma warning restore SYSLIB0057
            return c.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch { return null; }
    }
}

/// <summary>Resolve detalhes caros dos processos (caminho, usuário, fornecedor, assinatura, ícone) em thread de baixa prioridade, com cache.</summary>
internal sealed class ProcInfoResolver : IDisposable
{
    readonly BlockingCollection<(int Pid, ProcDetails D)> _queue = new(new ConcurrentQueue<(int, ProcDetails)>());
    readonly ConcurrentDictionary<string, (SignatureState, string?, string)> _sigCache = new(StringComparer.OrdinalIgnoreCase);
    readonly ConcurrentDictionary<string, (string? Company, string? Desc, string? Ver)> _verCache = new(StringComparer.OrdinalIgnoreCase);
    readonly ConcurrentDictionary<string, System.Windows.Media.ImageSource?> _iconCache = new(StringComparer.OrdinalIgnoreCase);
    readonly Thread _t;
    readonly CancellationTokenSource _cts = new();

    public ProcInfoResolver()
    {
        _t = new Thread(Loop) { IsBackground = true, Name = "PH-Resolver", Priority = ThreadPriority.BelowNormal };
        _t.Start();
    }

    public void Enqueue(int pid, ProcDetails d) { if (!_queue.IsAddingCompleted) _queue.Add((pid, d)); }

    void Loop()
    {
        try
        {
            foreach (var (pid, d) in _queue.GetConsumingEnumerable(_cts.Token))
            {
                try { Resolve(pid, d); } catch { d.Resolved = true; d.Signature = SignatureState.Unknown; }
            }
        }
        catch (OperationCanceledException) { }
    }

    public static string? GetPath(int pid)
    {
        if (pid <= 4) return null;
        var h = Win32.OpenProcess(Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024); int sz = sb.Capacity;
            return Win32.QueryFullProcessImageNameW(h, 0, sb, ref sz) ? sb.ToString() : null;
        }
        finally { Win32.CloseHandle(h); }
    }

    public static string PriorityName(int pid)
    {
        var h = Win32.OpenProcess(Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return "—";
        try
        {
            return Win32.GetPriorityClass(h) switch
            {
                0x40 => "Baixa", 0x4000 => "Abaixo do normal", 0x20 => "Normal", 0x8000 => "Acima do normal",
                0x80 => "Alta", 0x100 => "Tempo real", 0x00100000 => "Segundo plano (modo)", 0x00200000 => "Segundo plano (modo)", _ => "—"
            };
        }
        finally { Win32.CloseHandle(h); }
    }

    static string? GetUser(int pid)
    {
        var h = Win32.OpenProcess(Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            if (!Win32.OpenProcessToken(h, Win32.TOKEN_QUERY, out var tok)) return null;
            try { using var id = new WindowsIdentity(tok); return id.Name; }
            finally { Win32.CloseHandle(tok); }
        }
        catch { return null; }
        finally { Win32.CloseHandle(h); }
    }

    void Resolve(int pid, ProcDetails d)
    {
        var path = GetPath(pid);
        d.Path = path;
        d.User = pid <= 4 ? "SYSTEM" : (GetUser(pid) ?? "(acesso negado)");
        d.AccessDenied = path == null && pid > 4;
        d.Priority = PriorityName(pid);
        if (path != null && File.Exists(path))
        {
            var v = _verCache.GetOrAdd(path, p =>
            {
                try { var fvi = FileVersionInfo.GetVersionInfo(p); return (fvi.CompanyName, fvi.FileDescription, fvi.FileVersion); }
                catch { return (null, null, null); }
            });
            d.Company = v.Company; d.Description = v.Desc; d.Version = v.Ver;
            var sig = _sigCache.GetOrAdd(path, p => SignatureVerifier.Check(p));
            d.Signer = sig.Item2 ?? v.Company; d.SignatureNote = sig.Item3; d.Signature = sig.Item1;
            d.Icon = _iconCache.GetOrAdd(path, LoadIcon);
        }
        else
        {
            d.Signature = SignatureState.Unknown;
            d.SignatureNote = path == null ? "Caminho inacessível (processo protegido ou sem permissão)" : "Arquivo não encontrado";
        }
        d.Resolved = true;
    }

    static System.Windows.Media.ImageSource? LoadIcon(string path)
    {
        try
        {
            using var ic = System.Drawing.Icon.ExtractAssociatedIcon(path);
            if (ic == null) return null;
            var bs = Imaging.CreateBitmapSourceFromHIcon(ic.Handle, Int32Rect.Empty, BitmapSizeOptions.FromWidthAndHeight(16, 16));
            bs.Freeze();
            return bs;
        }
        catch { return null; }
    }

    public void Dispose() { _queue.CompleteAdding(); _cts.Cancel(); }
}
