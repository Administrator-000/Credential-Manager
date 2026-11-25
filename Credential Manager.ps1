# Windows PowerShell 5.1 / .NET Framework compatibility bootstrap
$script:KeyMgrRuntimeLog = Join-Path ([System.IO.Path]::GetTempPath()) 'KeyMgr_v4_7_PS51.log'
function Write-KeyMgrRuntimeLog {
    param(
        [string]$Stage,
        [object]$Message
    )
    try {
        $messageText = if ($null -eq $Message) { '' } elseif ($Message -is [System.Management.Automation.ErrorRecord]) { $Message.Exception.ToString() } elseif ($Message -is [System.Exception]) { $Message.ToString() } else { [string]$Message }
        $line = '{0} [{1}] {2}{3}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Stage, ($messageText -replace '[\r\n]+', ' '), [Environment]::NewLine
        [System.IO.File]::AppendAllText($script:KeyMgrRuntimeLog, $line, (New-Object System.Text.UTF8Encoding($false)))
    } catch {
        # Logging must never prevent the application from starting.
    }
}
script:Write-KeyMgrRuntimeLog 'STARTUP' ('PowerShell {0}; CLR {1}; {2}-bit process' -f $PSVersionTable.PSVersion, [Environment]::Version, ([IntPtr]::Size * 8))
try {
    # Ensure required presentation framework assemblies are loaded.
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Add-Type -AssemblyName System.Drawing -ErrorAction Stop
# ===================================================================
# WINDOWS CREDENTIAL MANAGER - UNIFIED INTERFACE (PowerShell 5.1 runtime-scope build)
# Revision: KeyMgr4-7
# ===================================================================
# Scope and storage boundaries
# ----------------------------
# This script presents several independent credential providers in one UI; it does not treat
# them as interchangeable views of one database. The current implementation includes:
#   1. Win32 Credential Manager enumeration and CRUD through CredRead, CredEnumerate,
#      CredWrite, and CredDelete, including generic, domain, and certificate credential types.
#   2. WinRT PasswordVault enumeration, add, and remove operations for credentials exposed by
#      Windows.Security.Credentials.
#   3. Windows Vault metadata enumeration plus add/delete operations through vaultcmd.exe, and
#      logical item enumeration plus core-element create/delete operations through vaultcli.dll.
#   4. Browser Credentials architecture: provider tabs for Microsoft Edge (Chromium), Legacy
#      Microsoft Edge (EdgeHTML), Internet Explorer 11, and Internet Explorer 7/9; staged Chromium
#      Edge add/edit/remove and v10/v11/v20 conversion; linked Windows Web Credential projections
#      for Legacy Edge and IE11; and IE7/9 IntelliForms Storage2 inventory.
#   5. Stored-credential .crd backup/restore through Microsoft's credwiz.exe, plus the separate
#      removable-media password-reset workflow exposed by keymgr.dll. Diagnostic .crd import uses
#      CredRestoreCredentials, snapshots the live-store change, and then attempts rollback.
#   6. Current User\Personal certificate inventory and certificate-backed CredMan construction.
#   7. Physical Vault inventory and a best-effort DPAPI/AES decryption probe across user and
#      system Vault roots.
#
# Important implementation limits
# -------------------------------
# - Provider datasets overlap only partially and remain independent in Diagnostics.
# - vaultcmd.exe exposes Package SID, Saved By, Hidden, and Roaming. The Vault API diagnostic view
#   correlates those values with each matching VAULT_ITEM's package SID, Flags, and pProperties.
#   The correlation is observational: undocumented flag bits and property IDs are intentionally
#   shown raw instead of being assigned speculative names, and no setters are provided.
# - The native create path still writes pPackageSid = null, Flags = 0, PropertiesCount = 0, and
#   pProperties = null. Add/update therefore does not preserve the correlated metadata.
# - The Vault filesystem probe is heuristic rather than a schema-aware general-purpose decryptor.
# - Edge diagnostic views are read-only. Browser Credential edits are staged in memory; only Apply
#   may terminate Edge and touch Login Data. Apply snapshots each profile, verifies every row and
#   protection format, rolls the batch back on failure, and retains a one-session recovery snapshot.
# - The credwiz transfer wizard covers remembered Windows logon credentials. It is not a browser-
#   password backup and should not be confused with the removable-media password-reset-disk wizard.
# - No private Control Panel/VaultSvc RPC client, interface UUID, endpoint, or port assumption is
#   implemented here; that internal boundary is intentionally outside this build's scope.
# - A centralized provider-capability matrix controls Add/Edit/Remove availability for buttons,
#   menus, and keyboard actions. Unsupported provider operations are disabled before dispatch.
# - Credential mutations flow through provider-aware operation dispatchers and produce a common
#   result record (status, provider, operation, target, error detail, and rollback availability).
#   Operation history intentionally excludes secret values and is available from the Tools menu.
# - Supported mutations now capture provider-specific snapshots, perform the write, re-read the
#   provider, and roll back a mismatched or partially failed change when restoration is possible.
#   vaultcmd replacement/removal can be verified but cannot restore an unreadable authenticator;
#   that limitation is recorded explicitly instead of claiming rollback support.
# - Routine CredMan, PasswordVault, Vault API, and Edge enumeration is metadata-only. Secrets are
#   retrieved for an explicit edit, reveal/copy action, or short-lived transaction snapshot, and UI
#   controls plus managed snapshot holders are cleared as soon as the operation completes.
# - CredMan reveal is credential-type aware. Generic text blobs can be shown through CredReadW or
#   the matching CredEnumerateW result. Domain-password/certificate blobs remain authentication-
#   package-only, and empty, inaccessible, or provider-owned binary blobs produce an explicit status
#   instead of being passed to the clipboard or misrepresented as a plaintext password.
# - The menu bar routes File, Edit, View, Tools, and Help actions into the same provider-aware
#   handlers used by the main controls. The Tools command console can execute raw PowerShell or
#   selected Windows/KeyMgr API and application commands in the current user's security context;
#   it is intentionally explicit, displays a warning, and never runs a template automatically.
# ===================================================================
# ==============================================
# 1. EMBEDDED C# ENGINE (CREDMAN, EDGE/SQLITE, VAULT FILES, VAULTCLI, CERTIFICATES)
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
    // Materialize the managed model from a CREDENTIAL returned by CredEnumerate.
    public Credential(SecurityEngineMatrix.CREDENTIAL enumCred)
    {
        // Enumeration is metadata-only. Secrets are materialized only by an explicit Load call.
        LoadInternal(enumCred, false);
    }
    public string Username { get { return username; } set { username = value; } }
    public string Password { get { return password; } set { password = value; } }
    public string Target { get { return target; } set { target = value; } }
    public string Description { get { return description; } set { description = value; } }
    public DateTime LastWriteTime { get { return LastWriteTimeUtc.ToLocalTime(); } }
    public DateTime LastWriteTimeUtc { get { return lastWriteTime; } private set { lastWriteTime = value; } }
    public CredentialType Type { get { return type; } set { type = value; } }
    public PersistenceType PersistenceType { get { return persistenceType; } set { persistenceType = value; } }
    public void ClearSecret()
    {
        password = null;
    }
    public void Dispose()
    {
        ClearSecret();
    }
    public bool Load()
    {
        IntPtr credPointer;
        bool result = SecurityEngineMatrix.CredRead(Target, Type, 0, out credPointer);
        if (!result) 
        {
            // Preserve the caller's existing object state when CredRead cannot reopen the target.
            return false;
        }
        using (SecurityEngineMatrix.CriticalCredentialHandle credentialHandle = new SecurityEngineMatrix.CriticalCredentialHandle(credPointer))
        {
            LoadInternal(credentialHandle.GetCredential(), true);
        }
        return true;
    }
    public static IEnumerable<Credential> LoadAll()
    {
        return LoadAll(false);
    }
    public static IEnumerable<Credential> LoadAll(bool includeSecrets)
    {
        List<Credential> credlist = new List<Credential>();
        HashSet<string> seenTargets = new HashSet<string>();
        // Query unrestricted and common target prefixes; deduplicate overlaps by target, type, and user.
        string[] filters = new string[] { 
            null,                       // Unrestricted query with CRED_ENUMERATE_ALL_CREDENTIALS
            "*",                        // Explicit wildcard query; results can overlap the unrestricted query
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
                    // The composite key suppresses duplicate rows returned by overlapping filters.
                    string uniqueKey = cred.TargetName + "||" + cred.Type + "||" + cred.UserName;
                    if (seenTargets.Contains(uniqueKey)) continue;
                    // Copy the enumerated native record before CredFree releases the result buffer.
                    Credential fullCred = new Credential();
                    fullCred.LoadInternal(cred, includeSecrets);
                    credlist.Add(fullCred);
                    seenTargets.Add(uniqueKey);
                }
            }
            catch {}
        }
        return credlist;
    }
    internal void LoadInternal(SecurityEngineMatrix.CREDENTIAL credential, bool includeSecret)
    {
        Type = (CredentialType)credential.Type;
        Username = ((Type == CredentialType.DomainCertificate || Type == CredentialType.GenericCertificate) && !string.IsNullOrEmpty(credential.Comment))
            ? credential.Comment
            : credential.UserName;
        Password = includeSecret ? SecurityEngineMatrix.ReadCredentialBlob(credential) : null;
        Target = credential.TargetName;
        PersistenceType = (PersistenceType)credential.Persist;
        Description = credential.Comment;
        LastWriteTimeUtc = DateTime.FromFileTimeUtc(credential.LastWritten);
    }
}
public sealed class CredentialSecretReadResult : IDisposable
{
    public bool Success { get; set; }
    public string Secret { get; set; }
    public string Status { get; set; }
    public string Message { get; set; }
    public string Source { get; set; }
    public int BlobSize { get; set; }
    public int Win32Error { get; set; }
    public void ClearSecret()
    {
        Secret = null;
    }
    public void Dispose()
    {
        ClearSecret();
    }
}
public class SecurityEngineMatrix
{
    public const string CompatibilityBuild = "v4-7-docked-listview-scroll-ps51-csharp5-20261110a";
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
                return (Comment ?? string.Empty) + "\u001f" + Persist.ToString() + "\u001f" + GetBlobHash(CredentialBlobBytes);
            }
        }
        private static string GetBlobHash(byte[] bytes)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return BitConverter.ToString(sha.ComputeHash(bytes ?? new byte[0])).Replace("-", string.Empty);
            }
        }
        public void ClearSecret()
        {
            if (CredentialBlobBytes != null && CredentialBlobBytes.Length > 0)
                Array.Clear(CredentialBlobBytes, 0, CredentialBlobBytes.Length);
            CredentialBlobBytes = null;
            SecretText = null;
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
    public static CredentialSecretReadResult ReadCredentialSecret(string target, CredentialType type)
    {
        CredentialSecretReadResult result = new CredentialSecretReadResult
        {
            Success = false,
            Secret = null,
            Status = "NotRead",
            Message = "The credential has not been read.",
            Source = "CredMan",
            BlobSize = 0,
            Win32Error = 0
        };
        if (string.IsNullOrWhiteSpace(target))
        {
            result.Status = "InvalidTarget";
            result.Message = "The selected credential has no target name.";
            return result;
        }
        if (type == CredentialType.DomainPassword)
        {
            result.Status = "AuthenticationPackageProtected";
            result.Message = "Windows documents CRED_TYPE_DOMAIN_PASSWORD blobs as readable only by authentication packages. Advapi32!CredReadW can reopen the metadata, but a normal desktop process cannot legitimately reveal the stored domain password.";
            return result;
        }
        if (type == CredentialType.DomainCertificate || type == CredentialType.GenericCertificate)
        {
            result.Status = "CertificateCredential";
            result.Message = "This is a certificate-backed credential, not a revealable password. Certificate material and authentication-package PIN handling are intentionally not exposed as plaintext.";
            return result;
        }
        if (type == CredentialType.DomainExtended)
        {
            result.Status = "ExtendedCredential";
            result.Message = (target.StartsWith("MicrosoftAccount:", StringComparison.OrdinalIgnoreCase) || target.IndexOf("SSO_POP_", StringComparison.OrdinalIgnoreCase) >= 0)
                ? "This MicrosoftAccount SSO_POP item is a Windows extended credential owned by the Microsoft account identity provider. CredMan does not define its blob as a plaintext password, so KeyMgr will not decode or copy it."
                : "This Windows extended credential is owned by an authentication or identity provider. CredMan does not define its blob as a plaintext password, so KeyMgr will not decode or copy it.";
            return result;
        }
        if (type == CredentialType.DomainVisiblePassword)
        {
            result.Status = "UnsupportedCredentialType";
            result.Message = "CRED_TYPE_DOMAIN_VISIBLE_PASSWORD is no longer supported by Windows. KeyMgr will not treat its blob as a current plaintext-password format.";
            return result;
        }
        if (type != CredentialType.Generic)
        {
            result.Status = "UnsupportedCredentialType";
            result.Message = "The selected CredMan type has no supported plaintext reveal path.";
            return result;
        }

        if (TryReadCredentialByName(target, type, result))
            return result;

        string normalizedTarget = GetProjectedTargetValue(target);
        if (!string.Equals(normalizedTarget, target, StringComparison.OrdinalIgnoreCase) &&
            TryReadCredentialByName(normalizedTarget, type, result))
            return result;

        if (TryReadCredentialByEnumeration(target, normalizedTarget, type, result))
            return result;

        result.Status = "NotFoundOrInaccessible";
        result.Source = "Advapi32!CredReadW / CredEnumerateW";
        result.Message = "CredMan did not return the selected credential to the current logon session. It may be namespace-projected, unavailable to this token, or no longer present." +
            (result.Win32Error != 0 ? " Last Win32 error: " + result.Win32Error.ToString() + "." : string.Empty);
        return result;
    }
    private static bool TryReadCredentialByName(string target, CredentialType type, CredentialSecretReadResult result)
    {
        if (string.IsNullOrWhiteSpace(target))
            return false;
        IntPtr credentialPointer;
        if (!CredRead(target, type, 0, out credentialPointer) || credentialPointer == IntPtr.Zero)
        {
            result.Win32Error = Marshal.GetLastWin32Error();
            return false;
        }
        using (CriticalCredentialHandle credentialHandle = new CriticalCredentialHandle(credentialPointer))
        {
            PopulateCredentialSecretResult(credentialHandle.GetCredential(), target, "Advapi32!CredReadW", result);
        }
        return true;
    }
    private static bool TryReadCredentialByEnumeration(string projectedTarget, string normalizedTarget, CredentialType type, CredentialSecretReadResult result)
    {
        int[] flagsToTry = new int[] { 1, 0 };
        foreach (int flags in flagsToTry)
        {
            int count;
            IntPtr credentialsPointer;
            if (!CredEnumerate(null, flags, out count, out credentialsPointer) || credentialsPointer == IntPtr.Zero)
                continue;
            try
            {
                for (int index = 0; index < count; index++)
                {
                    IntPtr credentialPointer = Marshal.ReadIntPtr(credentialsPointer, index * IntPtr.Size);
                    CREDENTIAL credential = (CREDENTIAL)Marshal.PtrToStructure(credentialPointer, typeof(CREDENTIAL));
                    if ((CredentialType)credential.Type != type)
                        continue;
                    string enumeratedTarget = credential.TargetName ?? string.Empty;
                    string enumeratedNormalized = GetProjectedTargetValue(enumeratedTarget);
                    bool matches = string.Equals(enumeratedTarget, projectedTarget, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(enumeratedTarget, normalizedTarget, StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(enumeratedNormalized, normalizedTarget, StringComparison.OrdinalIgnoreCase);
                    if (!matches)
                        continue;
                    PopulateCredentialSecretResult(credential, projectedTarget, "Advapi32!CredEnumerateW", result);
                    return true;
                }
            }
            finally
            {
                CredFree(credentialsPointer);
            }
        }
        return false;
    }
    private static string GetProjectedTargetValue(string target)
    {
        if (string.IsNullOrEmpty(target))
            return target;
        int colon = target.IndexOf(':');
        int equals = colon >= 0 ? target.IndexOf('=', colon + 1) : -1;
        if (colon > 0 && equals > colon && equals + 1 < target.Length)
            return target.Substring(equals + 1);
        return target;
    }
    private static void PopulateCredentialSecretResult(CREDENTIAL credential, string requestedTarget, string source, CredentialSecretReadResult result)
    {
        result.Source = source;
        result.BlobSize = Math.Max(0, credential.CredentialBlobSize);
        if ((credential.Flags & 2) != 0)
        {
            result.Status = "PromptRequired";
            result.Message = "Windows marked this credential CRED_FLAGS_PROMPT_NOW. Its secret was not persisted for this logon and must be entered again by the owning application.";
            return;
        }
        if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize <= 0)
        {
            result.Status = "EmptyBlob";
            result.Message = DescribeGenericBlobStatus(requestedTarget, false, 0);
            return;
        }
        byte[] blobBytes = new byte[credential.CredentialBlobSize];
        try
        {
            Marshal.Copy(credential.CredentialBlob, blobBytes, 0, blobBytes.Length);
            string text;
            if (!TryDecodeUnicodeText(blobBytes, out text))
            {
                result.Status = "OpaqueBinaryBlob";
                result.Message = DescribeGenericBlobStatus(requestedTarget, true, blobBytes.Length);
                return;
            }
            if (string.IsNullOrEmpty(text))
            {
                result.Status = "EmptySecret";
                result.Message = DescribeGenericBlobStatus(requestedTarget, false, blobBytes.Length);
                return;
            }
            result.Secret = text;
            result.Success = true;
            result.Status = "ReadableText";
            result.Message = "CredMan returned a non-empty Unicode text blob through " + source + ".";
        }
        finally
        {
            Array.Clear(blobBytes, 0, blobBytes.Length);
        }
    }
    private static bool TryDecodeUnicodeText(byte[] bytes, out string text)
    {
        text = null;
        if (bytes == null || bytes.Length == 0 || (bytes.Length % 2) != 0)
            return false;
        try
        {
            UnicodeEncoding strictUnicode = new UnicodeEncoding(false, false, true);
            string candidate = strictUnicode.GetString(bytes).TrimEnd('\0');
            for (int index = 0; index < candidate.Length; index++)
            {
                char value = candidate[index];
                if (value == '\0' || (char.IsControl(value) && value != '\r' && value != '\n' && value != '\t'))
                    return false;
            }
            text = candidate;
            return true;
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
    }
    private static string DescribeGenericBlobStatus(string target, bool binary, int blobSize)
    {
        string sizeText = blobSize > 0 ? " (" + blobSize.ToString() + " bytes)" : string.Empty;
        if (target.StartsWith("MicrosoftAccount:", StringComparison.OrdinalIgnoreCase) ||
            target.IndexOf("SSO_POP_", StringComparison.OrdinalIgnoreCase) >= 0)
            return "This MicrosoftAccount SSO item contains " + (binary ? "provider-owned non-text data" : "no plaintext secret") + sizeText + ". It is not a password returned by the public CredMan contract; CredUnPackAuthenticationBuffer is not a general decoder for stored credential blobs.";
        if (target.StartsWith("WindowsLive:", StringComparison.OrdinalIgnoreCase) ||
            target.IndexOf("virtualapp/didlogical", StringComparison.OrdinalIgnoreCase) >= 0)
            return "The WindowsLive generic credential contains " + (binary ? "an application-defined non-text blob" : "no persisted plaintext secret") + sizeText + ". KeyMgr only reveals it when the supported CredMan path returns non-empty Unicode text.";
        if (target.StartsWith("LegacyGeneric:", StringComparison.OrdinalIgnoreCase))
            return "The legacy generic credential contains " + (binary ? "application-defined binary data" : "an empty credential blob") + sizeText + ", so there is no text value to copy.";
        return "The generic credential contains " + (binary ? "application-defined binary data" : "no persisted text secret") + sizeText + ". CredMan defines generic blobs by their owning application, so KeyMgr will not guess a password encoding.";
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
        // Flag 1 is CRED_ENUMERATE_ALL_CREDENTIALS; it requests all target namespaces available to the current logon.
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
// Microsoft Edge (Chromium) Login Data and diagnostics engine
// Discovery and reads use isolated copies; staged Apply invokes Add/Update/Delete against the live profile.
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
    public bool SecretLoaded { get; set; }
}
public sealed class EdgeCredentialSnapshot : IDisposable
{
    public long LoginId { get; set; }
    public string ProfilePath { get; set; }
    public string Website { get; set; }
    public string ActionUrl { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
    public string EncryptionVersion { get; set; }
    public void ClearSecret() { Password = null; }
    public void Dispose() { ClearSecret(); }
}
public class EdgeDatabaseOverview
{
    public string ProfileName { get; set; }
    public string ProfileDirectory { get; set; }
    public string DatabasePath { get; set; }
    public string QueryDatabasePath { get; set; }
    public long DatabaseSizeBytes { get; set; }
    public string SqliteVersion { get; set; }
    public string OpenMode { get; set; }
    public bool EdgeRunning { get; set; }
    public bool WalPresent { get; set; }
    public bool ShmPresent { get; set; }
    public long LoginRowCount { get; set; }
    public long StatsRowCount { get; set; }
    public long UserVersion { get; set; }
    public string MetaVersion { get; set; }
    public string JournalMode { get; set; }
    public long PageCount { get; set; }
    public long FreelistCount { get; set; }
    public string IntegrityResult { get; set; }
    public int V10Count { get; set; }
    public int V11Count { get; set; }
    public int V20Count { get; set; }
    public int RawDpapiCount { get; set; }
    public int EmptyCount { get; set; }
    public int UnknownCount { get; set; }
    public int DecryptSuccessCount { get; set; }
    public int DecryptFailureCount { get; set; }
    public string LastScan { get; set; }
}
public class EdgeSqlTraceEntry
{
    public string Timestamp { get; set; }
    public string ProfileName { get; set; }
    public string Operation { get; set; }
    public string ObjectName { get; set; }
    public string Result { get; set; }
    public long Rows { get; set; }
    public double DurationMs { get; set; }
    public string Detail { get; set; }
    public string Sql { get; set; }
}
public class EdgeSchemaColumnInfo
{
    public string ProfileName { get; set; }
    public string ObjectName { get; set; }
    public string ObjectType { get; set; }
    public string ColumnName { get; set; }
    public string DataType { get; set; }
    public bool Nullable { get; set; }
    public string DefaultValue { get; set; }
    public int PrimaryKeyOrder { get; set; }
}
public class EdgeDiagnosticErrorInfo
{
    public string Timestamp { get; set; }
    public string ProfileName { get; set; }
    public string DatabasePath { get; set; }
    public string Stage { get; set; }
    public int SqliteCode { get; set; }
    public string SqliteResult { get; set; }
    public string Message { get; set; }
    public string Operation { get; set; }
    public string Sql { get; set; }
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
    private const int SQLITE_OPEN_READONLY = 0x00000001;
    private const int SQLITE_OPEN_READWRITE = 0x00000002;
    private const int SQLITE_OPEN_FULLMUTEX = 0x00010000;
    private const int MAX_SQLITE_TEXT_BYTES = 16 * 1024 * 1024;
    private const int MAX_SQLITE_BLOB_BYTES = 64 * 1024 * 1024;
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
    private const int MAX_SQL_TRACE_ENTRIES = 1000;
    private static readonly object DiagnosticsSync = new object();
    private static readonly List<EdgeDatabaseOverview> DatabaseOverview = new List<EdgeDatabaseOverview>();
    private static readonly List<EdgeSqlTraceEntry> SqlTrace = new List<EdgeSqlTraceEntry>();
    private static readonly List<EdgeSchemaColumnInfo> SchemaInventory = new List<EdgeSchemaColumnInfo>();
    private static readonly List<EdgeDiagnosticErrorInfo> DiagnosticErrors = new List<EdgeDiagnosticErrorInfo>();
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
        public void ClearSecrets()
        {
            if (MasterKey != null && MasterKey.Length > 0) Array.Clear(MasterKey, 0, MasterKey.Length);
            if (AppBoundKey != null && AppBoundKey.Length > 0) Array.Clear(AppBoundKey, 0, AppBoundKey.Length);
            MasterKey = null;
            AppBoundKey = null;
        }
    }
    private sealed class ProcessInfo
    {
        public string Name;
        public int ProcessId;
    }
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int sqlite3_open_v2([In] byte[] filename, out IntPtr db, int flags, IntPtr zVfs);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int sqlite3_close(IntPtr db);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int sqlite3_prepare16_v2(IntPtr db, string sql, int numBytes, out IntPtr stmt, IntPtr pzTail);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int sqlite3_step(IntPtr stmt);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int sqlite3_finalize(IntPtr stmt);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int sqlite3_reset(IntPtr stmt);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern IntPtr sqlite3_errmsg16(IntPtr db);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern IntPtr sqlite3_column_text16(IntPtr stmt, int iCol);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern IntPtr sqlite3_column_blob(IntPtr stmt, int iCol);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int sqlite3_column_bytes(IntPtr stmt, int iCol);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int sqlite3_column_bytes16(IntPtr stmt, int iCol);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern long sqlite3_column_int64(IntPtr stmt, int iCol);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int sqlite3_bind_int64(IntPtr stmt, int index, long value);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int sqlite3_bind_text16(IntPtr stmt, int index, string value, int lengthInBytes, IntPtr destructor);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int sqlite3_bind_blob(IntPtr stmt, int index, byte[] value, int length, IntPtr destructor);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int sqlite3_changes(IntPtr db);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern long sqlite3_last_insert_rowid(IntPtr db);
    [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern IntPtr sqlite3_libversion();
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
        try
        {
            return ListProfiles(userDataPath, localState);
        }
        finally
        {
            localState.ClearSecrets();
        }
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
        return LoadDiagnostics(false);
    }
    public static List<EdgeDiagnosticCredential> LoadDiagnostics(bool includeSecrets)
    {
        ResetScanDiagnostics();
        List<EdgeDiagnosticCredential> credentials = new List<EdgeDiagnosticCredential>();
        string userDataPath = FindUserDataPath();
        if (string.IsNullOrEmpty(userDataPath))
        {
            RecordError(string.Empty, string.Empty, "Profile discovery", -1, "Edge User Data directory was not found.", "DISCOVER", string.Empty);
            return credentials;
        }
        EdgeLocalStateInfo localState = LoadLocalState(userDataPath);
        try
        {
            foreach (EdgeProfileInfo profile in ListProfiles(userDataPath, localState))
            {
                try
                {
                    credentials.AddRange(ReadProfileCredentials(profile, localState, includeSecrets));
                }
                catch (Exception ex)
                {
                    RecordError(profile.DisplayName, Path.Combine(profile.ProfilePath, "Login Data"), "Profile scan", -1, ex.Message, "SCAN", string.Empty);
                    credentials.Add(new EdgeDiagnosticCredential
                    {
                        ProfileName = profile.DisplayName,
                        ProfileDirectory = profile.DirectoryName,
                        ProfilePath = profile.ProfilePath,
                        Website = "[Profile Read Error]",
                        Username = "-",
                        Password = null,
                        LastUsed = "-",
                        EncryptionVersion = "ERROR",
                        SecretLoaded = false
                    });
                }
            }
        }
        finally
        {
            localState.ClearSecrets();
        }
        return credentials;
    }
    public static List<EdgeDatabaseOverview> GetDatabaseOverview()
    {
        lock (DiagnosticsSync)
            return new List<EdgeDatabaseOverview>(DatabaseOverview);
    }
    public static List<EdgeSqlTraceEntry> GetSqlTrace()
    {
        lock (DiagnosticsSync)
            return new List<EdgeSqlTraceEntry>(SqlTrace);
    }
    public static List<EdgeSchemaColumnInfo> GetSchemaInventory()
    {
        lock (DiagnosticsSync)
            return new List<EdgeSchemaColumnInfo>(SchemaInventory);
    }
    public static List<EdgeDiagnosticErrorInfo> GetDiagnosticErrors()
    {
        lock (DiagnosticsSync)
            return new List<EdgeDiagnosticErrorInfo>(DiagnosticErrors);
    }
    public static void ClearSqlTrace()
    {
        lock (DiagnosticsSync)
            SqlTrace.Clear();
    }
    private static void ResetScanDiagnostics()
    {
        lock (DiagnosticsSync)
        {
            DatabaseOverview.Clear();
            SchemaInventory.Clear();
            DiagnosticErrors.Clear();
        }
    }
    private static string LimitDiagnosticText(string value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;
        string clean = value.Replace("\r", " ").Replace("\n", " ").Trim();
        return clean.Length <= 1200 ? clean : clean.Substring(0, 1200) + "...";
    }
    private static string SqliteResultName(int code)
    {
        int primary = code < 0 ? code : (code & 0xFF);
        switch (primary)
        {
            case 0: return "SQLITE_OK";
            case 1: return "SQLITE_ERROR";
            case 2: return "SQLITE_INTERNAL";
            case 3: return "SQLITE_PERM";
            case 4: return "SQLITE_ABORT";
            case 5: return "SQLITE_BUSY";
            case 6: return "SQLITE_LOCKED";
            case 7: return "SQLITE_NOMEM";
            case 8: return "SQLITE_READONLY";
            case 9: return "SQLITE_INTERRUPT";
            case 10: return "SQLITE_IOERR";
            case 11: return "SQLITE_CORRUPT";
            case 12: return "SQLITE_NOTFOUND";
            case 13: return "SQLITE_FULL";
            case 14: return "SQLITE_CANTOPEN";
            case 17: return "SQLITE_SCHEMA";
            case 19: return "SQLITE_CONSTRAINT";
            case 21: return "SQLITE_MISUSE";
            case 26: return "SQLITE_NOTADB";
            case 100: return "SQLITE_ROW";
            case 101: return "SQLITE_DONE";
            default: return code < 0 ? "N/A" : "SQLITE_" + code.ToString();
        }
    }
    private static void AddTrace(string profile, string operation, string objectName, int code, long rows, Stopwatch timer, string detail, string sql)
    {
        EdgeSqlTraceEntry entry = new EdgeSqlTraceEntry
        {
            Timestamp = DateTime.Now.ToString("HH:mm:ss.fff"),
            ProfileName = profile ?? string.Empty,
            Operation = operation ?? string.Empty,
            ObjectName = objectName ?? string.Empty,
            Result = SqliteResultName(code),
            Rows = rows,
            DurationMs = timer == null ? 0.0 : Math.Round(timer.Elapsed.TotalMilliseconds, 3),
            Detail = LimitDiagnosticText(detail),
            Sql = LimitDiagnosticText(sql)
        };
        lock (DiagnosticsSync)
        {
            SqlTrace.Add(entry);
            while (SqlTrace.Count > MAX_SQL_TRACE_ENTRIES)
                SqlTrace.RemoveAt(0);
        }
    }
    private static void RecordError(string profile, string databasePath, string stage, int code, string message, string operation, string sql)
    {
        EdgeDiagnosticErrorInfo error = new EdgeDiagnosticErrorInfo
        {
            Timestamp = DateTime.Now.ToString("HH:mm:ss.fff"),
            ProfileName = profile ?? string.Empty,
            DatabasePath = databasePath ?? string.Empty,
            Stage = stage ?? string.Empty,
            SqliteCode = code,
            SqliteResult = SqliteResultName(code),
            Message = LimitDiagnosticText(message),
            Operation = operation ?? string.Empty,
            Sql = LimitDiagnosticText(sql)
        };
        lock (DiagnosticsSync)
            DiagnosticErrors.Add(error);
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
    public static EdgeCredentialSnapshot CaptureCredentialSnapshot(long loginId, string profilePath)
    {
        if (loginId <= 0)
            throw new ArgumentOutOfRangeException("loginId");
        if (string.IsNullOrEmpty(profilePath))
            throw new ArgumentNullException("profilePath");
        string userDataPath = GetUserDataPathFromProfile(profilePath);
        EdgeLocalStateInfo localState = LoadLocalState(userDataPath);
        string loginDataPath = Path.Combine(profilePath, "Login Data");
        string tempPath = CreateTempCopyPath("cm_edge_tx_", ".db");
        string tempWalPath = tempPath + "-wal";
        string tempShmPath = tempPath + "-shm";
        IntPtr db = IntPtr.Zero;
        IntPtr stmt = IntPtr.Zero;
        string sql = "SELECT origin_url, action_url, username_value, password_value FROM logins WHERE id = ?1 LIMIT 1";
        try
        {
            File.Copy(loginDataPath, tempPath, true);
            if (File.Exists(loginDataPath + "-wal"))
                File.Copy(loginDataPath + "-wal", tempWalPath, true);
            int openResult = OpenSqliteDatabase(tempPath, true, out db);
            if (openResult != SQLITE_OK || db == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_open_v2 failed: " + GetSqliteError(db, openResult));
            int prepareResult = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
            if (prepareResult != SQLITE_OK || stmt == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_prepare16_v2 failed: " + GetSqliteError(db, prepareResult));
            int bindResult = sqlite3_bind_int64(stmt, 1, loginId);
            if (bindResult != SQLITE_OK)
                throw new InvalidOperationException("sqlite3_bind_int64 failed: " + GetSqliteError(db, bindResult));
            int stepResult = sqlite3_step(stmt);
            if (stepResult == SQLITE_DONE)
                return null;
            if (stepResult != SQLITE_ROW)
                throw new InvalidOperationException("sqlite3_step failed: " + GetSqliteError(db, stepResult));
            byte[] passwordBlob = GetColumnBlob(stmt, 3);
            string decryptedPassword = DecryptPassword(passwordBlob, localState);
            if (!string.IsNullOrEmpty(decryptedPassword) && decryptedPassword.StartsWith("[", StringComparison.Ordinal) &&
                (decryptedPassword.IndexOf("failed", StringComparison.OrdinalIgnoreCase) >= 0 || decryptedPassword.IndexOf("unavailable", StringComparison.OrdinalIgnoreCase) >= 0))
                throw new InvalidOperationException("The selected Edge secret could not be decrypted for a verified transaction.");
            return new EdgeCredentialSnapshot
            {
                LoginId = loginId,
                ProfilePath = profilePath,
                Website = GetColumnText(stmt, 0),
                ActionUrl = GetColumnText(stmt, 1),
                Username = GetColumnText(stmt, 2),
                Password = decryptedPassword,
                EncryptionVersion = GetEncryptionVersion(passwordBlob)
            };
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
            SafeDeleteFile(tempPath);
            SafeDeleteFile(tempWalPath);
            SafeDeleteFile(tempShmPath);
            localState.ClearSecrets();
        }
    }
    public static bool CredentialExists(long loginId, string profilePath)
    {
        EdgeCredentialSnapshot snapshot = CaptureCredentialSnapshot(loginId, profilePath);
        if (snapshot == null)
            return false;
        snapshot.Dispose();
        return true;
    }
    public static bool VerifyCredential(long loginId, string profilePath, string username, string password)
    {
        return VerifyCredential(loginId, profilePath, username, password, null);
    }
    public static bool VerifyCredential(long loginId, string profilePath, string username, string password, string encryptionVersion)
    {
        EdgeCredentialSnapshot snapshot = CaptureCredentialSnapshot(loginId, profilePath);
        if (snapshot == null)
            return false;
        try
        {
            bool valuesMatch = string.Equals(snapshot.Username ?? string.Empty, username ?? string.Empty, StringComparison.Ordinal)
                && string.Equals(snapshot.Password ?? string.Empty, password ?? string.Empty, StringComparison.Ordinal);
            bool formatMatches = string.IsNullOrEmpty(encryptionVersion)
                || string.Equals(snapshot.EncryptionVersion, encryptionVersion, StringComparison.OrdinalIgnoreCase);
            return valuesMatch && formatMatches;
        }
        finally
        {
            snapshot.Dispose();
        }
    }
    public static bool VerifyCredentialDetails(long loginId, string profilePath, string website, string username, string password, string encryptionVersion)
    {
        EdgeCredentialSnapshot snapshot = CaptureCredentialSnapshot(loginId, profilePath);
        if (snapshot == null)
            return false;
        try
        {
            bool siteMatches = string.Equals(snapshot.Website ?? string.Empty, website ?? string.Empty, StringComparison.Ordinal)
                || string.Equals(snapshot.ActionUrl ?? string.Empty, website ?? string.Empty, StringComparison.Ordinal);
            bool valuesMatch = string.Equals(snapshot.Username ?? string.Empty, username ?? string.Empty, StringComparison.Ordinal)
                && string.Equals(snapshot.Password ?? string.Empty, password ?? string.Empty, StringComparison.Ordinal);
            bool formatMatches = string.IsNullOrEmpty(encryptionVersion)
                || string.Equals(snapshot.EncryptionVersion, encryptionVersion, StringComparison.OrdinalIgnoreCase);
            return siteMatches && valuesMatch && formatMatches;
        }
        finally
        {
            snapshot.Dispose();
        }
    }
    public static void UpdateCredential(long loginId, string profilePath, string username, string password)
    {
        UpdateCredential(loginId, profilePath, username, password, "v10");
    }
    public static void UpdateCredential(long loginId, string profilePath, string username, string password, string encryptionVersion)
    {
        if (loginId <= 0)
            throw new ArgumentOutOfRangeException("loginId");
        if (string.IsNullOrEmpty(profilePath))
            throw new ArgumentNullException("profilePath");
        string userDataPath = GetUserDataPathFromProfile(profilePath);
        EdgeLocalStateInfo localState = LoadLocalState(userDataPath);
        byte[] encryptedPassword = null;
        try
        {
            encryptedPassword = EncryptPassword(password ?? string.Empty, encryptionVersion, localState);
            ExecuteCredentialUpdate(profilePath, loginId, username ?? string.Empty, encryptedPassword);
        }
        finally
        {
            if (encryptedPassword != null && encryptedPassword.Length > 0)
                Array.Clear(encryptedPassword, 0, encryptedPassword.Length);
            localState.ClearSecrets();
        }
    }
    public static long AddCredential(string profilePath, string website, string username, string password, string encryptionVersion)
    {
        if (string.IsNullOrEmpty(profilePath))
            throw new ArgumentNullException("profilePath");
        if (string.IsNullOrWhiteSpace(website))
            throw new ArgumentNullException("website");
        string userDataPath = GetUserDataPathFromProfile(profilePath);
        EdgeLocalStateInfo localState = LoadLocalState(userDataPath);
        byte[] encryptedPassword = null;
        try
        {
            encryptedPassword = EncryptPassword(password ?? string.Empty, encryptionVersion, localState);
            return ExecuteCredentialInsert(profilePath, website, username ?? string.Empty, encryptedPassword);
        }
        finally
        {
            if (encryptedPassword != null && encryptedPassword.Length > 0)
                Array.Clear(encryptedPassword, 0, encryptedPassword.Length);
            localState.ClearSecrets();
        }
    }
    public static void DeleteCredential(long loginId, string profilePath)
    {
        if (loginId <= 0)
            throw new ArgumentOutOfRangeException("loginId");
        if (string.IsNullOrEmpty(profilePath))
            throw new ArgumentNullException("profilePath");
        ExecuteCredentialDelete(profilePath, loginId);
    }
    private static List<EdgeDiagnosticCredential> ReadProfileCredentials(EdgeProfileInfo profile, EdgeLocalStateInfo localState, bool includeSecrets)
    {
        List<EdgeDiagnosticCredential> credentials = new List<EdgeDiagnosticCredential>();
        string loginDataPath = Path.Combine(profile.ProfilePath, "Login Data");
        string tempPath = CreateTempCopyPath("cm_edge_login_", ".db");
        string tempWalPath = tempPath + "-wal";
        string tempShmPath = tempPath + "-shm";
        EdgeDatabaseOverview overview = new EdgeDatabaseOverview
        {
            ProfileName = profile.DisplayName,
            ProfileDirectory = profile.DirectoryName,
            DatabasePath = loginDataPath,
            QueryDatabasePath = tempPath,
            DatabaseSizeBytes = File.Exists(loginDataPath) ? new FileInfo(loginDataPath).Length : 0,
            SqliteVersion = GetSqliteLibraryVersion(),
            OpenMode = "Temporary copy",
            EdgeRunning = IsEdgeRunning(),
            WalPresent = File.Exists(loginDataPath + "-wal"),
            ShmPresent = File.Exists(loginDataPath + "-shm"),
            LoginRowCount = -1,
            StatsRowCount = -1,
            MetaVersion = string.Empty,
            IntegrityResult = "not run",
            DecryptSuccessCount = includeSecrets ? 0 : -1,
            DecryptFailureCount = includeSecrets ? 0 : -1,
            LastScan = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")
        };
        IntPtr db = IntPtr.Zero;
        IntPtr stmt = IntPtr.Zero;
        Stopwatch openTimer = Stopwatch.StartNew();
        try
        {
            File.Copy(loginDataPath, tempPath, true);
            if (overview.WalPresent)
                File.Copy(loginDataPath + "-wal", tempWalPath, true);
            // Never copy the live -shm file. It is a process-shared WAL index, not durable database content.
            // winsqlite3 creates a fresh index for the isolated temporary database when required.
            int openResult = OpenSqliteDatabase(tempPath, true, out db);
            openTimer.Stop();
            AddTrace(profile.DisplayName, "OPEN", "Login Data", openResult, 0, openTimer, "Source copied to an isolated temporary database; no credential values logged.", tempPath);
            if (openResult != SQLITE_OK || db == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_open_v2 failed: " + GetSqliteError(db, openResult));
            overview.IntegrityResult = ExecuteScalarText(db, profile, loginDataPath, "PRAGMA", "quick_check", "PRAGMA quick_check;");
            overview.JournalMode = ExecuteScalarText(db, profile, loginDataPath, "PRAGMA", "journal_mode", "PRAGMA journal_mode;");
            overview.PageCount = ExecuteScalarLong(db, profile, loginDataPath, "PRAGMA", "page_count", "PRAGMA page_count;");
            overview.FreelistCount = ExecuteScalarLong(db, profile, loginDataPath, "PRAGMA", "freelist_count", "PRAGMA freelist_count;");
            overview.UserVersion = ExecuteScalarLong(db, profile, loginDataPath, "PRAGMA", "user_version", "PRAGMA user_version;");
            bool hasLogins = TableExists(db, profile, loginDataPath, "logins");
            bool hasStats = TableExists(db, profile, loginDataPath, "stats");
            bool hasMeta = TableExists(db, profile, loginDataPath, "meta");
            overview.LoginRowCount = hasLogins ? ExecuteScalarLong(db, profile, loginDataPath, "SELECT", "logins", "SELECT COUNT(*) FROM logins;") : -1;
            overview.StatsRowCount = hasStats ? ExecuteScalarLong(db, profile, loginDataPath, "SELECT", "stats", "SELECT COUNT(*) FROM stats;") : -1;
            overview.MetaVersion = hasMeta ? ExecuteScalarText(db, profile, loginDataPath, "SELECT", "meta", "SELECT value FROM meta WHERE key = 'version' LIMIT 1;") : string.Empty;
            CollectSchema(db, profile, loginDataPath);
            if (!hasLogins)
                throw new InvalidOperationException("The Edge Login Data database does not contain a logins table.");
            string sql = "SELECT id, origin_url, action_url, username_value, password_value, date_last_used FROM logins ORDER BY origin_url ASC, username_value ASC";
            Stopwatch queryTimer = Stopwatch.StartNew();
            int prepareResult = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
            if (prepareResult != SQLITE_OK || stmt == IntPtr.Zero)
            {
                queryTimer.Stop();
                RecordError(profile.DisplayName, loginDataPath, "sqlite3_prepare16_v2", prepareResult, GetSqliteError(db, prepareResult), "SELECT", sql);
                AddTrace(profile.DisplayName, "SELECT", "logins", prepareResult, 0, queryTimer, GetSqliteError(db, prepareResult), sql);
                throw new InvalidOperationException("sqlite3_prepare16_v2 failed: " + GetSqliteError(db, prepareResult));
            }
            long rows = 0;
            int finalCode = SQLITE_DONE;
            while (true)
            {
                int stepResult = sqlite3_step(stmt);
                finalCode = stepResult;
                if (stepResult == SQLITE_DONE)
                    break;
                if (stepResult != SQLITE_ROW)
                {
                    RecordError(profile.DisplayName, loginDataPath, "sqlite3_step", stepResult, GetSqliteError(db, stepResult), "SELECT", sql);
                    throw new InvalidOperationException("sqlite3_step failed: " + GetSqliteError(db, stepResult));
                }
                long loginId = sqlite3_column_int64(stmt, 0);
                string originUrl = GetColumnText(stmt, 1);
                string actionUrl = GetColumnText(stmt, 2);
                string username = GetColumnText(stmt, 3);
                byte[] passwordBlob = GetColumnBlob(stmt, 4);
                long dateLastUsed = sqlite3_column_int64(stmt, 5);
                string encryptionVersion = GetEncryptionVersion(passwordBlob);
                string password = includeSecrets ? DecryptPassword(passwordBlob, localState) : null;
                if (string.Equals(encryptionVersion, "v10", StringComparison.Ordinal)) overview.V10Count++;
                else if (string.Equals(encryptionVersion, "v11", StringComparison.Ordinal)) overview.V11Count++;
                else if (string.Equals(encryptionVersion, "v20", StringComparison.Ordinal)) overview.V20Count++;
                else if (string.Equals(encryptionVersion, "dpapi/raw", StringComparison.Ordinal)) overview.RawDpapiCount++;
                else if (string.Equals(encryptionVersion, "EMPTY", StringComparison.Ordinal)) overview.EmptyCount++;
                else overview.UnknownCount++;
                if (includeSecrets)
                {
                    if (!string.IsNullOrEmpty(password) && password.StartsWith("[", StringComparison.Ordinal) &&
                        (password.IndexOf("failed", StringComparison.OrdinalIgnoreCase) >= 0 || password.IndexOf("unavailable", StringComparison.OrdinalIgnoreCase) >= 0))
                        overview.DecryptFailureCount++;
                    else
                        overview.DecryptSuccessCount++;
                }
                credentials.Add(new EdgeDiagnosticCredential
                {
                    LoginId = loginId,
                    ProfileName = profile.DisplayName,
                    ProfileDirectory = profile.DirectoryName,
                    ProfilePath = profile.ProfilePath,
                    Website = !string.IsNullOrEmpty(originUrl) ? originUrl : actionUrl,
                    ActionUrl = actionUrl,
                    Username = username,
                    Password = password,
                    LastUsed = ChromeTimeToString(dateLastUsed),
                    EncryptionVersion = encryptionVersion,
                    SecretLoaded = includeSecrets
                });
                rows++;
            }
            queryTimer.Stop();
            AddTrace(profile.DisplayName, "SELECT", "logins", finalCode, rows, queryTimer,
                includeSecrets
                    ? "Password values were decrypted for an explicit caller request; values and key material were not written to diagnostics."
                    : "password_value inspected only as encrypted BLOB length/prefix metadata; plaintext was not materialized.", sql);
        }
        catch (Exception ex)
        {
            overview.IntegrityResult = overview.IntegrityResult == "not run" ? "scan failed" : overview.IntegrityResult;
            RecordError(profile.DisplayName, loginDataPath, "Profile database scan", -1, ex.Message, "SCAN", string.Empty);
            throw;
        }
        finally
        {
            if (stmt != IntPtr.Zero)
                sqlite3_finalize(stmt);
            if (db != IntPtr.Zero)
            {
                Stopwatch closeTimer = Stopwatch.StartNew();
                int closeResult = sqlite3_close(db);
                closeTimer.Stop();
                AddTrace(profile.DisplayName, "CLOSE", "Login Data", closeResult, 0, closeTimer, "Closed temporary database copy.", tempPath);
            }
            SafeDeleteFile(tempPath);
            SafeDeleteFile(tempWalPath);
            SafeDeleteFile(tempShmPath);
            lock (DiagnosticsSync)
                DatabaseOverview.Add(overview);
        }
        return credentials;
    }
    private static string GetSqliteLibraryVersion()
    {
        try
        {
            IntPtr value = sqlite3_libversion();
            return value == IntPtr.Zero ? string.Empty : Marshal.PtrToStringAnsi(value);
        }
        catch
        {
            return string.Empty;
        }
    }
    private static long ExecuteScalarLong(IntPtr db, EdgeProfileInfo profile, string databasePath, string operation, string objectName, string sql)
    {
        IntPtr stmt = IntPtr.Zero;
        Stopwatch timer = Stopwatch.StartNew();
        int code = SQLITE_OK;
        try
        {
            code = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
            if (code != SQLITE_OK || stmt == IntPtr.Zero)
                throw new InvalidOperationException(GetSqliteError(db, code));
            code = sqlite3_step(stmt);
            if (code == SQLITE_ROW)
            {
                long value = sqlite3_column_int64(stmt, 0);
                timer.Stop();
                AddTrace(profile.DisplayName, operation, objectName, code, 1, timer, string.Empty, sql);
                return value;
            }
            if (code == SQLITE_DONE)
            {
                timer.Stop();
                AddTrace(profile.DisplayName, operation, objectName, code, 0, timer, "No row returned.", sql);
                return 0;
            }
            throw new InvalidOperationException(GetSqliteError(db, code));
        }
        catch (Exception ex)
        {
            timer.Stop();
            RecordError(profile.DisplayName, databasePath, operation, code, ex.Message, operation, sql);
            AddTrace(profile.DisplayName, operation, objectName, code, 0, timer, ex.Message, sql);
            throw;
        }
        finally
        {
            if (stmt != IntPtr.Zero) sqlite3_finalize(stmt);
        }
    }
    private static string ExecuteScalarText(IntPtr db, EdgeProfileInfo profile, string databasePath, string operation, string objectName, string sql)
    {
        IntPtr stmt = IntPtr.Zero;
        Stopwatch timer = Stopwatch.StartNew();
        int code = SQLITE_OK;
        try
        {
            code = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
            if (code != SQLITE_OK || stmt == IntPtr.Zero)
                throw new InvalidOperationException(GetSqliteError(db, code));
            code = sqlite3_step(stmt);
            if (code == SQLITE_ROW)
            {
                string value = GetColumnText(stmt, 0);
                timer.Stop();
                AddTrace(profile.DisplayName, operation, objectName, code, 1, timer, string.Empty, sql);
                return value;
            }
            if (code == SQLITE_DONE)
            {
                timer.Stop();
                AddTrace(profile.DisplayName, operation, objectName, code, 0, timer, "No row returned.", sql);
                return string.Empty;
            }
            throw new InvalidOperationException(GetSqliteError(db, code));
        }
        catch (Exception ex)
        {
            timer.Stop();
            RecordError(profile.DisplayName, databasePath, operation, code, ex.Message, operation, sql);
            AddTrace(profile.DisplayName, operation, objectName, code, 0, timer, ex.Message, sql);
            throw;
        }
        finally
        {
            if (stmt != IntPtr.Zero) sqlite3_finalize(stmt);
        }
    }
    private static bool TableExists(IntPtr db, EdgeProfileInfo profile, string databasePath, string tableName)
    {
        string safeName = (tableName ?? string.Empty).Replace("'", "''");
        return ExecuteScalarLong(db, profile, databasePath, "SELECT", "sqlite_master",
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '" + safeName + "';") > 0;
    }
    private static string QuoteSqlIdentifier(string value)
    {
        return "\"" + (value ?? string.Empty).Replace("\"", "\"\"") + "\"";
    }
    private static void CollectSchema(IntPtr db, EdgeProfileInfo profile, string databasePath)
    {
        const string masterSql = "SELECT name, type FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%' ORDER BY type, name;";
        List<string[]> objects = new List<string[]>();
        IntPtr stmt = IntPtr.Zero;
        Stopwatch timer = Stopwatch.StartNew();
        int code = SQLITE_OK;
        long rows = 0;
        try
        {
            code = sqlite3_prepare16_v2(db, masterSql, -1, out stmt, IntPtr.Zero);
            if (code != SQLITE_OK || stmt == IntPtr.Zero)
                throw new InvalidOperationException(GetSqliteError(db, code));
            while (true)
            {
                code = sqlite3_step(stmt);
                if (code == SQLITE_DONE) break;
                if (code != SQLITE_ROW) throw new InvalidOperationException(GetSqliteError(db, code));
                objects.Add(new string[] { GetColumnText(stmt, 0), GetColumnText(stmt, 1) });
                rows++;
            }
            timer.Stop();
            AddTrace(profile.DisplayName, "SELECT", "sqlite_master", code, rows, timer, "Enumerated schema objects.", masterSql);
        }
        catch (Exception ex)
        {
            timer.Stop();
            RecordError(profile.DisplayName, databasePath, "Schema inventory", code, ex.Message, "SELECT", masterSql);
            AddTrace(profile.DisplayName, "SELECT", "sqlite_master", code, rows, timer, ex.Message, masterSql);
            throw;
        }
        finally
        {
            if (stmt != IntPtr.Zero) sqlite3_finalize(stmt);
        }
        foreach (string[] schemaObject in objects)
        {
            string objectName = schemaObject[0];
            string objectType = schemaObject[1];
            string sql = "PRAGMA table_info(" + QuoteSqlIdentifier(objectName) + ");";
            stmt = IntPtr.Zero;
            timer = Stopwatch.StartNew();
            code = SQLITE_OK;
            rows = 0;
            try
            {
                code = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
                if (code != SQLITE_OK || stmt == IntPtr.Zero)
                    throw new InvalidOperationException(GetSqliteError(db, code));
                while (true)
                {
                    code = sqlite3_step(stmt);
                    if (code == SQLITE_DONE) break;
                    if (code != SQLITE_ROW) throw new InvalidOperationException(GetSqliteError(db, code));
                    EdgeSchemaColumnInfo column = new EdgeSchemaColumnInfo
                    {
                        ProfileName = profile.DisplayName,
                        ObjectName = objectName,
                        ObjectType = objectType,
                        ColumnName = GetColumnText(stmt, 1),
                        DataType = GetColumnText(stmt, 2),
                        Nullable = sqlite3_column_int64(stmt, 3) == 0,
                        DefaultValue = GetColumnText(stmt, 4),
                        PrimaryKeyOrder = (int)sqlite3_column_int64(stmt, 5)
                    };
                    lock (DiagnosticsSync)
                        SchemaInventory.Add(column);
                    rows++;
                }
                timer.Stop();
                AddTrace(profile.DisplayName, "PRAGMA", objectName, code, rows, timer, "Column inventory.", sql);
            }
            catch (Exception ex)
            {
                timer.Stop();
                RecordError(profile.DisplayName, databasePath, "Schema columns", code, ex.Message, "PRAGMA", sql);
                AddTrace(profile.DisplayName, "PRAGMA", objectName, code, rows, timer, ex.Message, sql);
            }
            finally
            {
                if (stmt != IntPtr.Zero) sqlite3_finalize(stmt);
            }
        }
    }
    private static byte[] GetUtf8NullTerminated(string value)
    {
        byte[] valueBytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        byte[] terminated = new byte[valueBytes.Length + 1];
        if (valueBytes.Length > 0)
            Buffer.BlockCopy(valueBytes, 0, terminated, 0, valueBytes.Length);
        return terminated;
    }
    private static int OpenSqliteDatabase(string path, bool readOnly, out IntPtr db)
    {
        db = IntPtr.Zero;
        if (string.IsNullOrEmpty(path))
            throw new ArgumentNullException("path");
        int flags = (readOnly ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE) | SQLITE_OPEN_FULLMUTEX;
        byte[] pathBytes = GetUtf8NullTerminated(path);
        return sqlite3_open_v2(pathBytes, out db, flags, IntPtr.Zero);
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
        if (textPtr == IntPtr.Zero)
            return string.Empty;
        int byteLength = sqlite3_column_bytes16(stmt, columnIndex);
        if (byteLength <= 0)
            return string.Empty;
        if (byteLength > MAX_SQLITE_TEXT_BYTES)
            throw new InvalidDataException("SQLite text column exceeds the diagnostic safety limit.");
        return Marshal.PtrToStringUni(textPtr, byteLength / 2);
    }
    private static byte[] GetColumnBlob(IntPtr stmt, int columnIndex)
    {
        int length = sqlite3_column_bytes(stmt, columnIndex);
        if (length <= 0)
            return new byte[0];
        if (length > MAX_SQLITE_BLOB_BYTES)
            throw new InvalidDataException("SQLite BLOB column exceeds the diagnostic safety limit.");
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
        if (blob.Length >= 1 && blob[0] == (byte)'v')
            return "UNKNOWN";
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
            byte[] plainText = DpapiUnprotect(blob);
            try
            {
                return DecodePasswordBytes(plainText);
            }
            finally
            {
                if (plainText != null && plainText.Length > 0)
                    Array.Clear(plainText, 0, plainText.Length);
            }
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
        byte[] plainText = null;
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
            plainText = new byte[cipherText.Length];
            int resultSize;
            status = BCryptDecrypt(key, cipherText, cipherText.Length, ref authInfo, null, 0, plainText, plainText.Length, out resultSize, 0);
            if (status != 0)
                throw new InvalidOperationException("BCryptDecrypt failed: 0x" + status.ToString("X8"));
            if (resultSize != plainText.Length)
            {
                byte[] resized = new byte[resultSize];
                Buffer.BlockCopy(plainText, 0, resized, 0, resultSize);
                Array.Clear(plainText, 0, plainText.Length);
                plainText = resized;
            }
            return DecodePasswordBytes(plainText);
        }
        finally
        {
            if (plainText != null && plainText.Length > 0)
                Array.Clear(plainText, 0, plainText.Length);
            if (keyObject != null && keyObject.Length > 0)
                Array.Clear(keyObject, 0, keyObject.Length);
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
        string profileName = Path.GetFileName(profilePath);
        string loginDataPath = Path.Combine(profilePath, "Login Data");
        string sql = "UPDATE logins SET username_value = ?1, password_value = ?2 WHERE id = ?3";
        Stopwatch openTimer = Stopwatch.StartNew();
        try
        {
            int openResult = OpenSqliteDatabase(loginDataPath, false, out db);
            openTimer.Stop();
            AddTrace(profileName, "OPEN", "Login Data", openResult, 0, openTimer, "Opened live database for requested edit.", loginDataPath);
            if (openResult != SQLITE_OK || db == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_open_v2 failed: " + GetSqliteError(db, openResult));
            Stopwatch timer = Stopwatch.StartNew();
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
            AddTrace(profileName, "BIND", "logins", SQLITE_OK, 0, null,
                "username_value=<text length " + (username ?? string.Empty).Length.ToString() + ">, password_value=<blob " + passwordBytes.Length.ToString() + " bytes>, id=<integer>; values omitted.", sql);
            int stepResult = sqlite3_step(stmt);
            if (stepResult != SQLITE_DONE)
                throw new InvalidOperationException("sqlite3_step failed: " + GetSqliteError(db, stepResult));
            int changed = sqlite3_changes(db);
            timer.Stop();
            AddTrace(profileName, "UPDATE", "logins", stepResult, changed, timer, "Live credential edit completed; bound values omitted.", sql);
            if (changed != 1)
                throw new InvalidOperationException("Expected exactly one Edge login row to be updated; SQLite reported " + changed.ToString() + ".");
        }
        catch (Exception ex)
        {
            RecordError(profileName, loginDataPath, "Credential update", -1, ex.Message, "UPDATE", sql);
            throw;
        }
        finally
        {
            if (stmt != IntPtr.Zero)
            {
                sqlite3_reset(stmt);
                sqlite3_finalize(stmt);
            }
            if (db != IntPtr.Zero)
            {
                Stopwatch closeTimer = Stopwatch.StartNew();
                int closeResult = sqlite3_close(db);
                closeTimer.Stop();
                AddTrace(profileName, "CLOSE", "Login Data", closeResult, 0, closeTimer, "Closed live database after edit.", loginDataPath);
            }
        }
    }
    private static HashSet<string> GetTableColumns(IntPtr db, string tableName)
    {
        HashSet<string> columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        IntPtr stmt = IntPtr.Zero;
        string sql = "PRAGMA table_info(" + tableName + ")";
        try
        {
            int prepareResult = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
            if (prepareResult != SQLITE_OK || stmt == IntPtr.Zero)
                throw new InvalidOperationException("Could not inspect the Edge logins schema: " + GetSqliteError(db, prepareResult));
            while (sqlite3_step(stmt) == SQLITE_ROW)
            {
                string name = GetColumnText(stmt, 1);
                if (!string.IsNullOrEmpty(name))
                    columns.Add(name);
            }
        }
        finally
        {
            if (stmt != IntPtr.Zero)
                sqlite3_finalize(stmt);
        }
        return columns;
    }
    private static long ExecuteCredentialInsert(string profilePath, string website, string username, byte[] encryptedPassword)
    {
        IntPtr db = IntPtr.Zero;
        IntPtr stmt = IntPtr.Zero;
        string profileName = Path.GetFileName(profilePath);
        string loginDataPath = Path.Combine(profilePath, "Login Data");
        string sql = string.Empty;
        Stopwatch openTimer = Stopwatch.StartNew();
        try
        {
            int openResult = OpenSqliteDatabase(loginDataPath, false, out db);
            openTimer.Stop();
            AddTrace(profileName, "OPEN", "Login Data", openResult, 0, openTimer, "Opened live database for requested add.", loginDataPath);
            if (openResult != SQLITE_OK || db == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_open_v2 failed: " + GetSqliteError(db, openResult));
            HashSet<string> available = GetTableColumns(db, "logins");
            string[] required = new string[] { "origin_url", "username_value", "password_value" };
            foreach (string requiredColumn in required)
            {
                if (!available.Contains(requiredColumn))
                    throw new InvalidOperationException("The Edge logins schema does not contain required column '" + requiredColumn + "'.");
            }
            List<string> columns = new List<string>();
            List<string> values = new List<string>();
            Action<string, string> add = delegate(string column, string value)
            {
                if (available.Contains(column)) { columns.Add(column); values.Add(value); }
            };
            add("origin_url", "?1");
            add("action_url", "?2");
            add("username_element", "''");
            add("username_value", "?3");
            add("password_element", "''");
            add("password_value", "?4");
            add("submit_element", "''");
            add("signon_realm", "?5");
            add("date_created", "?6");
            add("blacklisted_by_user", "0");
            add("scheme", "0");
            add("password_type", "0");
            add("times_used", "0");
            add("form_data", "X''");
            add("display_name", "''");
            add("icon_url", "''");
            add("federation_url", "''");
            add("skip_zero_click", "0");
            add("generation_upload_status", "0");
            add("possible_username_pairs", "X''");
            add("date_last_used", "?6");
            add("moving_blocked_for", "0");
            add("date_password_modified", "?6");
            sql = "INSERT INTO logins (" + string.Join(",", columns.ToArray()) + ") VALUES (" + string.Join(",", values.ToArray()) + ")";
            int prepareResult = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
            if (prepareResult != SQLITE_OK || stmt == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_prepare16_v2 failed: " + GetSqliteError(db, prepareResult));
            int bindResult = sqlite3_bind_text16(stmt, 1, website, -1, SQLITE_TRANSIENT);
            if (bindResult == SQLITE_OK) bindResult = sqlite3_bind_text16(stmt, 2, website, -1, SQLITE_TRANSIENT);
            if (bindResult == SQLITE_OK) bindResult = sqlite3_bind_text16(stmt, 3, username ?? string.Empty, -1, SQLITE_TRANSIENT);
            byte[] passwordBytes = encryptedPassword ?? new byte[0];
            if (bindResult == SQLITE_OK) bindResult = sqlite3_bind_blob(stmt, 4, passwordBytes, passwordBytes.Length, SQLITE_TRANSIENT);
            if (bindResult == SQLITE_OK && sql.IndexOf("?5", StringComparison.Ordinal) >= 0) bindResult = sqlite3_bind_text16(stmt, 5, website, -1, SQLITE_TRANSIENT);
            long chromeTime = DateTime.UtcNow.ToFileTimeUtc() / 10L;
            if (bindResult == SQLITE_OK && sql.IndexOf("?6", StringComparison.Ordinal) >= 0) bindResult = sqlite3_bind_int64(stmt, 6, chromeTime);
            if (bindResult != SQLITE_OK)
                throw new InvalidOperationException("SQLite bind failed: " + GetSqliteError(db, bindResult));
            Stopwatch timer = Stopwatch.StartNew();
            int stepResult = sqlite3_step(stmt);
            timer.Stop();
            if (stepResult != SQLITE_DONE)
                throw new InvalidOperationException("sqlite3_step failed: " + GetSqliteError(db, stepResult));
            long loginId = sqlite3_last_insert_rowid(db);
            AddTrace(profileName, "INSERT", "logins", stepResult, sqlite3_changes(db), timer, "Live credential add completed; bound values omitted.", sql);
            if (loginId <= 0)
                throw new InvalidOperationException("Edge credential insert did not return a valid row id.");
            return loginId;
        }
        catch (Exception ex)
        {
            RecordError(profileName, loginDataPath, "Credential insert", -1, ex.Message, "INSERT", sql);
            throw;
        }
        finally
        {
            if (stmt != IntPtr.Zero) { sqlite3_reset(stmt); sqlite3_finalize(stmt); }
            if (db != IntPtr.Zero) sqlite3_close(db);
        }
    }
    private static void ExecuteCredentialDelete(string profilePath, long loginId)
    {
        IntPtr db = IntPtr.Zero;
        IntPtr stmt = IntPtr.Zero;
        string profileName = Path.GetFileName(profilePath);
        string loginDataPath = Path.Combine(profilePath, "Login Data");
        string sql = "DELETE FROM logins WHERE id = ?1";
        Stopwatch openTimer = Stopwatch.StartNew();
        try
        {
            int openResult = OpenSqliteDatabase(loginDataPath, false, out db);
            openTimer.Stop();
            AddTrace(profileName, "OPEN", "Login Data", openResult, 0, openTimer, "Opened live database for requested removal.", loginDataPath);
            if (openResult != SQLITE_OK || db == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_open_v2 failed: " + GetSqliteError(db, openResult));
            Stopwatch timer = Stopwatch.StartNew();
            int prepareResult = sqlite3_prepare16_v2(db, sql, -1, out stmt, IntPtr.Zero);
            if (prepareResult != SQLITE_OK || stmt == IntPtr.Zero)
                throw new InvalidOperationException("sqlite3_prepare16_v2 failed: " + GetSqliteError(db, prepareResult));
            int bindResult = sqlite3_bind_int64(stmt, 1, loginId);
            if (bindResult != SQLITE_OK)
                throw new InvalidOperationException("sqlite3_bind_int64 failed: " + GetSqliteError(db, bindResult));
            AddTrace(profileName, "BIND", "logins", SQLITE_OK, 0, null, "id=<integer>; value omitted.", sql);
            int stepResult = sqlite3_step(stmt);
            if (stepResult != SQLITE_DONE)
                throw new InvalidOperationException("sqlite3_step failed: " + GetSqliteError(db, stepResult));
            int changed = sqlite3_changes(db);
            timer.Stop();
            AddTrace(profileName, "DELETE", "logins", stepResult, changed, timer, "Live credential removal completed; bound value omitted.", sql);
            if (changed != 1)
                throw new InvalidOperationException("Expected exactly one Edge login row to be removed; SQLite reported " + changed.ToString() + ".");
        }
        catch (Exception ex)
        {
            RecordError(profileName, loginDataPath, "Credential delete", -1, ex.Message, "DELETE", sql);
            throw;
        }
        finally
        {
            if (stmt != IntPtr.Zero)
            {
                sqlite3_reset(stmt);
                sqlite3_finalize(stmt);
            }
            if (db != IntPtr.Zero)
            {
                Stopwatch closeTimer = Stopwatch.StartNew();
                int closeResult = sqlite3_close(db);
                closeTimer.Stop();
                AddTrace(profileName, "CLOSE", "Login Data", closeResult, 0, closeTimer, "Closed live database after removal.", loginDataPath);
            }
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
    private static byte[] EncryptPassword(string plainText, string encryptionVersion, EdgeLocalStateInfo localState)
    {
        string version = string.IsNullOrEmpty(encryptionVersion) ? "v10" : encryptionVersion.ToLowerInvariant();
        if (version != "v10" && version != "v11" && version != "v20")
            throw new ArgumentException("Supported Edge protection formats are v10, v11, and v20.", "encryptionVersion");
        byte[] key = version == "v20" ? localState.AppBoundKey : localState.MasterKey;
        string keyError = version == "v20" ? localState.AppBoundKeyError : localState.MasterKeyError;
        if (key == null || key.Length == 0)
            throw new InvalidOperationException(string.IsNullOrEmpty(keyError) ? "The requested Edge encryption key is unavailable." : keyError);
        return EncryptPasswordAesGcm(plainText, key, version);
    }
    private static byte[] EncryptPasswordAesGcm(string plainText, byte[] masterKey, string version)
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
            output[0] = (byte)version[0];
            output[1] = (byte)version[1];
            output[2] = (byte)version[2];
            Buffer.BlockCopy(nonce, 0, output, 3, nonce.Length);
            Buffer.BlockCopy(cipherText, 0, output, 3 + nonce.Length, cipherText.Length);
            Buffer.BlockCopy(tag, 0, output, 3 + nonce.Length + cipherText.Length, tag.Length);
            return output;
        }
        finally
        {
            if (plainBytes != null && plainBytes.Length > 0) Array.Clear(plainBytes, 0, plainBytes.Length);
            if (cipherText != null && cipherText.Length > 0) Array.Clear(cipherText, 0, cipherText.Length);
            if (tag != null && tag.Length > 0) Array.Clear(tag, 0, tag.Length);
            if (keyObject != null && keyObject.Length > 0) Array.Clear(keyObject, 0, keyObject.Length);
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
// Windows Vault filesystem inventory and heuristic decryption probe
// Scans known Vault roots, attempts CurrentUser DPAPI policy recovery, and tests candidate AES keys.
// ------------------------------------------------------------------
public class VaultEncryptionEngine
{
    // Unused legacy format offsets are retained for reference; active candidate extraction is heuristic.
    private const uint VCRD_HEADER_SIZE = 16;
    private const uint POLICY_VPOL_HEADER = 4; // Retained legacy offset; active policy scanning searches for DPAPI blob magic.
    private static readonly byte[] DpapiBlobMagic = new byte[]
    {
        0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11,
        0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB
    };
    // Legacy helper for the current user Local Vault root; ProbeVaultFiles scans the complete root list.
    private static string GetVaultPath()
    {
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "Vault"
        );
    }
        public class VaultDecryptionProbe
        {
            public string RootName { get; set; }
            public string RootPath { get; set; }
            public string VaultGuid { get; set; }
            public string VaultPath { get; set; }
            public string PolicyPath { get; set; }
            public int PolicyFileCount { get; set; }
            public int SchemaFileCount { get; set; }
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
            string windowsRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string commonAppData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            List<string[]> roots = new List<string[]>();
            roots.Add(new string[] { "Current user - Local", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Microsoft", "Vault") });
            roots.Add(new string[] { "Current user - Roaming", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Microsoft", "Vault") });
            roots.Add(new string[] { "System profile - Local", Path.Combine(windowsRoot, "System32", "config", "systemprofile", "AppData", "Local", "Microsoft", "Vault") });
            roots.Add(new string[] { "System profile - Roaming", Path.Combine(windowsRoot, "System32", "config", "systemprofile", "AppData", "Roaming", "Microsoft", "Vault") });
            roots.Add(new string[] { "ProgramData", Path.Combine(commonAppData, "Microsoft", "Vault") });
            foreach (string[] root in roots)
            {
                string rootName = root[0];
                string rootPath = root[1];
                if (string.IsNullOrEmpty(rootPath) || !Directory.Exists(rootPath))
                {
                    probes.Add(CreateRootProbe(rootName, rootPath, "MISSING", "Vault root does not exist."));
                    continue;
                }
                string[] vaultDirectories;
                try
                {
                    vaultDirectories = Directory.GetDirectories(rootPath);
                }
                catch (UnauthorizedAccessException ex)
                {
                    probes.Add(CreateRootProbe(rootName, rootPath, "ACCESS-DENIED", ex.Message));
                    continue;
                }
                catch (Exception ex)
                {
                    probes.Add(CreateRootProbe(rootName, rootPath, "ROOT-ERROR", ex.Message));
                    continue;
                }
                if (vaultDirectories.Length == 0)
                {
                    probes.Add(CreateRootProbe(rootName, rootPath, "EMPTY", "Vault root is accessible and contains no vault directories."));
                    continue;
                }
                foreach (string vaultDir in vaultDirectories)
                {
                    VaultDecryptionProbe probe = new VaultDecryptionProbe
                    {
                        RootName = rootName,
                        RootPath = rootPath,
                        VaultGuid = Path.GetFileName(vaultDir),
                        VaultPath = vaultDir,
                        PolicyPath = Path.Combine(vaultDir, "Policy.vpol"),
                        Status = "INVENTORY",
                        Detail = string.Empty
                    };
                    try
                    {
                        string[] policyFiles = Directory.GetFiles(vaultDir, "Policy.vpol");
                        string[] schemaFiles = Directory.GetFiles(vaultDir, "*.vsch");
                        string[] vcrdFiles = Directory.GetFiles(vaultDir, "*.vcrd");
                        probe.PolicyFileCount = policyFiles.Length;
                        probe.SchemaFileCount = schemaFiles.Length;
                        probe.CredentialFileCount = vcrdFiles.Length;
                        probe.PolicyPath = policyFiles.Length > 0 ? policyFiles[0] : probe.PolicyPath;
                        if (probe.PolicyFileCount == 0)
                        {
                            probe.Status = "NO-POLICY";
                            probe.Detail = "Physical directory found without Policy.vpol.";
                        }
                        else if (probe.CredentialFileCount == 0)
                        {
                            probe.Status = probe.SchemaFileCount > 0 ? "POLICY-SCHEMA-ONLY" : "POLICY-ONLY";
                            probe.Detail = "Physical directory contains no .vcrd credential files.";
                        }
                        else
                        {
                            byte[] encryptedPolicy = File.ReadAllBytes(probe.PolicyPath);
                            byte[] decryptedPolicy;
                            string policyDetail;
                            if (!TryDecryptPolicyFile(encryptedPolicy, out decryptedPolicy, out policyDetail))
                                throw new CryptographicException(policyDetail);
                            List<byte[]> candidateKeys = BuildCandidateKeys(decryptedPolicy);
                            if (candidateKeys.Count == 0)
                            {
                                probe.Status = "NO-KEYS";
                                probe.Detail = policyDetail + " | no candidate AES keys were identified";
                            }
                            else
                            {
                                List<string> failures = new List<string>();
                                foreach (string vcrdPath in vcrdFiles)
                                {
                                    string content;
                                    string detail;
                                    if (TryDecryptCredentialFile(vcrdPath, candidateKeys, out content, out detail))
                                        probe.DecryptedCredentialCount++;
                                    else if (failures.Count < 3)
                                        failures.Add(Path.GetFileName(vcrdPath) + ": " + detail);
                                }
                                if (probe.DecryptedCredentialCount > 0)
                                {
                                    probe.Status = "DECRYPTED";
                                    probe.Detail = string.Format("{0}; recovered {1} of {2} physical credential file(s)", policyDetail, probe.DecryptedCredentialCount, probe.CredentialFileCount);
                                }
                                else
                                {
                                    probe.Status = "DECRYPT-FAILED";
                                    probe.Detail = failures.Count > 0 ? policyDetail + " | " + string.Join(" | ", failures) : policyDetail;
                                }
                            }
                        }
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        probe.Status = "ACCESS-DENIED";
                        probe.Detail = ex.Message;
                    }
                    catch (CryptographicException ex)
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
            return probes;
        }
        private static VaultDecryptionProbe CreateRootProbe(string rootName, string rootPath, string status, string detail)
        {
            return new VaultDecryptionProbe
            {
                RootName = rootName,
                RootPath = rootPath,
                VaultGuid = "(root)",
                VaultPath = rootPath,
                PolicyPath = string.Empty,
                PolicyFileCount = 0,
                SchemaFileCount = 0,
                CredentialFileCount = 0,
                DecryptedCredentialCount = 0,
                Status = status,
                Detail = detail
            };
        }
        /// <summary>
        /// Legacy field parser retained for follow-up payload inspection.
        /// The active probe currently validates and counts recognizable payloads without exporting fields.
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
// Vault API (vaultcli.dll) - private/undocumented surface; signatures are version-sensitive
// ------------------------------------------------------------------
public static class VaultNative
{
    // DLL name
    private const string VaultDll = "vaultcli.dll";
    // Vault flags
    public const uint VAULT_OPEN_FLAG_NONE = 0;
    public const uint VAULT_ENUMERATE_ALL_ITEMS = 512;
    // Legacy placeholder retained for compatibility; active paths obtain vault GUIDs from vaultcmd and schema IDs from items.
    public static readonly Guid VaultSchemaWindows = new Guid("3c1b1a8d-9b0b-4b6f-9c1e-8f7b1b3d5c4a");
    // The explicit marshaling declaration encodes offsets 0/8/16 and a 32-byte x64 element size.
    // This is an x64-style layout; a separate 32-bit declaration is not implemented here.
    public enum VAULT_ELEMENT_TYPE : int
    {
        Undefined = -1,
        Boolean = 0,
        Short = 1,
        UnsignedShort = 2,
        Int = 3,
        UnsignedInt = 4,
        Double = 5,
        Guid = 6,
        String = 7,
        ByteArray = 8,
        TimeStamp = 9,
        ProtectedArray = 10,
        Attribute = 11,
        Sid = 12,
        Last = 13
    }
    public enum VAULT_SCHEMA_ELEMENT_ID : int
    {
        Illegal = 0,
        Resource = 1,
        Identity = 2,
        Authenticator = 3,
        Tag = 4,
        PackageSid = 5,
        AppStart = 100,
        AppEnd = 10000
    }
    // ItemValue is a 16-byte native union beginning at offset 16. The 32-byte declaration is
    // required when pProperties is walked as a contiguous VAULT_ITEM_ELEMENT array on x64.
    [StructLayout(LayoutKind.Explicit, Size = 32, CharSet = CharSet.Unicode)]
    public struct VAULT_ITEM_ELEMENT
    {
        [FieldOffset(0)] public int SchemaElementId;
        [FieldOffset(8)] public VAULT_ELEMENT_TYPE Type;
        [FieldOffset(16)] public IntPtr Data;
    }
    // Windows 8 and later include pPackageSid before LastModified. Native pointer alignment follows
    // the process architecture. Flags and the property array are projected for diagnostics only.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct VAULT_ITEM
    {
        public Guid SchemaId;
        public IntPtr pszCredentialFriendlyName;
        public IntPtr pResourceElement;
        public IntPtr pIdentityElement;
        public IntPtr pAuthenticatorElement;
        public IntPtr pPackageSid;
        public ulong LastModified;
        public uint Flags;
        public uint PropertiesCount;
        public IntPtr pProperties;
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
        IntPtr pPackageSid,
        IntPtr hwndOwner,
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
    [DllImport(VaultDll, SetLastError = true, ExactSpelling = true)]
    public static extern void VaultFree(
        IntPtr pMemory
    );
    [DllImport("advapi32.dll", EntryPoint = "ConvertSidToStringSidW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr hMem);
    // Helper to create a VAULT_ITEM_ELEMENT from a string
    public static IntPtr CreateStringElement(string value)
    {
        if (string.IsNullOrEmpty(value))
            return IntPtr.Zero;
        IntPtr ptr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(VAULT_ITEM_ELEMENT)));
        VAULT_ITEM_ELEMENT elem = new VAULT_ITEM_ELEMENT
        {
            SchemaElementId = 0,
            Type = VAULT_ELEMENT_TYPE.String,
            Data = Marshal.StringToCoTaskMemUni(value)
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
    public static string GetSidFromElement(IntPtr pElement)
    {
        if (pElement == IntPtr.Zero) return null;
        try
        {
            VAULT_ITEM_ELEMENT elem = (VAULT_ITEM_ELEMENT)Marshal.PtrToStructure(pElement, typeof(VAULT_ITEM_ELEMENT));
            if (elem.Type != VAULT_ELEMENT_TYPE.Sid || elem.Data == IntPtr.Zero)
                return null;
            IntPtr stringSid = IntPtr.Zero;
            try
            {
                if (!ConvertSidToStringSid(elem.Data, out stringSid) || stringSid == IntPtr.Zero)
                    return null;
                return Marshal.PtrToStringUni(stringSid);
            }
            finally
            {
                if (stringSid != IntPtr.Zero) LocalFree(stringSid);
            }
        }
        catch
        {
            return null;
        }
    }
    public static string ReadInlineHex(IntPtr pElement)
    {
        if (pElement == IntPtr.Zero) return string.Empty;
        try
        {
            byte[] bytes = new byte[16];
            Marshal.Copy(IntPtr.Add(pElement, 16), bytes, 0, bytes.Length);
            return BitConverter.ToString(bytes).Replace("-", string.Empty);
        }
        catch
        {
            return string.Empty;
        }
    }
    public static VaultProperty DecodeElement(IntPtr pElement, int index)
    {
        VaultProperty decoded = new VaultProperty();
        decoded.Index = index;
        if (pElement == IntPtr.Zero)
        {
            decoded.DecodeStatus = "NULL";
            return decoded;
        }
        try
        {
            decoded.SchemaElementId = Marshal.ReadInt32(pElement, 0);
            decoded.TypeCode = Marshal.ReadInt32(pElement, 8);
            decoded.TypeName = Enum.IsDefined(typeof(VAULT_ELEMENT_TYPE), decoded.TypeCode)
                ? ((VAULT_ELEMENT_TYPE)decoded.TypeCode).ToString()
                : "Unknown";
            decoded.RawValueHex = ReadInlineHex(pElement);
            IntPtr value = IntPtr.Add(pElement, 16);
            switch ((VAULT_ELEMENT_TYPE)decoded.TypeCode)
            {
                case VAULT_ELEMENT_TYPE.Boolean:
                    decoded.Value = (Marshal.ReadByte(value) != 0).ToString();
                    break;
                case VAULT_ELEMENT_TYPE.Short:
                    decoded.Value = Marshal.ReadInt16(value).ToString();
                    break;
                case VAULT_ELEMENT_TYPE.UnsignedShort:
                    decoded.Value = unchecked((ushort)Marshal.ReadInt16(value)).ToString();
                    break;
                case VAULT_ELEMENT_TYPE.Int:
                    decoded.Value = Marshal.ReadInt32(value).ToString();
                    break;
                case VAULT_ELEMENT_TYPE.UnsignedInt:
                    decoded.Value = unchecked((uint)Marshal.ReadInt32(value)).ToString();
                    break;
                case VAULT_ELEMENT_TYPE.Double:
                    decoded.Value = BitConverter.Int64BitsToDouble(Marshal.ReadInt64(value)).ToString("R");
                    break;
                case VAULT_ELEMENT_TYPE.Guid:
                    decoded.Value = ((Guid)Marshal.PtrToStructure(value, typeof(Guid))).ToString("D");
                    break;
                case VAULT_ELEMENT_TYPE.String:
                    IntPtr stringPointer = Marshal.ReadIntPtr(value);
                    decoded.Value = stringPointer == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUni(stringPointer);
                    break;
                case VAULT_ELEMENT_TYPE.ByteArray:
                case VAULT_ELEMENT_TYPE.ProtectedArray:
                    uint byteCount = unchecked((uint)Marshal.ReadInt32(value));
                    decoded.Value = string.Format("<{0} bytes>", byteCount);
                    break;
                case VAULT_ELEMENT_TYPE.TimeStamp:
                    long fileTime = Marshal.ReadInt64(value);
                    decoded.Value = fileTime <= 0 ? fileTime.ToString() : DateTime.FromFileTimeUtc(fileTime).ToString("o");
                    break;
                case VAULT_ELEMENT_TYPE.Sid:
                    decoded.Value = GetSidFromElement(pElement) ?? string.Empty;
                    break;
                default:
                    decoded.Value = "0x" + decoded.RawValueHex;
                    break;
            }
            decoded.DecodeStatus = "OK";
        }
        catch (Exception ex)
        {
            decoded.DecodeStatus = ex.GetType().Name + ": " + ex.Message;
        }
        return decoded;
    }
    public static List<VaultProperty> DecodePropertyArray(IntPtr pProperties, uint count, out string layout)
    {
        List<VaultProperty> properties = new List<VaultProperty>();
        layout = "None";
        if (count == 0 || pProperties == IntPtr.Zero) return properties;
        if (count > 128)
        {
            layout = "Rejected count " + count.ToString();
            return properties;
        }
        bool contiguous = false;
        try
        {
            int firstId = Marshal.ReadInt32(pProperties, 0);
            int firstType = Marshal.ReadInt32(pProperties, 8);
            contiguous = firstId >= 0 && firstId <= 10000 && firstType >= -1 && firstType <= 13;
        }
        catch { }
        layout = contiguous ? "Contiguous32" : "PointerArray";
        int propertySize = Marshal.SizeOf(typeof(VAULT_ITEM_ELEMENT));
        for (uint propertyIndex = 0; propertyIndex < count; propertyIndex++)
        {
            IntPtr propertyPointer = IntPtr.Zero;
            try
            {
                if (contiguous)
                {
                    int propertyOffset = checked((int)(propertyIndex * (uint)propertySize));
                    propertyPointer = IntPtr.Add(pProperties, propertyOffset);
                }
                else
                {
                    int pointerOffset = checked((int)(propertyIndex * (uint)IntPtr.Size));
                    propertyPointer = Marshal.ReadIntPtr(pProperties, pointerOffset);
                }
                properties.Add(DecodeElement(propertyPointer, (int)propertyIndex));
            }
            catch (Exception ex)
            {
                properties.Add(new VaultProperty
                {
                    Index = (int)propertyIndex,
                    DecodeStatus = ex.GetType().Name + ": " + ex.Message
                });
            }
        }
        return properties;
    }
}
public class VaultProperty
{
    public int Index { get; set; }
    public int SchemaElementId { get; set; }
    public int TypeCode { get; set; }
    public string TypeName { get; set; }
    public string Value { get; set; }
    public string RawValueHex { get; set; }
    public string DecodeStatus { get; set; }
    public override string ToString()
    {
        return string.Format("#{0} ID={1} {2}={3} [raw:{4}; {5}]", Index, SchemaElementId, TypeName, Value, RawValueHex, DecodeStatus);
    }
}
// Managed projection used to correlate native Vault metadata with vaultcmd's rendered fields.
public class VaultCredential
{
    public string FriendlyName { get; set; }
    public string Resource { get; set; }
    public string Identity { get; set; }
    public string Authenticator { get; set; }
    public Guid SchemaId { get; set; }
    public ulong LastModified { get; set; }
    public string PackageSid { get; set; }
    public uint Flags { get; set; }
    public string FlagsHex { get; set; }
    public string FlagBits { get; set; }
    public uint PropertiesCount { get; set; }
    public List<VaultProperty> Properties { get; set; }
    public string PropertyLayout { get; set; }
    public string PropertySummary { get; set; }
    public string MetadataSource { get; set; }
    public int GetItemHResult { get; set; }
    public VaultCredential() { }
    public static VaultCredential FromNativeItem(IntPtr pItem)
    {
        return FromNativeItem(pItem, false);
    }
    public static VaultCredential FromNativeItem(IntPtr pItem, bool includeSecret)
    {
        if (pItem == IntPtr.Zero) return null;
        try
        {
            VaultNative.VAULT_ITEM item = (VaultNative.VAULT_ITEM)Marshal.PtrToStructure(pItem, typeof(VaultNative.VAULT_ITEM));
            string resource = VaultNative.GetStringFromElement(item.pResourceElement);
            string identity = VaultNative.GetStringFromElement(item.pIdentityElement);
            string authenticator = includeSecret ? VaultNative.GetStringFromElement(item.pAuthenticatorElement) : null;
            string friendlyName = Marshal.PtrToStringUni(item.pszCredentialFriendlyName);
            string propertyLayout;
            List<VaultProperty> properties = VaultNative.DecodePropertyArray(item.pProperties, item.PropertiesCount, out propertyLayout);
            List<string> setBits = new List<string>();
            for (int bit = 0; bit < 32; bit++)
            {
                uint mask = 1u << bit;
                if ((item.Flags & mask) != 0) setBits.Add(bit.ToString());
            }
            var cred = new VaultCredential
            {
                FriendlyName = friendlyName,
                Resource = resource,
                Identity = identity,
                Authenticator = authenticator,
                SchemaId = item.SchemaId,
                LastModified = item.LastModified,
                PackageSid = VaultNative.GetSidFromElement(item.pPackageSid),
                Flags = item.Flags,
                FlagsHex = string.Format("0x{0:X8}", item.Flags),
                FlagBits = setBits.Count == 0 ? "(none)" : string.Join(",", setBits.ToArray()),
                PropertiesCount = item.PropertiesCount,
                Properties = properties,
                PropertyLayout = propertyLayout,
                PropertySummary = properties.Count == 0 ? "(none)" : string.Join(" | ", properties.ConvertAll(delegate(VaultProperty p) { return p.ToString(); }).ToArray())
            };
            return cred;
        }
        catch (Exception)
        {
            return null;
        }
    }
    public void ClearSecret()
    {
        Authenticator = null;
    }
    public void Dispose()
    {
        // The wrapper owns managed copies only; EnumerateItems frees the native contiguous buffer.
        ClearSecret();
    }
}
// Opens one vault GUID and provides logical enumeration plus core-element create/delete operations.
public class VaultManager : IDisposable
{
    private IntPtr vaultHandle = IntPtr.Zero;
    private Guid vaultGuid;
    public int LastOpenHResult { get; private set; }
    public int LastEnumerateHResult { get; private set; }
    public int LastReportedItemCount { get; private set; }
    public int LastGetItemFailureCount { get; private set; }
    public string LastEnumerationStage { get; private set; }
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
        return EnumerateItems(false);
    }
    public List<VaultCredential> EnumerateItems(bool includeSecrets)
    {
        List<VaultCredential> items = new List<VaultCredential>();
        LastEnumerateHResult = 0;
        LastReportedItemCount = 0;
        LastGetItemFailureCount = 0;
        LastEnumerationStage = "VaultEnumerateItems";
        uint count = 0;
        IntPtr itemBuffer = IntPtr.Zero;
        int hr = VaultNative.VaultEnumerateItems(vaultHandle, VaultNative.VAULT_ENUMERATE_ALL_ITEMS, out count, out itemBuffer);
        LastEnumerateHResult = hr;
        LastReportedItemCount = (int)count;
        if (hr != 0 || count == 0 || itemBuffer == IntPtr.Zero)
            return items;
        if (count > 100000)
            throw new InvalidDataException("VaultEnumerateItems returned an implausible item count.");
        try
        {
            int itemSize = Marshal.SizeOf(typeof(VaultNative.VAULT_ITEM));
            for (uint i = 0; i < count; i++)
            {
                int offset = checked((int)(i * (uint)itemSize));
                IntPtr pItem = IntPtr.Add(itemBuffer, offset);
                VaultNative.VAULT_ITEM enumeratedItem = (VaultNative.VAULT_ITEM)Marshal.PtrToStructure(pItem, typeof(VaultNative.VAULT_ITEM));
                IntPtr pFullItem = IntPtr.Zero;
                Guid schemaId = enumeratedItem.SchemaId;
                int getItemHr = VaultNative.VaultGetItem(
                    vaultHandle,
                    ref schemaId,
                    enumeratedItem.pResourceElement,
                    enumeratedItem.pIdentityElement,
                    enumeratedItem.pPackageSid,
                    IntPtr.Zero,
                    0,
                    out pFullItem
                );
                VaultCredential credential = null;
                try
                {
                    if (getItemHr == 0 && pFullItem != IntPtr.Zero)
                    {
                        credential = VaultCredential.FromNativeItem(pFullItem, includeSecrets);
                        if (credential != null) credential.MetadataSource = "VaultGetItem";
                    }
                    else
                    {
                        LastGetItemFailureCount++;
                    }
                    if (credential == null)
                    {
                        credential = VaultCredential.FromNativeItem(pItem, includeSecrets);
                        if (credential != null) credential.MetadataSource = "VaultEnumerateItems";
                    }
                    if (credential != null) credential.GetItemHResult = getItemHr;
                }
                finally
                {
                    if (pFullItem != IntPtr.Zero) VaultNative.VaultFree(pFullItem);
                }
                if (credential != null)
                    items.Add(credential);
            }
        }
        finally
        {
            VaultNative.VaultFree(itemBuffer);
        }
        return items;
    }
    public string GetLastEnumerationSummary()
    {
        if (LastOpenHResult != 0)
            return string.Format("VaultOpenVault HRESULT: 0x{0:X8}", LastOpenHResult);
        if (LastEnumerateHResult != 0)
            return string.Format("VaultEnumerateItems HRESULT: 0x{0:X8}", LastEnumerateHResult);
        if (LastReportedItemCount == 0)
            return "VaultEnumerateItems returned zero items";
        return string.Format("VaultEnumerateItems returned {0} item(s); VaultGetItem metadata fallback(s): {1}", LastReportedItemCount, LastGetItemFailureCount);
    }
    public void CreateItem(string friendlyName, string resource, string identity, string authenticator, Guid schemaId)
    {
        IntPtr pResource = VaultNative.CreateStringElement(resource);
        IntPtr pIdentity = VaultNative.CreateStringElement(identity);
        IntPtr pAuthenticator = VaultNative.CreateStringElement(authenticator);
        IntPtr pFriendlyName = Marshal.StringToCoTaskMemUni(friendlyName);
        try
        {
            // Create only the core string elements. The diagnostic correlation intentionally does not turn
            // observed flag bits or property IDs into write semantics without schema-specific confirmation.
            VaultNative.VAULT_ITEM item = new VaultNative.VAULT_ITEM
            {
                SchemaId = schemaId,
                pszCredentialFriendlyName = pFriendlyName,
                pResourceElement = pResource,
                pIdentityElement = pIdentity,
                pAuthenticatorElement = pAuthenticator,
                pPackageSid = IntPtr.Zero,
                LastModified = 0,
                Flags = 0,
                PropertiesCount = 0,
                pProperties = IntPtr.Zero
            };
            int hr = VaultNative.VaultCreateItem(vaultHandle, ref item, 0);
            if (hr != 0)
            {
                throw new InvalidOperationException(string.Format("VaultCreateItem failed with HRESULT 0x{0:X8}", hr));
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
    public void DeleteItem(VaultCredential cred)
    {
        if (cred == null) throw new ArgumentNullException("cred");
        Guid schemaId = cred.SchemaId;
        // Recreate the core key elements required by VaultDeleteItem from the managed projection.
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
            // Release the temporary unmanaged element structures created for this call.
            if (pResource != IntPtr.Zero) VaultNative.FreeElement(pResource);
            if (pIdentity != IntPtr.Zero) VaultNative.FreeElement(pIdentity);
            if (pAuthenticator != IntPtr.Zero) VaultNative.FreeElement(pAuthenticator);
        }
    }
    // Update is a non-transactional delete followed by create; correlated metadata is not preserved.
    public void UpdateItem(VaultCredential oldCred, string newFriendlyName, string newResource, string newIdentity, string newAuthenticator)
    {
        DeleteItem(oldCred);
        CreateItem(newFriendlyName, newResource, newIdentity, newAuthenticator, oldCred.SchemaId);
    }
}
// ------------------------------------------------------------------
// Current-user Personal certificate inventory used by certificate-backed CredMan entries
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
            // Compatibility fallback for runtimes where PublicKey.Key is unavailable or obsolete.
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
"@
$ExpectedEngineBuild = 'v4-7-docked-listview-scroll-ps51-csharp5-20261110a'
$LoadedEngineType = ([System.Management.Automation.PSTypeName]'SecurityEngineMatrix').Type
if ($null -ne $LoadedEngineType) {
    $BuildField = $LoadedEngineType.GetField('CompatibilityBuild', [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static)
    $LoadedBuild = if ($null -ne $BuildField) { [string]$BuildField.GetValue($null) } else { '' }
    if ($LoadedBuild -ne $ExpectedEngineBuild) {
        throw "An older embedded KeyMgr engine is already loaded in this PowerShell process. Close the host completely and start this file in a fresh Windows PowerShell 5.1 process."
    }
    script:Write-KeyMgrRuntimeLog 'COMPILE' "Compatible embedded engine is already loaded: $LoadedBuild"
} else {
    script:Write-KeyMgrRuntimeLog 'COMPILE' 'Loading .NET Framework references for the embedded C# 5 engine.'
    Add-Type -AssemblyName System.Core -ErrorAction Stop
    Add-Type -AssemblyName System.Security -ErrorAction Stop
    Add-Type -AssemblyName System.DirectoryServices -ErrorAction Stop
    Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
    $null = [System.Security.Cryptography.Aes]
    $null = [System.Security.Cryptography.X509Certificates.X509Certificate2]
    $null = [System.Security.Cryptography.ProtectedData]
    $null = [System.Text.RegularExpressions.Regex]
    $null = [System.Linq.Enumerable]
    $null = [Microsoft.Win32.SafeHandles.SafeFileHandle]
    $null = [System.DirectoryServices.DirectoryEntry]
    $null = [System.Web.Script.Serialization.JavaScriptSerializer]
    # Avoid passing every assembly in the AppDomain to the Windows PowerShell 5.1 CodeDOM compiler.
    # Facade/WinMD/dynamic assemblies can make Add-Type fail unpredictably on .NET Framework.
    $ReferencedAssemblies = @(
        [System.Uri].Assembly.Location,
        [System.Linq.Enumerable].Assembly.Location,
        [System.Security.Cryptography.ProtectedData].Assembly.Location,
        [System.DirectoryServices.DirectoryEntry].Assembly.Location,
        [System.Web.Script.Serialization.JavaScriptSerializer].Assembly.Location
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique
    try {
        # Windows PowerShell 5.1 Add-Type has no -CompilerOptions parameter. Keep the invocation
        # limited to parameters present in its TypeDefinition parameter set and pin references to
        # a real string array so PowerShell 5.1 does not have to infer a pipeline-produced type.
        $addTypeParameters = @{
            TypeDefinition = $SourceCode
            Language = 'CSharp'
            ReferencedAssemblies = [string[]]$ReferencedAssemblies
            ErrorAction = 'Stop'
        }
        Microsoft.PowerShell.Utility\Add-Type @addTypeParameters
        script:Write-KeyMgrRuntimeLog 'COMPILE' 'Embedded C# 5-compatible source compiled successfully by Windows PowerShell 5.1 Add-Type without unsupported compiler switches.'
    } catch {
        script:Write-KeyMgrRuntimeLog 'COMPILE-FAIL' $_
        throw
    }
}
# ==============================================
# POWERSHELL INTEROP AND UI SUPPORT
# ==============================================
# ==============================================
# 2. PROVIDER CAPABILITY AND OPERATION-RESULT MODEL
# ==============================================
# Capabilities describe supported behavior once and are consumed by controls, menus, and
# dispatchers. They do not imply that the current account has access to every provider instance.
$Global:KeyMgrProviderCapabilities = [ordered]@{
    WebComposite = [pscustomobject]@{
        ProviderId = 'WebComposite'; DisplayName = 'Web Credentials'; CanEnumerate = $true
        CanReadSecret = $false; CanCreate = $true; CanEdit = $false; CanDelete = $false
        CanBackup = $false; CanRestore = $false; CanExport = $true; CanSetPersistence = $false
        CanSetVaultMetadata = $false; RequiresElevation = $false; RequiresExternalProcess = $false
    }
    PasswordVault = [pscustomobject]@{
        ProviderId = 'PasswordVault'; DisplayName = 'WinRT PasswordVault'; CanEnumerate = $true
        CanReadSecret = $true; CanCreate = $true; CanEdit = $true; CanDelete = $true
        CanBackup = $false; CanRestore = $false; CanExport = $true; CanSetPersistence = $false
        CanSetVaultMetadata = $false; RequiresElevation = $false; RequiresExternalProcess = $false
    }
    VaultCmd = [pscustomobject]@{
        ProviderId = 'VaultCmd'; DisplayName = 'Windows Vault (vaultcmd.exe)'; CanEnumerate = $true
        CanReadSecret = $false; CanCreate = $true; CanEdit = $true; CanDelete = $true
        CanBackup = $false; CanRestore = $false; CanExport = $true; CanSetPersistence = $false
        CanSetVaultMetadata = $false; RequiresElevation = $false; RequiresExternalProcess = $true
    }
    VaultApi = [pscustomobject]@{
        ProviderId = 'VaultApi'; DisplayName = 'Windows Vault API projection'; CanEnumerate = $true
        CanReadSecret = $true; CanCreate = $false; CanEdit = $false; CanDelete = $false
        CanBackup = $false; CanRestore = $false; CanExport = $true; CanSetPersistence = $false
        CanSetVaultMetadata = $false; RequiresElevation = $false; RequiresExternalProcess = $false
    }
    CredManCore = [pscustomobject]@{
        ProviderId = 'CredManCore'; DisplayName = 'Win32 Credential Manager'; CanEnumerate = $true
        CanReadSecret = $true; CanCreate = $true; CanEdit = $true; CanDelete = $true
        CanBackup = $true; CanRestore = $true; CanExport = $true; CanSetPersistence = $true
        CanSetVaultMetadata = $false; RequiresElevation = $false; RequiresExternalProcess = $false
    }
    CredManCertificate = [pscustomobject]@{
        ProviderId = 'CredManCertificate'; DisplayName = 'Certificate credentials'; CanEnumerate = $true
        CanReadSecret = $false; CanCreate = $true; CanEdit = $true; CanDelete = $true
        CanBackup = $true; CanRestore = $true; CanExport = $true; CanSetPersistence = $true
        CanSetVaultMetadata = $false; RequiresElevation = $false; RequiresExternalProcess = $false
    }
    CredManGeneric = [pscustomobject]@{
        ProviderId = 'CredManGeneric'; DisplayName = 'Generic credentials'; CanEnumerate = $true
        CanReadSecret = $true; CanCreate = $true; CanEdit = $true; CanDelete = $true
        CanBackup = $true; CanRestore = $true; CanExport = $true; CanSetPersistence = $true
        CanSetVaultMetadata = $false; RequiresElevation = $false; RequiresExternalProcess = $false
    }
    Edge = [pscustomobject]@{
        ProviderId = 'Edge'; DisplayName = 'Edge Chromium (staged)'; CanEnumerate = $true
        CanReadSecret = $true; CanCreate = $true; CanEdit = $true; CanDelete = $true
        CanBackup = $true; CanRestore = $true; CanExport = $true; CanSetPersistence = $false
        CanSetVaultMetadata = $false; RequiresElevation = $false; RequiresExternalProcess = $false
    }
    IEIntelliForms = [pscustomobject]@{
        ProviderId = 'IEIntelliForms'; DisplayName = 'IE7/9 IntelliForms Storage2'; CanEnumerate = $true
        CanReadSecret = $false; CanCreate = $false; CanEdit = $false; CanDelete = $false
        CanBackup = $false; CanRestore = $false; CanExport = $true; CanSetPersistence = $false
        CanSetVaultMetadata = $false; RequiresElevation = $false; RequiresExternalProcess = $false
    }
    Diagnostics = [pscustomobject]@{
        ProviderId = 'Diagnostics'; DisplayName = 'Diagnostics'; CanEnumerate = $true
        CanReadSecret = $false; CanCreate = $false; CanEdit = $false; CanDelete = $false
        CanBackup = $false; CanRestore = $false; CanExport = $true; CanSetPersistence = $false
        CanSetVaultMetadata = $false; RequiresElevation = $false; RequiresExternalProcess = $false
    }
    Unknown = [pscustomobject]@{
        ProviderId = 'Unknown'; DisplayName = 'Unknown provider'; CanEnumerate = $false
        CanReadSecret = $false; CanCreate = $false; CanEdit = $false; CanDelete = $false
        CanBackup = $false; CanRestore = $false; CanExport = $false; CanSetPersistence = $false
        CanSetVaultMetadata = $false; RequiresElevation = $false; RequiresExternalProcess = $false
    }
}
foreach ($capabilityRecord in $Global:KeyMgrProviderCapabilities.Values) {
    $supportsVerifiedMutation = $capabilityRecord.ProviderId -in @('PasswordVault','VaultCmd','CredManCore','CredManCertificate','CredManGeneric','Edge')
    $supportsRollback = $capabilityRecord.ProviderId -in @('PasswordVault','CredManCore','CredManCertificate','CredManGeneric','Edge')
    $capabilityRecord | Add-Member -NotePropertyName SupportsVerifiedMutation -NotePropertyValue $supportsVerifiedMutation -Force
    $capabilityRecord | Add-Member -NotePropertyName SupportsRollback -NotePropertyValue $supportsRollback -Force
}
$Global:KeyMgrOperationHistory = New-Object System.Collections.Generic.List[System.Object]
$script:LastKeyMgrOperationResult = $null
function Get-KeyMgrProviderCapabilities {
    param([string]$ProviderId)
    if ([string]::IsNullOrWhiteSpace($ProviderId) -or -not $Global:KeyMgrProviderCapabilities.Contains($ProviderId)) {
        return $Global:KeyMgrProviderCapabilities['Unknown']
    }
    return $Global:KeyMgrProviderCapabilities[$ProviderId]
}
function Get-KeyMgrActiveProviderContext {
    $providerId = 'Unknown'
    $providerName = 'Unknown provider'
    $selectedItem = $null
    $activeGrid = $Global:LastFocusedGrid
    if ($null -eq $TabControl -or $TabControl.IsDisposed) {
        $caps = script:Get-KeyMgrProviderCapabilities -ProviderId $providerId
        return [pscustomobject]@{ ProviderId = $providerId; ProviderName = $providerName; Capabilities = $caps; ActiveGrid = $activeGrid; SelectedItem = $null; HasSelection = $false; Target = '' }
    }
    switch ($TabControl.SelectedIndex) {
        0 {
            $providerId = 'WebComposite'
            if ($null -ne $ListViewWeb -and -not $ListViewWeb.IsDisposed -and $ListViewWeb.SelectedItems.Count -gt 0) {
                $activeGrid = $ListViewWeb
                $selectedItem = $ListViewWeb.SelectedItems[0].Tag
                if ($null -ne $selectedItem -and -not [string]::IsNullOrWhiteSpace([string]$selectedItem.Provider)) {
                    $providerId = [string]$selectedItem.Provider
                }
            }
        }
        1 {
            if ($Global:LastFocusedGrid -eq $LV_WinCert) { $providerId = 'CredManCertificate'; $activeGrid = $LV_WinCert }
            elseif ($Global:LastFocusedGrid -eq $LV_WinGen) { $providerId = 'CredManGeneric'; $activeGrid = $LV_WinGen }
            else { $providerId = 'CredManCore'; $activeGrid = $LV_WinCore }
            if ($null -ne $activeGrid -and -not $activeGrid.IsDisposed -and $activeGrid.SelectedItems.Count -gt 0) {
                $selectedItem = $activeGrid.SelectedItems[0].Tag
            }
        }
        2 {
            $activeGrid = script:Get-KeyMgrActiveBrowserListView
            $browserRow = script:Get-SelectedBrowserCredentialRow
            if ($null -ne $browserRow -and $browserRow.PSObject.Properties['BrowserProvider'] -and [string]$browserRow.BrowserProvider -in @('IE11','LegacyEdge') -and $null -ne $browserRow.SourceItem) {
                $selectedItem = $browserRow.SourceItem
                $providerId = if (-not [string]::IsNullOrWhiteSpace([string]$browserRow.Provider)) { [string]$browserRow.Provider } else { 'VaultApi' }
            } elseif ($null -ne $browserRow) {
                $selectedItem = $browserRow
                $providerId = if ($browserRow.PSObject.Properties['Provider'] -and -not [string]::IsNullOrWhiteSpace([string]$browserRow.Provider)) { [string]$browserRow.Provider } else { 'Edge' }
            } else {
                $providerId = switch ($BrowserCategoryTabs.SelectedIndex) { 1 { 'WebComposite' } 2 { 'WebComposite' } 3 { 'IEIntelliForms' } default { 'Edge' } }
            }
        }
        3 {
            $providerId = 'Diagnostics'
            if ($null -ne $activeGrid -and -not $activeGrid.IsDisposed -and $activeGrid.SelectedItems.Count -gt 0) {
                $selectedItem = $activeGrid.SelectedItems[0].Tag
            }
        }
    }
    $caps = script:Get-KeyMgrProviderCapabilities -ProviderId $providerId
    $providerName = $caps.DisplayName
    $target = ''
    if ($null -ne $selectedItem) {
        foreach ($propertyName in @('Target','Website','Resource','ProfileName')) {
            $property = $selectedItem.PSObject.Properties[$propertyName]
            if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
                $target = [string]$property.Value
                break
            }
        }
    }
    return [pscustomobject]@{
        ProviderId = $providerId
        ProviderName = $providerName
        Capabilities = $caps
        ActiveGrid = $activeGrid
        SelectedItem = $selectedItem
        HasSelection = ($null -ne $selectedItem)
        Target = $target
    }
}
function Get-KeyMgrOperationContext {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Add','Edit','Remove','Export')]
        [string]$Operation
    )
    $context = script:Get-KeyMgrActiveProviderContext
    # Web creation targets the composite Web view and asks the user to choose PasswordVault or
    # vaultcmd. A selected read-only VaultApi projection must not disable creation for the view.
    if ($Operation -eq 'Add' -and $null -ne $TabControl -and $TabControl.SelectedIndex -eq 2) {
        $browserProviderId = switch ($BrowserCategoryTabs.SelectedIndex) { 1 { 'WebComposite' } 2 { 'WebComposite' } 3 { 'IEIntelliForms' } default { 'Edge' } }
        $caps = script:Get-KeyMgrProviderCapabilities -ProviderId $browserProviderId
        return [pscustomobject]@{ ProviderId = $browserProviderId; ProviderName = $caps.DisplayName; Capabilities = $caps; ActiveGrid = $context.ActiveGrid; SelectedItem = $null; HasSelection = $false; Target = '' }
    }
    if ($Operation -eq 'Add' -and $null -ne $TabControl -and $TabControl.SelectedIndex -eq 0) {
        $caps = script:Get-KeyMgrProviderCapabilities -ProviderId 'WebComposite'
        return [pscustomobject]@{
            ProviderId = 'WebComposite'; ProviderName = $caps.DisplayName; Capabilities = $caps
            ActiveGrid = $context.ActiveGrid; SelectedItem = $context.SelectedItem
            HasSelection = $context.HasSelection; Target = $context.Target
        }
    }
    return $context
}
function Test-KeyMgrProviderCapability {
    param(
        [Parameter(Mandatory=$true)][string]$Capability,
        $Context = $null
    )
    if ($null -eq $Context) { $Context = script:Get-KeyMgrActiveProviderContext }
    if ($null -eq $Context -or $null -eq $Context.Capabilities) { return $false }
    $property = $Context.Capabilities.PSObject.Properties[$Capability]
    return ($null -ne $property -and [bool]$property.Value)
}
function New-KeyMgrOperationResult {
    param(
        [Parameter(Mandatory=$true)][string]$Operation,
        [Parameter(Mandatory=$true)][string]$Provider,
        [string]$Target = '',
        [bool]$Success = $false,
        [bool]$Changed = $false,
        [bool]$Cancelled = $false,
        [string]$ErrorCode = '',
        [string]$DiagnosticMessage = '',
        [bool]$RollbackAvailable = $false,
        $Transaction = $null,
        [datetime]$StartedAt = (Get-Date)
    )
    $status = if ($Cancelled) { 'Cancelled' } elseif ($Success) { 'Succeeded' } else { 'Failed' }
    return [pscustomobject]@{
        OperationId = [guid]::NewGuid().ToString('N')
        TransactionId = if ($null -ne $Transaction) { [string]$Transaction.TransactionId } else { '' }
        StartedAt = $StartedAt
        CompletedAt = Get-Date
        Status = $status
        Success = $Success
        Changed = $Changed
        Cancelled = $Cancelled
        Provider = $Provider
        Operation = $Operation
        Target = $Target
        ErrorCode = $ErrorCode
        RollbackAvailable = if ($null -ne $Transaction) { [bool]$Transaction.RollbackAvailable } else { $RollbackAvailable }
        SnapshotStatus = if ($null -ne $Transaction) { [string]$Transaction.SnapshotStatus } else { 'NotRequested' }
        VerificationStatus = if ($null -ne $Transaction) { [string]$Transaction.VerificationStatus } else { 'NotRequested' }
        RollbackAttempted = if ($null -ne $Transaction) { [bool]$Transaction.RollbackAttempted } else { $false }
        RollbackSucceeded = if ($null -ne $Transaction) { [bool]$Transaction.RollbackSucceeded } else { $false }
        RollbackDiagnostic = if ($null -ne $Transaction) { [string]$Transaction.RollbackDiagnostic } else { '' }
        DiagnosticMessage = $DiagnosticMessage
    }
}
function Register-KeyMgrOperationResult {
    param([Parameter(Mandatory=$true)]$Result)
    $script:LastKeyMgrOperationResult = $Result
    [void]$Global:KeyMgrOperationHistory.Add($Result)
    while ($Global:KeyMgrOperationHistory.Count -gt 100) { $Global:KeyMgrOperationHistory.RemoveAt(0) }
    $logMessage = '{0} | {1} | {2} | Changed={3} | Target={4}' -f $Result.Operation, $Result.Provider, $Result.Status, $Result.Changed, $Result.Target
    if (-not [string]::IsNullOrWhiteSpace($Result.TransactionId)) { $logMessage += ' | Tx=' + $Result.TransactionId }
    if ($Result.VerificationStatus -ne 'NotRequested') { $logMessage += ' | Verify=' + $Result.VerificationStatus }
    if ($Result.RollbackAttempted) { $logMessage += ' | Rollback=' + $(if ($Result.RollbackSucceeded) { 'Succeeded' } else { 'Failed' }) }
    if (-not [string]::IsNullOrWhiteSpace($Result.ErrorCode)) { $logMessage += ' | Error=' + $Result.ErrorCode }
    if (-not [string]::IsNullOrWhiteSpace($Result.DiagnosticMessage)) { $logMessage += ' | ' + $Result.DiagnosticMessage }
    script:Write-KeyMgrRuntimeLog 'OPERATION' $logMessage
    if (-not $Result.Success -and -not $Result.Cancelled) {
        try {
            if ($Global:DiagnosticListViews -and $Global:DiagnosticListViews.ContainsKey('ErrorLog')) {
                script:Add-DiagnosticErrorLogEntry -Source ("{0} / {1}" -f $Result.Provider, $Result.Operation) -Message $Result.DiagnosticMessage
            }
        } catch {}
    }
    return $Result
}
function Complete-KeyMgrOperation {
    param(
        [Parameter(Mandatory=$true)][string]$Operation,
        [Parameter(Mandatory=$true)][string]$Provider,
        [string]$Target = '',
        [bool]$Success = $false,
        [bool]$Changed = $false,
        [bool]$Cancelled = $false,
        [string]$ErrorCode = '',
        [string]$DiagnosticMessage = '',
        [bool]$RollbackAvailable = $false,
        $Transaction = $null,
        [datetime]$StartedAt = (Get-Date)
    )
    $result = script:New-KeyMgrOperationResult -Operation $Operation -Provider $Provider -Target $Target -Success $Success -Changed $Changed -Cancelled $Cancelled -ErrorCode $ErrorCode -DiagnosticMessage $DiagnosticMessage -RollbackAvailable $RollbackAvailable -Transaction $Transaction -StartedAt $StartedAt
    return script:Register-KeyMgrOperationResult -Result $result
}
function Show-KeyMgrUnsupportedOperation {
    param([string]$Operation, $Context)
    $message = "The active provider '$($Context.ProviderName)' does not support $($Operation.ToLowerInvariant())."
    [System.Windows.Forms.MessageBox]::Show($message, 'Operation not supported', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    return script:Complete-KeyMgrOperation -Operation $Operation -Provider $Context.ProviderName -Target $Context.Target -DiagnosticMessage $message
}
function Show-KeyMgrProviderCapabilities {
    $context = script:Get-KeyMgrActiveProviderContext
    $caps = $context.Capabilities
    $lines = New-Object System.Collections.Generic.List[string]
    [void]$lines.Add('Active provider: ' + $context.ProviderName)
    [void]$lines.Add('Provider ID: ' + $context.ProviderId)
    [void]$lines.Add('Selection: ' + $(if ($context.HasSelection) { $context.Target } else { '[none]' }))
    [void]$lines.Add('')
    foreach ($name in @('CanEnumerate','CanReadSecret','CanCreate','CanEdit','CanDelete','CanBackup','CanRestore','CanExport','CanSetPersistence','CanSetVaultMetadata','SupportsVerifiedMutation','SupportsRollback','RequiresElevation','RequiresExternalProcess')) {
        [void]$lines.Add(('{0,-25} {1}' -f $name, [bool]$caps.$name))
    }
    [System.Windows.Forms.MessageBox]::Show(($lines -join [Environment]::NewLine), 'Active Provider Capabilities', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
}
function Show-KeyMgrOperationHistory {
    $historyForm = New-Object System.Windows.Forms.Form
    $historyForm.Text = 'KeyMgr Operation History'
    $historyForm.StartPosition = 'CenterParent'
    $historyForm.Size = New-Object System.Drawing.Size(1180, 420)
    $historyForm.MinimumSize = New-Object System.Drawing.Size(700, 300)
    $historyForm.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $historyList = New-Object System.Windows.Forms.ListView
    $historyList.Dock = [System.Windows.Forms.DockStyle]::Fill
    $historyList.View = [System.Windows.Forms.View]::Details
    $historyList.FullRowSelect = $true
    $historyList.GridLines = $true
    [void]$historyList.Columns.Add('Completed', 145)
    [void]$historyList.Columns.Add('Status', 80)
    [void]$historyList.Columns.Add('Provider', 150)
    [void]$historyList.Columns.Add('Operation', 90)
    [void]$historyList.Columns.Add('Changed', 65)
    [void]$historyList.Columns.Add('Snapshot', 85)
    [void]$historyList.Columns.Add('Verify', 75)
    [void]$historyList.Columns.Add('Rollback', 75)
    [void]$historyList.Columns.Add('Target', 180)
    [void]$historyList.Columns.Add('Error', 95)
    [void]$historyList.Columns.Add('Diagnostic', 250)
    for ($i = $Global:KeyMgrOperationHistory.Count - 1; $i -ge 0; $i--) {
        $entry = $Global:KeyMgrOperationHistory[$i]
        $item = New-Object System.Windows.Forms.ListViewItem($entry.CompletedAt.ToString('yyyy-MM-dd HH:mm:ss'))
        [void]$item.SubItems.Add([string]$entry.Status)
        [void]$item.SubItems.Add([string]$entry.Provider)
        [void]$item.SubItems.Add([string]$entry.Operation)
        [void]$item.SubItems.Add([string]$entry.Changed)
        [void]$item.SubItems.Add([string]$entry.SnapshotStatus)
        [void]$item.SubItems.Add([string]$entry.VerificationStatus)
        $rollbackText = if ($entry.RollbackAttempted) { if ($entry.RollbackSucceeded) { 'Succeeded' } else { 'Failed' } } elseif ($entry.RollbackAvailable) { 'Supported' } else { 'N/A' }
        [void]$item.SubItems.Add($rollbackText)
        [void]$item.SubItems.Add([string]$entry.Target)
        [void]$item.SubItems.Add([string]$entry.ErrorCode)
        [void]$item.SubItems.Add([string]$entry.DiagnosticMessage)
        if ($entry.Status -eq 'Failed') { $item.ForeColor = [System.Drawing.Color]::Red }
        elseif ($entry.Status -eq 'Succeeded') { $item.ForeColor = [System.Drawing.Color]::DarkGreen }
        elseif ($entry.Status -eq 'Cancelled') { $item.ForeColor = [System.Drawing.Color]::DimGray }
        [void]$historyList.Items.Add($item)
    }
    if ($historyList.Items.Count -eq 0) {
        $item = New-Object System.Windows.Forms.ListViewItem('[No mutation operations have been recorded in this session]')
        $item.ForeColor = [System.Drawing.Color]::Gray
        [void]$historyList.Items.Add($item)
    }
    $historyForm.Controls.Add($historyList)
    [void]$historyForm.ShowDialog($MainForm)
}

# ==============================================
# 3. TRANSACTION, SNAPSHOT, VERIFICATION, AND SECRET-LIFETIME SUPPORT
# ==============================================
function New-KeyMgrTransaction {
    param([string]$ProviderId, [string]$Operation, [string]$Target)
    return [pscustomobject]@{
        TransactionId = [guid]::NewGuid().ToString('N')
        ProviderId = $ProviderId
        Operation = $Operation
        Target = $Target
        SnapshotStatus = 'Pending'
        VerificationStatus = 'Pending'
        RollbackAvailable = $false
        RollbackAttempted = $false
        RollbackSucceeded = $false
        RollbackDiagnostic = ''
        Success = $false
        Changed = $false
        ErrorCode = ''
        DiagnosticMessage = ''
    }
}
function Get-KeyMgrByteHash {
    param([byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($(if ($null -ne $Bytes) { $Bytes } else { [byte[]]@() }))
        return ([BitConverter]::ToString($hash) -replace '-', '')
    } finally {
        $sha.Dispose()
    }
}
function Get-KeyMgrSecretHash {
    param([AllowNull()][string]$Secret)
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($(if ($null -ne $Secret) { $Secret } else { '' }))
    try { return script:Get-KeyMgrByteHash -Bytes $bytes }
    finally { if ($bytes.Length -gt 0) { [Array]::Clear($bytes, 0, $bytes.Length) } }
}
function Clear-KeyMgrSecretObject {
    param($Value)
    if ($null -eq $Value) { return }
    try {
        if ($null -ne $Value.PSObject.Methods['ClearSecret']) { $Value.ClearSecret() }
    } catch {}
    foreach ($name in @('Secret','Password','Authenticator')) {
        try {
            $property = $Value.PSObject.Properties[$name]
            if ($null -ne $property -and $property.IsSettable) { $property.Value = $null }
        } catch {}
    }
}
function Clear-KeyMgrSecretCollection {
    param([AllowNull()][System.Collections.IEnumerable]$Collection)
    if ($null -eq $Collection) { return }
    # Do not use @($Collection) here. Windows PowerShell 5.1 can throw
    # "Argument types do not match" while materializing some generic List[object] instances.
    foreach ($item in $Collection) {
        script:Clear-KeyMgrSecretObject -Value $item
    }
}
function Invoke-KeyMgrRollback {
    param([Parameter(Mandatory=$true)]$Transaction, [Parameter(Mandatory=$true)][scriptblock]$Action)
    $Transaction.RollbackAttempted = $true
    try {
        & $Action
        $Transaction.RollbackSucceeded = $true
        $Transaction.RollbackDiagnostic = 'The pre-mutation snapshot was restored and rechecked.'
        return $true
    } catch {
        $Transaction.RollbackSucceeded = $false
        $Transaction.RollbackDiagnostic = $_.Exception.Message
        return $false
    }
}
function Get-KeyMgrCredManSnapshot {
    param([string]$Target, [uint32]$Type)
    $snapshots = @(script:Get-CrdCredentialSnapshots)
    $match = @($snapshots | Where-Object { $_.TargetName -eq $Target -and [uint32]$_.Type -eq $Type } | Select-Object -First 1)[0]
    foreach ($snapshot in $snapshots) {
        if ($snapshot -ne $match) { script:Clear-KeyMgrSecretObject $snapshot }
    }
    return $match
}
function Get-KeyMgrSnapshotLogicalUsername {
    param($Snapshot)
    if ($null -eq $Snapshot) { return '' }
    if ([int]$Snapshot.Type -eq 3 -or [int]$Snapshot.Type -eq 5) { return [string]$Snapshot.Comment }
    return [string]$Snapshot.UserName
}
function Write-KeyMgrCredManCredential {
    param([Parameter(Mandatory=$true)]$Data, $BeforeSnapshot = $null)
    $nativeStruct = New-Object 'SecurityEngineMatrix+CREDENTIAL'
    $nativeStruct.Type = [int]$Data.CredentialType
    $nativeStruct.TargetName = [string]$Data.Target
    $nativeStruct.Persist = [int]$Data.Persist
    $nativeStruct.UserName = [string]$Data.Username
    if ($null -ne $BeforeSnapshot) { $nativeStruct.Comment = [string]$BeforeSnapshot.Comment }
    $nativeStruct.CredentialBlob = [System.IntPtr]::Zero
    $nativeStruct.CredentialBlobSize = 0
    $allocatedPointer = [System.IntPtr]::Zero
    try {
        if ($Data.IsCertificateCredential) {
            $blobInfo = script:New-CertificateCredentialBlob -Thumbprint ([string]$Data.CertificateThumbprint)
            $allocatedPointer = $blobInfo.Pointer
            $nativeStruct.CredentialBlob = $allocatedPointer
            $nativeStruct.CredentialBlobSize = $blobInfo.Size
            $nativeStruct.UserName = [SecurityEngineMatrix]::MarshalCertificateUsername([byte[]]$blobInfo.HashBytes)
            $nativeStruct.Comment = [string]$Data.Username
        } elseif (-not $Data.SecretWasChanged -and $null -ne $BeforeSnapshot) {
            $blobBytes = [byte[]]$BeforeSnapshot.CredentialBlobBytes
            if ($null -ne $blobBytes -and $blobBytes.Length -gt 0) {
                $allocatedPointer = [System.Runtime.InteropServices.Marshal]::AllocCoTaskMem($blobBytes.Length)
                [System.Runtime.InteropServices.Marshal]::Copy($blobBytes, 0, $allocatedPointer, $blobBytes.Length)
                $nativeStruct.CredentialBlob = $allocatedPointer
                $nativeStruct.CredentialBlobSize = $blobBytes.Length
            }
        } else {
            $secretBytes = [System.Text.Encoding]::Unicode.GetBytes($(if ($null -ne $Data.Secret) { [string]$Data.Secret } else { '' }))
            try {
                if ($secretBytes.Length -gt 0) {
                    $allocatedPointer = [System.Runtime.InteropServices.Marshal]::AllocCoTaskMem($secretBytes.Length)
                    [System.Runtime.InteropServices.Marshal]::Copy($secretBytes, 0, $allocatedPointer, $secretBytes.Length)
                    $nativeStruct.CredentialBlob = $allocatedPointer
                    $nativeStruct.CredentialBlobSize = $secretBytes.Length
                }
            } finally {
                if ($secretBytes.Length -gt 0) { [Array]::Clear($secretBytes, 0, $secretBytes.Length) }
            }
        }
        if (-not [SecurityEngineMatrix]::CredWrite([ref]$nativeStruct, 0)) {
            $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "CredWrite failed with Win32 error $errorCode."
        }
    } finally {
        if ($allocatedPointer -ne [System.IntPtr]::Zero) {
            $zeroBytes = New-Object byte[] ([int]$nativeStruct.CredentialBlobSize)
            if ($zeroBytes.Length -gt 0) { [System.Runtime.InteropServices.Marshal]::Copy($zeroBytes, 0, $allocatedPointer, $zeroBytes.Length) }
            [System.Runtime.InteropServices.Marshal]::FreeCoTaskMem($allocatedPointer)
        }
    }
}
function Test-KeyMgrCredManWrite {
    param([Parameter(Mandatory=$true)]$Data, $BeforeSnapshot = $null)
    $after = script:Get-KeyMgrCredManSnapshot -Target ([string]$Data.Target) -Type ([uint32]$Data.CredentialType)
    if ($null -eq $after) { return $false }
    try {
        if ((script:Get-KeyMgrSnapshotLogicalUsername -Snapshot $after) -ne [string]$Data.Username) { return $false }
        if ([int]$after.Persist -ne [int]$Data.Persist) { return $false }
        if ($Data.IsCertificateCredential) { return ([string]$after.SecretText).ToUpperInvariant() -eq ([string]$Data.CertificateThumbprint).ToUpperInvariant() }
        if ($Data.SecretWasChanged) {
            return (script:Get-KeyMgrByteHash -Bytes ([byte[]]$after.CredentialBlobBytes)) -eq [string]$Data.SecretHash
        }
        if ($null -ne $BeforeSnapshot) {
            return (script:Get-KeyMgrByteHash -Bytes ([byte[]]$after.CredentialBlobBytes)) -eq (script:Get-KeyMgrByteHash -Bytes ([byte[]]$BeforeSnapshot.CredentialBlobBytes))
        }
        return $true
    } finally {
        script:Clear-KeyMgrSecretObject $after
    }
}
function Get-KeyMgrPasswordVaultSnapshot {
    param([string]$Target, [string]$Username)
    try {
        $credential = $Vault.Retrieve($Target, $Username)
        if ($null -eq $credential) { return $null }
        $credential.RetrievePassword()
        return [pscustomobject]@{ Target = [string]$credential.Resource; Username = [string]$credential.UserName; Password = [string]$credential.Password }
    } catch { return $null }
}
function Test-KeyMgrPasswordVaultExists {
    param([string]$Target, [string]$Username)
    $credentials = $Vault.RetrieveAll()
    foreach ($credential in $credentials) {
        if ([string]$credential.Resource -eq $Target -and [string]$credential.UserName -eq $Username) { return $true }
    }
    return $false
}
function Set-KeyMgrPasswordVaultCredential {
    param([string]$Target, [string]$Username, [AllowNull()][string]$Password)
    $credential = New-Object Windows.Security.Credentials.PasswordCredential($Target, $Username, $(if ($null -ne $Password) { $Password } else { '' }))
    $Vault.Add($credential)
}
function Remove-KeyMgrPasswordVaultCredential {
    param([string]$Target, [string]$Username)
    $credential = New-Object Windows.Security.Credentials.PasswordCredential($Target, $Username, '')
    $Vault.Remove($credential)
}
function Get-KeyMgrVaultcmdMatch {
    param([string]$VaultName, [string]$Schema, [string]$Identity, [string]$Resource)
    return @(script:Get-VaultcmdCredentials | Where-Object {
        $_.VaultName -eq $VaultName -and $_.Schema -eq $Schema -and $_.Identity -eq $Identity -and $_.Resource -eq $Resource
    } | Select-Object -First 1)[0]
}
function New-KeyMgrEdgeDatabaseSnapshot {
    param([Parameter(Mandatory=$true)][string]$ProfilePath)
    $source = Join-Path $ProfilePath 'Login Data'
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Edge Login Data was not found at '$source'." }
    $root = Join-Path ([System.IO.Path]::GetTempPath()) ('KeyMgrEdgeTx_' + [guid]::NewGuid().ToString('N'))
    try {
        [System.IO.Directory]::CreateDirectory($root) | Out-Null
        foreach ($suffix in @('', '-wal', '-shm')) {
            $candidate = $source + $suffix
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { Copy-Item -LiteralPath $candidate -Destination (Join-Path $root ('Login Data' + $suffix)) -Force }
        }
        return [pscustomobject]@{ Root = $root; ProfilePath = $ProfilePath }
    } catch {
        if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        throw
    }
}
function Restore-KeyMgrEdgeDatabaseSnapshot {
    param([Parameter(Mandatory=$true)]$Snapshot)
    $destination = Join-Path ([string]$Snapshot.ProfilePath) 'Login Data'
    foreach ($suffix in @('', '-wal', '-shm')) {
        $current = $destination + $suffix
        $saved = Join-Path ([string]$Snapshot.Root) ('Login Data' + $suffix)
        if (Test-Path -LiteralPath $current -PathType Leaf) { Remove-Item -LiteralPath $current -Force }
        if (Test-Path -LiteralPath $saved -PathType Leaf) { Copy-Item -LiteralPath $saved -Destination $current -Force }
    }
}
function Remove-KeyMgrEdgeDatabaseSnapshot {
    param($Snapshot)
    if ($null -ne $Snapshot -and -not [string]::IsNullOrWhiteSpace([string]$Snapshot.Root) -and (Test-Path -LiteralPath $Snapshot.Root)) {
        try {
            Remove-Item -LiteralPath $Snapshot.Root -Recurse -Force -ErrorAction Stop
        } catch {
            script:Write-KeyMgrRuntimeLog 'EDGE-TX-CLEANUP' ("Temporary database snapshot cleanup failed for '{0}': {1}" -f $Snapshot.Root, $_.Exception.Message)
        }
    }
}
function Invoke-KeyMgrProviderMutation {
    param(
        [Parameter(Mandatory=$true)][string]$ProviderId,
        [Parameter(Mandatory=$true)][ValidateSet('Add','Edit','Remove')][string]$Operation,
        $SelectedItem = $null,
        $MutationData = $null
    )
    $target = if ($null -ne $MutationData -and $MutationData.PSObject.Properties['Target']) { [string]$MutationData.Target } elseif ($null -ne $MutationData -and $MutationData.PSObject.Properties['Resource']) { [string]$MutationData.Resource } elseif ($null -ne $SelectedItem -and $SelectedItem.PSObject.Properties['Target']) { [string]$SelectedItem.Target } elseif ($null -ne $SelectedItem -and $SelectedItem.PSObject.Properties['Website']) { [string]$SelectedItem.Website } else { '' }
    $tx = script:New-KeyMgrTransaction -ProviderId $ProviderId -Operation $Operation -Target $target
    $before = $null
    $after = $null
    $edgeDatabaseSnapshot = $null
    $mutationStarted = $false
    $rollbackAction = $null
    try {
        switch -Regex ($ProviderId) {
            '^CredMan' {
                $type = if ($null -ne $MutationData) { [uint32]$MutationData.CredentialType } else { [uint32]$SelectedItem.Type }
                $target = if ($null -ne $MutationData) { [string]$MutationData.Target } else { [string]$SelectedItem.Target }
                $before = script:Get-KeyMgrCredManSnapshot -Target $target -Type $type
                if ($Operation -ne 'Add' -and $null -eq $before) { throw 'The selected CredMan credential could not be captured before mutation.' }
                $tx.SnapshotStatus = if ($null -ne $before) { 'Captured' } else { 'Absent' }
                $tx.RollbackAvailable = $true
                $rollbackAction = {
                    if ($null -ne $before) {
                        if (-not (script:Restore-CrdCredentialSnapshot -Snapshot $before)) { throw 'CredMan snapshot restore failed.' }
                    } else {
                        $removed = script:Remove-CrdCredential -TargetName $target -Type $type
                        if (-not $removed) {
                            $code = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            if ($code -ne 1168) { throw "CredMan rollback delete failed with Win32 error $code." }
                        }
                    }
                    $check = script:Get-KeyMgrCredManSnapshot -Target $target -Type $type
                    if (($null -eq $before -and $null -ne $check) -or ($null -ne $before -and $null -eq $check)) { throw 'CredMan rollback verification failed.' }
                    if ($null -ne $before -and $check.Fingerprint -ne $before.Fingerprint) { throw 'CredMan rollback fingerprint verification failed.' }
                    if ($null -ne $check) { script:Clear-KeyMgrSecretObject $check }
                }
                $mutationStarted = $true
                if ($Operation -eq 'Remove') {
                    if (-not (script:Remove-CrdCredential -TargetName $target -Type $type)) {
                        $code = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        throw "CredDelete failed with Win32 error $code."
                    }
                    $after = script:Get-KeyMgrCredManSnapshot -Target $target -Type $type
                    $verified = $null -eq $after
                } else {
                    $MutationData.SecretHash = if ($MutationData.SecretWasChanged -and -not $MutationData.IsCertificateCredential) { script:Get-KeyMgrSecretHash -Secret ([string]$MutationData.Secret) } else { '' }
                    script:Write-KeyMgrCredManCredential -Data $MutationData -BeforeSnapshot $before
                    $verified = script:Test-KeyMgrCredManWrite -Data $MutationData -BeforeSnapshot $before
                }
                if (-not $verified) {
                    $tx.VerificationStatus = 'Failed'
                    [void](script:Invoke-KeyMgrRollback -Transaction $tx -Action $rollbackAction)
                    throw 'CredMan accepted the API call, but provider re-read verification failed.'
                }
                $tx.VerificationStatus = 'Passed'
            }
            '^PasswordVault$' {
                $target = if ($null -ne $MutationData) { [string]$MutationData.Target } else { [string]$SelectedItem.Target }
                $username = if ($null -ne $MutationData) { [string]$MutationData.Username } else { [string]$SelectedItem.Username }
                $originalTarget = if ($Operation -eq 'Edit') { [string]$SelectedItem.Target } else { $target }
                $originalUsername = if ($Operation -eq 'Edit') { [string]$SelectedItem.Username } else { $username }
                $originalExists = script:Test-KeyMgrPasswordVaultExists -Target $originalTarget -Username $originalUsername
                $before = script:Get-KeyMgrPasswordVaultSnapshot -Target $originalTarget -Username $originalUsername
                if ($originalExists -and $null -eq $before) { throw 'The PasswordVault item exists, but its secret could not be captured for a verified transaction.' }
                $tx.SnapshotStatus = if ($null -ne $before) { 'Captured' } else { 'Absent' }
                $tx.RollbackAvailable = $true
                $rollbackAction = {
                    if ($target -ne $originalTarget -or $username -ne $originalUsername -or $null -eq $before) {
                        try { script:Remove-KeyMgrPasswordVaultCredential -Target $target -Username $username } catch {}
                    }
                    if ($null -ne $before) { script:Set-KeyMgrPasswordVaultCredential -Target $before.Target -Username $before.Username -Password $before.Password }
                    $checkExists = script:Test-KeyMgrPasswordVaultExists -Target $originalTarget -Username $originalUsername
                    $check = if ($checkExists) { script:Get-KeyMgrPasswordVaultSnapshot -Target $originalTarget -Username $originalUsername } else { $null }
                    if (($null -eq $before -and $checkExists) -or ($null -ne $before -and -not $checkExists)) { throw 'PasswordVault rollback verification failed.' }
                    if ($null -ne $before -and (script:Get-KeyMgrSecretHash -Secret ([string]$check.Password)) -ne (script:Get-KeyMgrSecretHash -Secret ([string]$before.Password))) { throw 'PasswordVault rollback secret verification failed.' }
                    if ($null -ne $check) { script:Clear-KeyMgrSecretObject $check }
                }
                $mutationStarted = $true
                if ($Operation -eq 'Remove') {
                    script:Remove-KeyMgrPasswordVaultCredential -Target $target -Username $username
                    $verified = -not (script:Test-KeyMgrPasswordVaultExists -Target $target -Username $username)
                } else {
                    script:Set-KeyMgrPasswordVaultCredential -Target $target -Username $username -Password ([string]$MutationData.Secret)
                    $after = script:Get-KeyMgrPasswordVaultSnapshot -Target $target -Username $username
                    $verified = $null -ne $after -and (script:Get-KeyMgrSecretHash -Secret ([string]$after.Password)) -eq (script:Get-KeyMgrSecretHash -Secret ([string]$MutationData.Secret))
                    if ($verified -and $Operation -eq 'Edit' -and ($target -ne $originalTarget -or $username -ne $originalUsername)) {
                        script:Remove-KeyMgrPasswordVaultCredential -Target $originalTarget -Username $originalUsername
                        $verified = -not (script:Test-KeyMgrPasswordVaultExists -Target $originalTarget -Username $originalUsername)
                    }
                }
                if (-not $verified) {
                    $tx.VerificationStatus = 'Failed'
                    [void](script:Invoke-KeyMgrRollback -Transaction $tx -Action $rollbackAction)
                    throw 'PasswordVault accepted the API call, but provider re-read verification failed.'
                }
                $tx.VerificationStatus = 'Passed'
            }
            '^VaultCmd$' {
                $vaultName = if ($null -ne $MutationData) { [string]$MutationData.VaultName } else { [string]$SelectedItem.VaultName }
                $schema = if ($null -ne $MutationData) { [string]$MutationData.Schema } else { [string]$SelectedItem.Schema }
                $identity = if ($null -ne $MutationData) { [string]$MutationData.Identity } else { [string]$SelectedItem.Username }
                $resource = if ($null -ne $MutationData) { [string]$MutationData.Resource } else { [string]$SelectedItem.Target }
                $before = script:Get-KeyMgrVaultcmdMatch -VaultName $vaultName -Schema $schema -Identity $identity -Resource $resource
                $tx.SnapshotStatus = if ($null -ne $before) { 'MetadataOnly' } else { 'Absent' }
                $tx.RollbackAvailable = ($Operation -eq 'Add' -and $null -eq $before)
                if ($tx.RollbackAvailable) {
                    $rollbackAction = {
                        script:Invoke-VaultcmdDeleteCredential -VaultName $vaultName -Schema $schema -Identity $identity -Resource $resource -PackageSid '' | Out-Null
                        if ($null -ne (script:Get-KeyMgrVaultcmdMatch -VaultName $vaultName -Schema $schema -Identity $identity -Resource $resource)) { throw 'vaultcmd rollback verification failed.' }
                    }
                }
                $mutationStarted = $true
                if ($Operation -eq 'Remove') {
                    script:Invoke-VaultcmdDeleteCredential -VaultName $vaultName -Schema $schema -Identity $identity -Resource $resource -PackageSid ([string]$SelectedItem.PackageSid) | Out-Null
                    $verified = $null -eq (script:Get-KeyMgrVaultcmdMatch -VaultName $vaultName -Schema $schema -Identity $identity -Resource $resource)
                } else {
                    script:Invoke-VaultcmdAddCredential -VaultName $vaultName -Schema $schema -Identity $identity -Authenticator ([string]$MutationData.Authenticator) -Resource $resource -SavedBy ([string]$MutationData.SavedBy) | Out-Null
                    $verified = $null -ne (script:Get-KeyMgrVaultcmdMatch -VaultName $vaultName -Schema $schema -Identity $identity -Resource $resource)
                }
                if (-not $verified) {
                    $tx.VerificationStatus = 'Failed'
                    if ($tx.RollbackAvailable) {
                        [void](script:Invoke-KeyMgrRollback -Transaction $tx -Action $rollbackAction)
                    }
                    throw 'vaultcmd completed, but the credential could not be verified by re-enumeration.'
                }
                $tx.VerificationStatus = 'Passed'
            }
            '^Edge$' {
                throw 'Direct Edge mutation is disabled in KeyMgr 4-7. Stage the change in Browser Credentials and use Apply.'
            }
            default { throw "No transactional mutation adapter is registered for provider '$ProviderId'." }
        }
        $tx.Success = $true
        $tx.Changed = $true
        $tx.DiagnosticMessage = 'Snapshot, mutation, and provider re-read verification completed.'
    } catch {
        $tx.Success = $false
        $tx.Changed = $mutationStarted -and -not $tx.RollbackSucceeded
        $tx.DiagnosticMessage = $_.Exception.Message
        if ($tx.VerificationStatus -eq 'Pending') { $tx.VerificationStatus = 'Failed' }
        if ($tx.RollbackAvailable -and $mutationStarted -and -not $tx.RollbackAttempted) {
            if ($null -ne $rollbackAction) {
                [void](script:Invoke-KeyMgrRollback -Transaction $tx -Action $rollbackAction)
            } else {
                $tx.RollbackDiagnostic = 'The mutation failed before a safe provider-specific rollback could be selected.'
            }
        }
        if ($tx.DiagnosticMessage -match 'Win32 error ([0-9]+)') { $tx.ErrorCode = $Matches[1] }
    } finally {
        script:Clear-KeyMgrSecretObject $after
        script:Clear-KeyMgrSecretObject $before
        script:Clear-KeyMgrSecretObject $MutationData
        script:Remove-KeyMgrEdgeDatabaseSnapshot -Snapshot $edgeDatabaseSnapshot
    }
    return $tx
}

# ==============================================
# 4. .CRD DIAGNOSTIC IMPORT AND SESSION-ONLY SNAPSHOT STORE
# ==============================================
# Imported snapshots stay in memory; the legacy JSON path is retained only for cleanup.
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
    if (script:Test-SecurityEngineMatrixMethod -MethodName 'CredRestoreCredentials') {
        return [SecurityEngineMatrix]::CredRestoreCredentials($FilePath, $PasswordBytes, $PasswordBytes.Length, $Flags)
    }
    script:Ensure-CrdInteropBridge
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
    if (script:Test-SecurityEngineMatrixMethod -MethodName 'CredDelete') {
        return [SecurityEngineMatrix]::CredDelete($TargetName, $Type, $Flags)
    }
    script:Ensure-CrdInteropBridge
    return [CrdInteropBridge]::CredDelete($TargetName, $Type, $Flags)
}
function Get-CrdCredentialSnapshots {
    if (script:Test-SecurityEngineMatrixMethod -MethodName 'CaptureCredentialSnapshots') {
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
        $secretText = if (script:Test-SecurityEngineMatrixMethod -MethodName 'ReadCredentialBlob') {
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
            Fingerprint = $comment + $separator + ([int]$credential.Persist).ToString() + $separator + (script:Get-KeyMgrByteHash -Bytes $blobBytes)
        }
    }
    return $snapshots
}
function Restore-CrdCredentialSnapshot {
    param(
        [Parameter(Mandatory=$true)]
        $Snapshot
    )
    if (script:Test-SecurityEngineMatrixMethod -MethodName 'WriteSnapshot') {
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
    $dialogResult = $form.ShowDialog($MainForm)
    $result = if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) { $form.Tag } else { $null }
    $textbox.Clear()
    return $result
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
                return (New-Object System.ComponentModel.Win32Exception -ArgumentList $ErrorCode).Message
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
    Inspects an encrypted .crd backup by temporarily invoking the native Windows restore API
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
    2. Uses the Windows restore API, which mutates the live credential store
    3. Captures credentials added or changed by that restore into session memory
    4. Attempts to delete new entries and restore overwritten entries to their prior snapshots
    Rollback is best-effort; callers must treat warnings as possible residual live-store changes.
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
            $Password = script:Show-ImportPasswordDialog
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
        # Read bytes for file-size metadata; CredRestoreCredentials performs format and password validation.
        $fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
        Write-Verbose "File size: $($fileBytes.Length) bytes"
        $passwordPtr = [System.IntPtr]::Zero
        $passwordPlain = $null
        $passwordBytes = [byte[]]@()
        $beforeSnapshots = @(script:Get-CrdCredentialSnapshots)
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
            $restoreSucceeded = script:Invoke-CrdRestoreCredentials -FilePath $FilePath -PasswordBytes $passwordBytes
            if (-not $restoreSucceeded) {
                $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "CRD restore failed. $(Get-CrdImportErrorMessage -ErrorCode $errorCode)"
            }
            $afterSnapshots = @(script:Get-CrdCredentialSnapshots)
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
                    $afterSnapshots = @(script:Get-CrdCredentialSnapshots)
                }
                foreach ($afterSnapshot in $afterSnapshots) {
                    $beforeSnapshot = $beforeByKey[$afterSnapshot.Key]
                    if ($null -eq $beforeSnapshot) {
                        if (-not (script:Remove-CrdCredential -TargetName $afterSnapshot.TargetName -Type ([uint32]$afterSnapshot.Type))) {
                            $deleteError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                            if ($deleteError -ne 1168) {
                                $rollbackFailures += "Delete '$($afterSnapshot.TargetName)' failed: $(Get-CrdImportErrorMessage -ErrorCode $deleteError)"
                            }
                        }
                    }
                    elseif ($beforeSnapshot.Fingerprint -ne $afterSnapshot.Fingerprint) {
                        if (-not (script:Restore-CrdCredentialSnapshot -Snapshot $beforeSnapshot)) {
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
                Type = script:Get-CredentialTypeDisplayName -Type $snapshot.Type
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
        script:Clear-KeyMgrSecretCollection -Collection $Global:ImportedCredentials
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
function Get-CertificateCredentials {
    <#
    .SYNOPSIS
    Enumerates certificates from Current User > Personal (CurrentUser\My)
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
    $normalizedThumbprint = script:Normalize-CertificateThumbprint $Thumbprint
    if ($normalizedThumbprint.Length -ne 40) {
        return $null
    }
    foreach ($cert in (script:Get-CertificateCredentials)) {
        if ((script:Normalize-CertificateThumbprint $cert.Thumbprint) -eq $normalizedThumbprint) {
            return $cert
        }
    }
    return $null
}
function Test-CertificateCredentialUsability {
    param(
        [string]$Thumbprint
    )
    $normalizedThumbprint = script:Normalize-CertificateThumbprint $Thumbprint
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
            (script:Normalize-CertificateThumbprint $_.Thumbprint) -eq $normalizedThumbprint
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
    $normalizedThumbprint = script:Normalize-CertificateThumbprint $Thumbprint
    if ($normalizedThumbprint.Length -ne 40) {
        throw "Certificate thumbprint must contain exactly 40 hexadecimal characters."
    }
    $cert = script:Find-CertificateCredential $normalizedThumbprint
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
    $certificates = @(script:Get-CertificateCredentials | Sort-Object ExpiryStatus, Subject)
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
        [void]$item.SubItems.Add((script:Normalize-CertificateThumbprint $cert.Thumbprint))
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
# -------------------------------------------------------------
# 5. CREDENTIAL SOURCE ADAPTERS AND WEB-CREDENTIAL AGGREGATION
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
    script:Write-TraceLog "PasswordVault initialized successfully"
} catch {
    Write-Warning "Failed to initialize PasswordVault: $_"
    $Vault = $null
}
# Parse cmdkey.exe summary output for an independent CredMan diagnostic view.
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
# Parse vaultcmd.exe vault/property/credential metadata; authenticators are not returned by this path.
function Get-VaultcmdCredentials {
    $found = @()
    try {
        $vaultOutput = & vaultcmd.exe /list 2>$null
        if (-not $vaultOutput) {
            script:Write-TraceLog "vaultcmd /list returned no output"
            return $found
        }
        $vaults = @()
        $vaultName = $null
        $vaultGuid = $null
        $vaultLocation = $null
        foreach ($line in $vaultOutput) {
            if ($line -match '^\s*Vault:\s*(.+)$') {
                $vaultName = $matches[1].Trim()
            } elseif ($line -imatch 'Vault Guid:\s*([A-F0-9\-]+)') {
                $vaultGuid = $matches[1].Trim()
            } elseif ($line -match '^\s*Location:\s*(.+)$') {
                $vaultLocation = $matches[1].Trim()
                if ($vaultName -and $vaultGuid) {
                    $vaults += [PSCustomObject]@{ Name = $vaultName; Guid = $vaultGuid; Location = $vaultLocation }
                    $vaultName = $null
                    $vaultGuid = $null
                    $vaultLocation = $null
                }
            }
        }
        foreach ($vault in $vaults) {
            try {
                $vaultProtection = ''
                $vaultReportedCount = $null
                try {
                    $propOutput = & vaultcmd.exe "/listproperties:$($vault.Name)" 2>$null
                    foreach ($propLine in $propOutput) {
                        if ($propLine -match '^\s*Number of credentials:\s*(\d+)') { $vaultReportedCount = [int]$matches[1] }
                        elseif ($propLine -match '^\s*Current protection method:\s*(.+)$') { $vaultProtection = $matches[1].Trim() }
                    }
                } catch { }
                $credsOutput = & vaultcmd.exe "/listcreds:$($vault.Name)" /all 2>$null
                if (-not $credsOutput) { continue }
                $record = [ordered]@{}
                $flushRecord = {
                    if ($record.Resource -and $record.Identity) {
                        $found += [PSCustomObject]@{
                            Target     = [string]$record.Resource
                            Resource   = [string]$record.Resource
                            Username   = [string]$record.Identity
                            Identity   = [string]$record.Identity
                            Password   = $null
                            Type       = [string]$record.Schema
                            Schema     = [string]$record.Schema
                            VaultName  = [string]$vault.Name
                            VaultGuid  = [string]$vault.Guid
                            VaultLocation = [string]$vault.Location
                            VaultProtection = [string]$vaultProtection
                            VaultReportedCount = $vaultReportedCount
                            PackageSid = [string]$record.PackageSid
                            SavedBy    = [string]$record.SavedBy
                            Hidden     = [string]$record.Hidden
                            Roaming    = [string]$record.Roaming
                            Provider   = 'VaultCmd'
                        }
                    }
                    $record.Clear()
                }
                foreach ($line in @($credsOutput) + '') {
                    if ([string]::IsNullOrWhiteSpace($line)) {
                        . $flushRecord
                        continue
                    }
                    if ($line -match '^\s*Credential schema:\s*(.+)$') {
                        if ($record.Resource -and $record.Identity) { . $flushRecord }
                        $record.Schema = $matches[1].Trim()
                    } elseif ($line -match '^\s*Resource:\s*(.*)$') {
                        $record.Resource = $matches[1].Trim()
                    } elseif ($line -match '^\s*Identity:\s*(.*)$') {
                        $record.Identity = $matches[1].Trim()
                    } elseif ($line -match '^\s*Package Sid:\s*(.*)$') {
                        $record.PackageSid = $matches[1].Trim()
                    } elseif ($line -match '^\s*Saved By:\s*(.*)$') {
                        $record.SavedBy = $matches[1].Trim()
                    } elseif ($line -match '^\s*Hidden:\s*(.*)$') {
                        $record.Hidden = $matches[1].Trim()
                    } elseif ($line -match '^\s*Roaming:\s*(.*)$') {
                        $record.Roaming = $matches[1].Trim()
                    }
                }
            } catch {
                Write-Warning "Error querying vault $($vault.Name): $_"
            }
        }
    } catch {
        Write-Warning "Error in Get-VaultcmdCredentials: $_"
    }
    script:Write-TraceLog "Total vaultcmd credentials found: $($found.Count)"
    return $found
}
function Find-VaultcmdNativeMatch {
    param(
        [Parameter(Mandatory=$true)][Guid]$VaultGuid,
        [Parameter(Mandatory=$true)]$NativeItem,
        [object[]]$VaultcmdCredentials
    )
    $result = [ordered]@{
        Credential = $null
        Match = 'No match'
        CandidateCount = 0
    }
    if ($null -eq $VaultcmdCredentials -or $null -eq $NativeItem) {
        return [PSCustomObject]$result
    }
    $vaultGuidText = $VaultGuid.ToString('D')
    $resource = if ($null -ne $NativeItem.Resource) { [string]$NativeItem.Resource } else { '' }
    $identity = if ($null -ne $NativeItem.Identity) { [string]$NativeItem.Identity } else { '' }
    $packageSid = if ($null -ne $NativeItem.PackageSid) { [string]$NativeItem.PackageSid } else { '' }
    $candidates = @($VaultcmdCredentials | Where-Object {
        ([string]$_.VaultGuid -eq $vaultGuidText) -and
        ([string]$_.Resource -eq $resource) -and
        ([string]$_.Identity -eq $identity)
    })
    $result.CandidateCount = $candidates.Count
    if ($candidates.Count -eq 0) {
        return [PSCustomObject]$result
    }
    if (-not [string]::IsNullOrWhiteSpace($packageSid)) {
        $packageMatches = @($candidates | Where-Object { [string]$_.PackageSid -eq $packageSid })
        if ($packageMatches.Count -eq 1) {
            $result.Credential = $packageMatches[0]
            $result.Match = 'Exact core key + Package SID'
            return [PSCustomObject]$result
        }
        if ($packageMatches.Count -gt 1) {
            $result.Credential = $packageMatches[0]
            $result.Match = "Ambiguous package match ($($packageMatches.Count))"
            return [PSCustomObject]$result
        }
    }
    if ($candidates.Count -eq 1) {
        $result.Credential = $candidates[0]
        $result.Match = 'Exact vault/resource/identity'
    } else {
        $result.Credential = $candidates[0]
        $result.Match = "Ambiguous core match ($($candidates.Count))"
    }
    return [PSCustomObject]$result
}
function Get-VaultMetadataMappingEvidence {
    param(
        [Parameter(Mandatory=$true)]$NativeItem,
        $VaultcmdCredential
    )
    if ($null -eq $VaultcmdCredential) { return 'No vaultcmd record matched this native item.' }
    $evidence = New-Object System.Collections.Generic.List[string]
    $nativeSid = if ($null -ne $NativeItem.PackageSid) { [string]$NativeItem.PackageSid } else { '' }
    $cliSid = if ($null -ne $VaultcmdCredential.PackageSid) { [string]$VaultcmdCredential.PackageSid } else { '' }
    if ([string]::IsNullOrWhiteSpace($nativeSid) -and [string]::IsNullOrWhiteSpace($cliSid)) {
        $evidence.Add('Package SID: both empty')
    } elseif ($nativeSid -eq $cliSid) {
        $evidence.Add('Package SID: vaultcmd value matches VAULT_ITEM.pPackageSid')
    } else {
        $evidence.Add("Package SID mismatch: native='$nativeSid'; CLI='$cliSid'")
    }
    $evidence.Add("CLI Hidden=$([string]$VaultcmdCredential.Hidden), Roaming=$([string]$VaultcmdCredential.Roaming) <-> Flags=$($NativeItem.FlagsHex), set bits=$($NativeItem.FlagBits)")
    $savedBy = if ($null -ne $VaultcmdCredential.SavedBy) { [string]$VaultcmdCredential.SavedBy } else { '' }
    if ([string]::IsNullOrWhiteSpace($savedBy)) {
        $evidence.Add('Saved By: CLI value is empty')
    } else {
        $propertyMatches = @($NativeItem.Properties | Where-Object { [string]$_.Value -eq $savedBy })
        if ($propertyMatches.Count -gt 0) {
            $propertyLabels = @($propertyMatches | ForEach-Object { "ID=$($_.SchemaElementId)/$($_.TypeName)" })
            $evidence.Add("Saved By '$savedBy' matches pProperties $($propertyLabels -join ', ')")
        } else {
            $evidence.Add("Saved By '$savedBy' was not found in decoded pProperties")
        }
    }
    return ($evidence -join ' | ')
}
function Invoke-VaultcmdAddCredential {
    param(
        [Parameter(Mandatory=$true)][string]$VaultName,
        [Parameter(Mandatory=$true)][string]$Schema,
        [Parameter(Mandatory=$true)][string]$Identity,
        [Parameter(Mandatory=$true)][string]$Authenticator,
        [string]$Resource,
        [string]$SavedBy
    )
    if (-not (Get-Command vaultcmd.exe -ErrorAction SilentlyContinue)) { throw 'vaultcmd.exe is unavailable.' }
    $args = @("/addcreds:$VaultName", "/credtype:$Schema", "/identity:$Identity", "/authenticator:$Authenticator")
    if (-not [string]::IsNullOrWhiteSpace($Resource)) { $args += "/resource:$Resource" }
    if (-not [string]::IsNullOrWhiteSpace($SavedBy)) { $args += "/savedBy:$SavedBy" }
    $output = & vaultcmd.exe @args 2>&1
    if ($LASTEXITCODE -ne 0) {
        $safeOutput = ($output -join [Environment]::NewLine)
        if (-not [string]::IsNullOrEmpty($Authenticator)) { $safeOutput = $safeOutput.Replace($Authenticator, '[REDACTED]') }
        throw "vaultcmd /addcreds failed with exit code $LASTEXITCODE.`n$safeOutput"
    }
    return $output
}
function Invoke-VaultcmdDeleteCredential {
    param(
        [Parameter(Mandatory=$true)][string]$VaultName,
        [Parameter(Mandatory=$true)][string]$Schema,
        [Parameter(Mandatory=$true)][string]$Identity,
        [string]$Resource,
        [string]$PackageSid
    )
    if (-not (Get-Command vaultcmd.exe -ErrorAction SilentlyContinue)) { throw 'vaultcmd.exe is unavailable.' }
    $args = @("/deletecreds:$VaultName", "/credtype:$Schema", "/identity:$Identity")
    if (-not [string]::IsNullOrWhiteSpace($Resource)) { $args += "/resource:$Resource" }
    if (-not [string]::IsNullOrWhiteSpace($PackageSid)) { $args += "/sid:$PackageSid" }
    $output = & vaultcmd.exe @args 2>&1
    if ($LASTEXITCODE -ne 0) { throw "vaultcmd /deletecreds failed with exit code $LASTEXITCODE.`n$($output -join [Environment]::NewLine)" }
    return $output
}
function Show-VaultcmdWebCredentialDialog {
    param($SelectedObj)
    $isEdit = $null -ne $SelectedObj
    $form = New-Object System.Windows.Forms.Form
    $form.Text = if ($isEdit) { 'Stored Credential Properties' } else { 'Add Stored Credential' }
    $form.StartPosition = 'CenterParent'
    $form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.ShowIcon = $false
    $form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $clientHeight = if ($isEdit) { 611 } else { 485 }
    $form.ClientSize = New-Object System.Drawing.Size(360, $clientHeight)
    $instruction = New-Object System.Windows.Forms.Label
    $instruction.Location = New-Object System.Drawing.Point(16, 16)
    $instruction.Size = New-Object System.Drawing.Size(328, 42)
    $instruction.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $instruction.Text = if ($isEdit) {
        'You can replace the password for the logon location shown below.'
    } else {
        'Type the name of a server or Web site, and the user name and password you use to access it.'
    }
    $form.Controls.Add($instruction)
    $fieldLabelX = 16
    $fieldControlX = 108
    $fieldControlWidth = 236
    $fieldTop = 67
    $fieldSpacing = 31
    $lblResource = New-Object System.Windows.Forms.Label
    $lblResource.Text = 'Log on to:'
    $lblResource.Location = New-Object System.Drawing.Point($fieldLabelX, $($fieldTop + 3))
    $lblResource.AutoSize = $true
    $form.Controls.Add($lblResource)
    $txtResource = New-Object System.Windows.Forms.TextBox
    $txtResource.Location = New-Object System.Drawing.Point($fieldControlX, $fieldTop)
    $txtResource.Size = New-Object System.Drawing.Size($fieldControlWidth, 23)
    $txtResource.Text = if ($isEdit) { [string]$SelectedObj.Target } else { '' }
    $txtResource.ReadOnly = $isEdit
    $form.Controls.Add($txtResource)
    $lblIdentity = New-Object System.Windows.Forms.Label
    $lblIdentity.Text = 'User name:'
    $lblIdentity.Location = New-Object System.Drawing.Point($fieldLabelX, $($fieldTop + $fieldSpacing + 3))
    $lblIdentity.AutoSize = $true
    $form.Controls.Add($lblIdentity)
    $txtIdentity = New-Object System.Windows.Forms.TextBox
    $txtIdentity.Location = New-Object System.Drawing.Point($fieldControlX, $($fieldTop + $fieldSpacing))
    $txtIdentity.Size = New-Object System.Drawing.Size($fieldControlWidth, 23)
    $txtIdentity.Text = if ($isEdit) { [string]$SelectedObj.Username } else { '' }
    $txtIdentity.ReadOnly = $isEdit
    $form.Controls.Add($txtIdentity)
    $lblAuthenticator = New-Object System.Windows.Forms.Label
    $lblAuthenticator.Text = 'Password:'
    $lblAuthenticator.Location = New-Object System.Drawing.Point($fieldLabelX, $($fieldTop + (2 * $fieldSpacing) + 3))
    $lblAuthenticator.AutoSize = $true
    $form.Controls.Add($lblAuthenticator)
    $txtAuthenticator = New-Object System.Windows.Forms.TextBox
    $txtAuthenticator.Location = New-Object System.Drawing.Point($fieldControlX, $($fieldTop + (2 * $fieldSpacing)))
    $txtAuthenticator.Size = New-Object System.Drawing.Size($fieldControlWidth, 23)
    $txtAuthenticator.UseSystemPasswordChar = $true
    $form.Controls.Add($txtAuthenticator)
    $chkShowPassword = New-Object System.Windows.Forms.CheckBox
    $chkShowPassword.Text = 'Show password'
    $chkShowPassword.Location = New-Object System.Drawing.Point($fieldControlX, 160)
    $chkShowPassword.AutoSize = $true
    $form.Controls.Add($chkShowPassword)
    $grpCredentialType = New-Object System.Windows.Forms.GroupBox
    $grpCredentialType.Text = 'Credential type'
    $grpCredentialType.Location = New-Object System.Drawing.Point(16, 187)
    $grpCredentialType.Size = New-Object System.Drawing.Size(328, 96)
    $form.Controls.Add($grpCredentialType)
    $rdoProgram = New-Object System.Windows.Forms.RadioButton
    $rdoProgram.Text = 'A Web site or program credential'
    $rdoProgram.Location = New-Object System.Drawing.Point(16, 22)
    $rdoProgram.Size = New-Object System.Drawing.Size(292, 22)
    $rdoProgram.Checked = $true
    $rdoProgram.Enabled = $false
    $grpCredentialType.Controls.Add($rdoProgram)
    $credentialDescription = New-Object System.Windows.Forms.Label
    $credentialDescription.Text = 'Choose this option to save a user name and password for a Web site or program.'
    $credentialDescription.Location = New-Object System.Drawing.Point(38, 45)
    $credentialDescription.Size = New-Object System.Drawing.Size(270, 38)
    $credentialDescription.Font = New-Object System.Drawing.Font('Segoe UI', 8)
    $credentialDescription.Enabled = $false
    $grpCredentialType.Controls.Add($credentialDescription)
    $grpProvider = New-Object System.Windows.Forms.GroupBox
    $grpProvider.Text = 'Provider details'
    $grpProvider.Location = New-Object System.Drawing.Point(16, 295)
    $grpProvider.Size = New-Object System.Drawing.Size(328, 130)
    $form.Controls.Add($grpProvider)
    $lblVault = New-Object System.Windows.Forms.Label
    $lblVault.Text = 'Vault:'
    $lblVault.Location = New-Object System.Drawing.Point(12, 27)
    $lblVault.AutoSize = $true
    $grpProvider.Controls.Add($lblVault)
    $txtVault = New-Object System.Windows.Forms.TextBox
    $txtVault.Location = New-Object System.Drawing.Point(120, 24)
    $txtVault.Size = New-Object System.Drawing.Size(194, 23)
    $txtVault.Text = if ($isEdit) { [string]$SelectedObj.VaultName } else { 'Web Credentials' }
    $txtVault.ReadOnly = $isEdit
    $grpProvider.Controls.Add($txtVault)
    $lblSchema = New-Object System.Windows.Forms.Label
    $lblSchema.Text = 'Credential schema:'
    $lblSchema.Location = New-Object System.Drawing.Point(12, 59)
    $lblSchema.AutoSize = $true
    $grpProvider.Controls.Add($lblSchema)
    $txtSchema = New-Object System.Windows.Forms.TextBox
    $txtSchema.Location = New-Object System.Drawing.Point(120, 56)
    $txtSchema.Size = New-Object System.Drawing.Size(194, 23)
    $txtSchema.Text = if ($isEdit) { [string]$SelectedObj.Schema } else { 'Windows Web Password Credential' }
    $txtSchema.ReadOnly = $isEdit
    $grpProvider.Controls.Add($txtSchema)
    $lblSavedBy = New-Object System.Windows.Forms.Label
    $lblSavedBy.Text = 'Saved by:'
    $lblSavedBy.Location = New-Object System.Drawing.Point(12, 91)
    $lblSavedBy.AutoSize = $true
    $grpProvider.Controls.Add($lblSavedBy)
    $txtSavedBy = New-Object System.Windows.Forms.TextBox
    $txtSavedBy.Location = New-Object System.Drawing.Point(120, 88)
    $txtSavedBy.Size = New-Object System.Drawing.Size(194, 23)
    $txtSavedBy.Text = if ($isEdit) { [string]$SelectedObj.SavedBy } else { 'Credential Manager' }
    $grpProvider.Controls.Add($txtSavedBy)
    if ($isEdit) {
        $grpMetadata = New-Object System.Windows.Forms.GroupBox
        $grpMetadata.Text = 'Credential information'
        $grpMetadata.Location = New-Object System.Drawing.Point(16, 437)
        $grpMetadata.Size = New-Object System.Drawing.Size(328, 116)
        $form.Controls.Add($grpMetadata)
        $metadata = New-Object System.Windows.Forms.TextBox
        $metadata.Multiline = $true
        $metadata.ReadOnly = $true
        $metadata.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
        $metadata.Location = New-Object System.Drawing.Point(12, 22)
        $metadata.Size = New-Object System.Drawing.Size(298, 80)
        $metadata.Text = @(
            "Vault GUID: $($SelectedObj.VaultGuid)",
            "Location: $($SelectedObj.VaultLocation)",
            "Protection: $($SelectedObj.VaultProtection)",
            "Reported credential count: $($SelectedObj.VaultReportedCount)",
            "Package SID: $($SelectedObj.PackageSid)",
            "Saved By: $($SelectedObj.SavedBy)",
            "Hidden: $($SelectedObj.Hidden)",
            "Roaming: $($SelectedObj.Roaming)"
        ) -join [Environment]::NewLine
        $grpMetadata.Controls.Add($metadata)
    }
    $buttonTop = if ($isEdit) { 569 } else { 443 }
    $ok = New-Object System.Windows.Forms.Button
    $ok.Text = 'OK'
    $ok.Location = New-Object System.Drawing.Point(186, $buttonTop)
    $ok.Size = New-Object System.Drawing.Size(75, 25)
    $form.Controls.Add($ok)
    $cancel = New-Object System.Windows.Forms.Button
    $cancel.Text = 'Cancel'
    $cancel.Location = New-Object System.Drawing.Point(269, $buttonTop)
    $cancel.Size = New-Object System.Drawing.Size(75, 25)
    $cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.Controls.Add($cancel)
    $form.AcceptButton = $ok
    $form.CancelButton = $cancel
    $chkShowPassword.Add_CheckedChanged({
        $txtAuthenticator.UseSystemPasswordChar = -not $chkShowPassword.Checked
        $txtAuthenticator.Focus()
    })
    $ok.Add_Click({
        $errors = New-Object System.Collections.Generic.List[string]
        if ([string]::IsNullOrWhiteSpace($txtIdentity.Text)) { [void]$errors.Add("- 'User name' cannot be left blank.") }
        if ([string]::IsNullOrWhiteSpace($txtAuthenticator.Text)) { [void]$errors.Add("- 'Password' cannot be left blank.") }
        if ([string]::IsNullOrWhiteSpace($txtVault.Text)) { [void]$errors.Add("- 'Vault' cannot be left blank.") }
        if ([string]::IsNullOrWhiteSpace($txtSchema.Text)) { [void]$errors.Add("- 'Credential schema' cannot be left blank.") }
        if ($errors.Count -gt 0) {
            $errorMessage = "The information provided contains errors and cannot be saved:`n`n" + ($errors -join "`n")
            [System.Windows.Forms.MessageBox]::Show($errorMessage, 'Malformed Data Error', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
            return
        }
        $form.Tag = [pscustomobject]@{
            VaultName = [string]$txtVault.Text
            Schema = [string]$txtSchema.Text
            Identity = [string]$txtIdentity.Text
            Authenticator = [string]$txtAuthenticator.Text
            Resource = [string]$txtResource.Text
            SavedBy = [string]$txtSavedBy.Text
        }
        $form.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $form.Close()
    })
    $cancel.Add_Click({
        $form.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
        $form.Close()
    })
    $dialogResult = $form.ShowDialog($MainForm)
    $result = if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) { $form.Tag } else { $null }
    $txtAuthenticator.Clear()
    $chkShowPassword.Checked = $false
    return $result
}
function Get-PasswordVaultCredentials {
    param([switch]$IncludeSecrets)
    $found = @()
    try {
        if ($null -eq $Vault) {
            script:Write-TraceLog "PasswordVault is unavailable"
            return $found
        }
        script:Write-TraceLog "Retrieving the PasswordVault-only diagnostic dataset..."
        $creds = $Vault.RetrieveAll()
        if ($null -eq $creds) { return $found }
        foreach ($c in $creds) {
            if ($null -eq $c) { continue }
            try {
                if ($IncludeSecrets) { $c.RetrievePassword() }
                $found += [PSCustomObject]@{
                    Target = $c.Resource
                    Username = $c.UserName
                    Password = if ($IncludeSecrets) { $c.Password } else { $null }
                    SecretLoaded = [bool]$IncludeSecrets
                    Type = 'Web'
                    Provider = 'PasswordVault'
                    VaultName = 'Web Credentials'
                    Schema = 'Windows Web Password Credential'
                }
            } catch {
                Write-Warning "Failed to retrieve PasswordVault password for $($c.Resource): $_"
            }
        }
    } catch {
        Write-Warning "PasswordVault RetrieveAll failed: $_"
    }
    return $found
}
function Get-WebCredentials {
    param([object[]]$PasswordVaultCredentials)
    $found = @()
    if ($null -eq $PasswordVaultCredentials) {
        $PasswordVaultCredentials = @(script:Get-PasswordVaultCredentials)
    }
    foreach ($credential in $PasswordVaultCredentials) {
        if ($null -ne $credential) { $found += $credential }
    }
    # Compatibility heuristic: include selected Snapshot/MicrosoftStore items exposed by native Vault enumeration.
    script:Write-TraceLog "Searching for Snapshot credentials in Vault API..."
    try {
        $allVaults = script:Get-AllVaultGuids
        foreach ($vaultGuid in $allVaults) {
            try {
                $vaultMgr = New-Object VaultManager($vaultGuid)
                $items = $vaultMgr.EnumerateItems()
                foreach ($item in $items) {
                    if ($item.Resource -match "Snapshot" -or $item.FriendlyName -match "Snapshot" -or 
                        $item.Resource -match "MicrosoftStore" -or $item.FriendlyName -match "MicrosoftStore") {
                        script:Write-TraceLog "Found Snapshot credential in Vault: $($item.Resource)"
                        $found += [PSCustomObject]@{
                            Target = $item.Resource
                            Username = $item.Identity
                            Password = $null
                            SecretLoaded = $false
                            Type   = "Vault/Web"
                            Provider = "VaultApi"
                            VaultName = "Web Credentials"
                            Schema = $item.FriendlyName
                        }
                    }
                }
                $vaultMgr.Dispose()
            } catch {
                # This optional heuristic is best-effort; skip vaults that cannot be opened or decoded.
            }
        }
    } catch {
        Write-Warning "Error searching vaults: $_"
    }
    # Merge credentials that Windows itself classifies under the Web Credentials vault.
    # PasswordVault can omit package-scoped/system-owned Web credentials that vaultcmd still enumerates.
    try {
        $vaultcmdWeb = @(script:Get-VaultcmdCredentials | Where-Object { $_.VaultName -eq 'Web Credentials' })
        foreach ($vc in $vaultcmdWeb) {
            $matches = @($found | Where-Object {
                $_.Target -eq $vc.Resource -and $_.Username -eq $vc.Identity
            })
            if ($matches.Count -gt 0) {
                # PasswordVault exposes the logical credential but not the owning package metadata.
                # Enrich the existing row so Legacy Edge (EdgeHTML) can be identified conservatively.
                foreach ($existing in $matches) {
                    foreach ($metadataName in @('VaultGuid','VaultLocation','VaultProtection','VaultReportedCount','Schema','PackageSid','SavedBy','Hidden','Roaming')) {
                        $sourceProperty = $vc.PSObject.Properties[$metadataName]
                        if ($null -ne $sourceProperty -and $null -ne $sourceProperty.Value) {
                            $existing | Add-Member -NotePropertyName $metadataName -NotePropertyValue $sourceProperty.Value -Force
                        }
                    }
                }
            } else {
                $found += [PSCustomObject]@{
                    Target     = $vc.Resource
                    Username   = $vc.Identity
                    Password   = $null
                    Type       = 'VaultCmd/Web'
                    Provider   = 'VaultCmd'
                    VaultName  = $vc.VaultName
                    VaultGuid  = $vc.VaultGuid
                    VaultLocation = $vc.VaultLocation
                    VaultProtection = $vc.VaultProtection
                    VaultReportedCount = $vc.VaultReportedCount
                    Schema     = $vc.Schema
                    PackageSid = $vc.PackageSid
                    SavedBy    = $vc.SavedBy
                    Hidden     = $vc.Hidden
                    Roaming    = $vc.Roaming
                }
                script:Write-TraceLog "Added vaultcmd Web credential: $($vc.Resource) / $($vc.Identity)"
            }
        }
    } catch {
        Write-Warning "Error merging vaultcmd Web credentials: $_"
    }
    script:Write-TraceLog "Total web credentials found: $($found.Count)"
    return $found
}
# -------------------------------------------------------------
# NATIVE BACKUP, RESTORE, AND PASSWORD-RESET WIZARD LAUNCHERS
# -------------------------------------------------------------
function Invoke-KeyMgrCredentialTransferWizard {
    <#
    Opens Microsoft's Stored User Names and Passwords wizard (credwiz.exe). This is the supported
    interactive .crd backup/restore experience: the backup page accepts a path through its Browse
    control. Removable media is recommended for resilience but is not a hard destination requirement.
    The wizard covers remembered Windows logon credentials; it does not back up browser passwords.
    #>
    $credwizPath = Join-Path ([Environment]::SystemDirectory) 'credwiz.exe'
    if (-not (Test-Path -LiteralPath $credwizPath -PathType Leaf)) {
        throw "The Windows Credential Backup and Restore Wizard was not found: $credwizPath"
    }
    script:Write-KeyMgrRuntimeLog 'CREDWIZ' "Starting Stored User Names and Passwords wizard: $credwizPath"
    Start-Process -FilePath $credwizPath -Wait
    script:Refresh-TabbedUI
}
function Invoke-KeyMgrPasswordResetWizard {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('Create','Restore')]
        [string]$Operation
    )
    # These keymgr.dll exports are the local-account password-reset-disk workflow. They require
    # removable media and are intentionally kept separate from credwiz credential transfer.
    $rundll32Path = Join-Path ([Environment]::SystemDirectory) 'rundll32.exe'
    if (-not (Test-Path -LiteralPath $rundll32Path -PathType Leaf)) {
        throw "The Windows rundll32 launcher was not found: $rundll32Path"
    }
    $entryPoint = if ($Operation -eq 'Create') { 'PRShowSaveWizardExW' } else { 'PRShowRestoreWizardExW' }
    script:Write-KeyMgrRuntimeLog 'PASSWORD-RESET' ("Starting {0} password-reset-disk wizard through {1}." -f $Operation.ToLowerInvariant(), $entryPoint)
    Start-Process -FilePath $rundll32Path -ArgumentList ("keymgr.dll,{0}" -f $entryPoint) -Wait
}
function Show-KeyMgrPasswordResetDialog {
    $choice = [System.Windows.Forms.MessageBox]::Show(
        "The password reset disk workflow is different from a credential backup and requires removable media.`n`nYes: create a password reset disk`nNo: restore with a password reset disk`nCancel: return to KeyMgr",
        'Password Reset Disk',
        [System.Windows.Forms.MessageBoxButtons]::YesNoCancel,
        [System.Windows.Forms.MessageBoxIcon]::Information
    )
    if ($choice -eq [System.Windows.Forms.DialogResult]::Yes) {
        script:Invoke-KeyMgrPasswordResetWizard -Operation Create
    }
    elseif ($choice -eq [System.Windows.Forms.DialogResult]::No) {
        script:Invoke-KeyMgrPasswordResetWizard -Operation Restore
    }
}

# Credential lists use the same native WinForms ListView scrolling model as Diagnostics:
# Details view, fixed-width columns, and a ListView docked directly in its page/layout cell.
# WinForms displays the native horizontal scrollbar whenever the combined column width exceeds
# the visible client width; no parallel scrollbar state or user32 message shim is maintained.
# -------------------------------------------------------------
# 6. INTERACTIVE TABBED USER INTERFACE
# -------------------------------------------------------------
$MainForm = New-Object System.Windows.Forms.Form
$MainForm.Text = "Stored Usernames and Passwords"
$MainForm.Size = New-Object System.Drawing.Size(560, 616)
$MainForm.MinimumSize = New-Object System.Drawing.Size(560, 616)
$MainForm.StartPosition = "CenterScreen"
$MainForm.FormBorderStyle = "Sizable"
$MainForm.MaximizeBox = $True; $MainForm.MinimizeBox = $True
$MainForm.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$MainForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)
try {
    $CredwizPath = Join-Path ([Environment]::SystemDirectory) 'credwiz.exe'
    $MainForm.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($CredwizPath)
    $MainForm.ShowIcon = $True
} catch {}
$InfoLabel = New-Object System.Windows.Forms.Label
$InfoLabel.Text = "Windows can store log-on credentials for servers, websites and programs. When you revisit one of those locations, Windows will try to log you on automatically."
$InfoLabel.Location = New-Object System.Drawing.Point(12, 36)
$InfoLabel.Size = New-Object System.Drawing.Size(520, 60)
$InfoLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$InfoLabel.AutoEllipsis = $True
$MainForm.Controls.Add($InfoLabel)
$TabControl = New-Object System.Windows.Forms.TabControl
$TabControl.Location = New-Object System.Drawing.Point(12, 104)
$TabControl.Size = New-Object System.Drawing.Size(400, 360)
$TabControl.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$MainForm.Controls.Add($TabControl)
function New-KeyMgrFilteredPageLayout {
    param([System.Windows.Forms.TabPage]$Page, [System.Windows.Forms.Label]$Label, [System.Windows.Forms.TextBox]$TextBox, [System.Windows.Forms.TabControl]$Body)
    $Page.Padding = New-Object System.Windows.Forms.Padding(5)
    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = [System.Windows.Forms.DockStyle]::Fill
    $layout.Margin = New-Object System.Windows.Forms.Padding(0)
    $layout.ColumnCount = 2; $layout.RowCount = 2
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 47)))
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 30)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $Label.Anchor = [System.Windows.Forms.AnchorStyles]::Left
    $Label.AutoSize = $True
    $Label.Margin = New-Object System.Windows.Forms.Padding(0, 0, 3, 0)
    $TextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $TextBox.Margin = New-Object System.Windows.Forms.Padding(0)
    $Body.Anchor = [System.Windows.Forms.AnchorStyles]::None
    $Body.Dock = [System.Windows.Forms.DockStyle]::Fill
    $Body.Margin = New-Object System.Windows.Forms.Padding(0, 3, 0, 0)
    [void]$layout.Controls.Add($Label, 0, 0)
    [void]$layout.Controls.Add($TextBox, 1, 0)
    [void]$layout.Controls.Add($Body, 0, 1)
    $layout.SetColumnSpan($Body, 2)
    $Page.Controls.Add($layout)
}
# Tab Page 1: Web Credentials
$TabWeb = New-Object System.Windows.Forms.TabPage
$TabWeb.Text = "Web Credentials"
$TabWeb.Padding = New-Object System.Windows.Forms.Padding(3)
$TabControl.Controls.Add($TabWeb)
$ListViewWeb = New-Object System.Windows.Forms.ListView
$ListViewWeb.Dock = "Fill"
$ListViewWeb.View = "Details"
$ListViewWeb.FullRowSelect = $True; $ListViewWeb.MultiSelect = $False; $ListViewWeb.HeaderStyle = "Nonclickable"
[void]$ListViewWeb.Columns.Add("Resource / Website", 420)
[void]$ListViewWeb.Columns.Add("Identity Name", 260)
$TabWeb.Controls.Add($ListViewWeb)
# Tab Page 2: Windows Credentials
$TabWin = New-Object System.Windows.Forms.TabPage
$TabWin.Text = "Windows Credentials"
$TabWin.AutoScroll = $False
$TabControl.Controls.Add($TabWin)
# A filter plus category tabs gives each credential type the full page height. This keeps
# the native tabbed-dialog model while remaining usable when a category contains many items.
$LblWinFilter = New-Object System.Windows.Forms.Label
$LblWinFilter.Text = "Filter:"
$LblWinFilter.Location = New-Object System.Drawing.Point(8, 11)
$LblWinFilter.Size = New-Object System.Drawing.Size(40, 20)
$TxtWinFilter = New-Object System.Windows.Forms.TextBox
$TxtWinFilter.Location = New-Object System.Drawing.Point(55, 8)
$TxtWinFilter.Size = New-Object System.Drawing.Size(313, 23)
$TxtWinFilter.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$WinCategoryTabs = New-Object System.Windows.Forms.TabControl
$WinCategoryTabs.Location = New-Object System.Drawing.Point(8, 38)
$WinCategoryTabs.Size = New-Object System.Drawing.Size(360, 287)
$WinCategoryTabs.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
New-KeyMgrFilteredPageLayout -Page $TabWin -Label $LblWinFilter -TextBox $TxtWinFilter -Body $WinCategoryTabs
function New-CredentialGrid {
    param([string]$Title)
    $Page = New-Object System.Windows.Forms.TabPage
    $Page.Text = $Title
    $Page.Padding = New-Object System.Windows.Forms.Padding(3)
    [void]$WinCategoryTabs.TabPages.Add($Page)
    $LV = New-Object System.Windows.Forms.ListView
    $LV.Dock = [System.Windows.Forms.DockStyle]::Fill
    $LV.View = "Details"
    $LV.FullRowSelect = $True
    $LV.MultiSelect = $False
    $LV.HideSelection = $False
    $LV.HeaderStyle = "Nonclickable"
    [void]$LV.Columns.Add("Logged on to", 420)
    [void]$LV.Columns.Add("User Name", 260)
    $Page.Controls.Add($LV)
    return $LV
}
$LV_WinCore = script:New-CredentialGrid "Windows"
$LV_WinCert = script:New-CredentialGrid "Certificate-based"
$LV_WinGen  = script:New-CredentialGrid "Generic"
$TabWinCore = $WinCategoryTabs.TabPages[0]
$TabWinCert = $WinCategoryTabs.TabPages[1]
$TabWinGen  = $WinCategoryTabs.TabPages[2]
function New-WindowsCredentialListItem {
    param([object]$Credential)
    $targetText = if ($null -ne $Credential.Target) { [string]$Credential.Target } else { '' }
    $userText = if ($null -ne $Credential.Username) { [string]$Credential.Username } else { '' }
    $item = New-Object System.Windows.Forms.ListViewItem($targetText)
    [void]$item.SubItems.Add($userText)
    $item.Tag = $Credential
    return $item
}
function Update-WindowsCredentialLists {
    $filterText = if ($null -ne $TxtWinFilter) { $TxtWinFilter.Text.Trim() } else { '' }
    $views = @(
        [PSCustomObject]@{ List = $LV_WinCore; Collection = $Global:WinCoreColl; Page = $TabWinCore; Title = 'Windows' },
        [PSCustomObject]@{ List = $LV_WinCert; Collection = $Global:WinCertColl; Page = $TabWinCert; Title = 'Certificate-based' },
        [PSCustomObject]@{ List = $LV_WinGen; Collection = $Global:WinGenColl; Page = $TabWinGen; Title = 'Generic' }
    )
    foreach ($view in $views) {
        if ($null -eq $view.List -or $view.List.IsDisposed) { continue }
        $view.List.BeginUpdate()
        try {
            $view.List.Items.Clear()
            $collection = $view.Collection
            if ($null -ne $collection) {
                foreach ($credential in $collection) {
                    if ($null -eq $credential) { continue }
                    $targetText = if ($null -ne $credential.Target) { [string]$credential.Target } else { '' }
                    $userText = if ($null -ne $credential.Username) { [string]$credential.Username } else { '' }
                    if ([string]::IsNullOrWhiteSpace($filterText) -or
                        $targetText.IndexOf($filterText, [System.StringComparison]::CurrentCultureIgnoreCase) -ge 0 -or
                        $userText.IndexOf($filterText, [System.StringComparison]::CurrentCultureIgnoreCase) -ge 0) {
                        [void]$view.List.Items.Add((script:New-WindowsCredentialListItem -Credential $credential))
                    }
                }
            }
        } finally {
            $view.List.EndUpdate()
        }
        $view.Page.Text = "{0} ({1})" -f $view.Title, $view.List.Items.Count
    }
}
# --- Tab Page 3: Browser Credentials ---
$TabEdge = New-Object System.Windows.Forms.TabPage
$TabEdge.Text = "Browser Credentials"
$TabEdge.AutoScroll = $False
$TabControl.Controls.Add($TabEdge)
$LblEdgeTabFilter = New-Object System.Windows.Forms.Label
$LblEdgeTabFilter.Text = "Filter:"
$LblEdgeTabFilter.Location = New-Object System.Drawing.Point(8, 11)
$LblEdgeTabFilter.Size = New-Object System.Drawing.Size(40, 20)
$TxtEdgeTabFilter = New-Object System.Windows.Forms.TextBox
$TxtEdgeTabFilter.Location = New-Object System.Drawing.Point(55, 8)
$TxtEdgeTabFilter.Size = New-Object System.Drawing.Size(313, 23)
$TxtEdgeTabFilter.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
# Browser/version tabs mirror the Windows Credentials category tabs. Each provider keeps an
# independent selection and column set while sharing the Browser Credentials filter.
$BrowserCategoryTabs = New-Object System.Windows.Forms.TabControl
$BrowserCategoryTabs.ShowToolTips = $true
$BrowserCategoryTabs.Location = New-Object System.Drawing.Point(8, 38)
$BrowserCategoryTabs.Size = New-Object System.Drawing.Size(360, 287)
$BrowserCategoryTabs.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
New-KeyMgrFilteredPageLayout -Page $TabEdge -Label $LblEdgeTabFilter -TextBox $TxtEdgeTabFilter -Body $BrowserCategoryTabs
function New-BrowserCredentialGrid {
    param(
        [Parameter(Mandatory=$true)][string]$Title,
        [Parameter(Mandatory=$true)][object[]]$Columns,
        [switch]$ShowPendingHeader
    )
    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $Title
    $page.Padding = New-Object System.Windows.Forms.Padding(3)
    [void]$BrowserCategoryTabs.TabPages.Add($page)
    $listView = New-Object System.Windows.Forms.ListView
    $listView.Dock = [System.Windows.Forms.DockStyle]::Fill
    $listView.Margin = New-Object System.Windows.Forms.Padding(0)
    $listView.View = 'Details'
    $listView.FullRowSelect = $true
    $listView.MultiSelect = $false
    $listView.HideSelection = $false
    $listView.HeaderStyle = 'Nonclickable'
    foreach ($column in $Columns) { [void]$listView.Columns.Add([string]$column.Text, [int]$column.Width) }
    $pendingLabel = $null
    if ($ShowPendingHeader) {
        $layout = New-Object System.Windows.Forms.TableLayoutPanel
        $layout.Dock = [System.Windows.Forms.DockStyle]::Fill
        $layout.Margin = New-Object System.Windows.Forms.Padding(0)
        $layout.ColumnCount = 1
        $layout.RowCount = 2
        [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
        [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34)))
        [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
        $pendingLabel = New-Object System.Windows.Forms.Label
        $pendingLabel.Text = 'No pending Edge changes.'
        $pendingLabel.Dock = [System.Windows.Forms.DockStyle]::Fill
        $pendingLabel.Margin = New-Object System.Windows.Forms.Padding(0)
        $pendingLabel.Padding = New-Object System.Windows.Forms.Padding(3, 6, 3, 0)
        $pendingLabel.ForeColor = [System.Drawing.Color]::DimGray
        [void]$layout.Controls.Add($pendingLabel, 0, 0)
        [void]$layout.Controls.Add($listView, 0, 1)
        $page.Controls.Add($layout)
    } else {
        $page.Controls.Add($listView)
    }
    return [pscustomobject]@{ Page = $page; ListView = $listView; PendingLabel = $pendingLabel; BaseTitle = $Title }
}
$BrowserEdgeView = script:New-BrowserCredentialGrid -Title 'Edge (Chromium)' -ShowPendingHeader -Columns @(
    @{Text='Profile';Width=85}, @{Text='Site / Realm';Width=180}, @{Text='Username';Width=110},
    @{Text='Protection';Width=75}, @{Text='State';Width=125}
)
$LV_EdgeTab = $BrowserEdgeView.ListView
$LblBrowserPending = $BrowserEdgeView.PendingLabel
$TabBrowserEdge = $BrowserEdgeView.Page
$TabBrowserEdge.ToolTipText = 'Microsoft Edge (Chromium)'
$BrowserLegacyEdgeView = script:New-BrowserCredentialGrid -Title 'Edge (EdgeHTML)' -Columns @(
    @{Text='Detection';Width=180}, @{Text='Resource / Website';Width=260}, @{Text='Identity Name';Width=150},
    @{Text='Protection';Width=105}, @{Text='State';Width=125}
)
$LV_LegacyEdgeTab = $BrowserLegacyEdgeView.ListView
$TabBrowserLegacyEdge = $BrowserLegacyEdgeView.Page
$TabBrowserLegacyEdge.ToolTipText = 'Legacy Microsoft Edge (EdgeHTML) credentials identified in Windows Web Credentials'
$BrowserIE11View = script:New-BrowserCredentialGrid -Title 'IE 11' -Columns @(
    @{Text='Credential store';Width=115}, @{Text='Resource / Website';Width=190}, @{Text='Identity Name';Width=120},
    @{Text='Protection';Width=95}, @{Text='State';Width=110}
)
$LV_IE11Tab = $BrowserIE11View.ListView
$TabBrowserIE11 = $BrowserIE11View.Page
$TabBrowserIE11.ToolTipText = 'Internet Explorer 11 linked Web Credentials'
$BrowserIE79View = script:New-BrowserCredentialGrid -Title 'IE 7/9' -Columns @(
    @{Text='User scope';Width=95}, @{Text='Storage2 record';Width=210}, @{Text='Blob bytes';Width=75},
    @{Text='Protection';Width=105}, @{Text='State';Width=105}
)
$LV_IE79Tab = $BrowserIE79View.ListView
$TabBrowserIE79 = $BrowserIE79View.Page
$TabBrowserIE79.ToolTipText = 'Internet Explorer 7/9 IntelliForms Storage2 inventory'
# --- Tab Page 4: Diagnostics (Source Tabs) ---
$TabDiag = New-Object System.Windows.Forms.TabPage
$TabDiag.Text = "Diagnostics"
$TabDiag.AutoScroll = $False
$TabControl.Controls.Add($TabDiag)
# Display one source at a time. Each source retains an independent ListView and selection.
# Diagnostic rows never enable Add/Edit/Remove; .crd import is a separate explicit action.
$DiagnosticPanel = New-Object System.Windows.Forms.Panel
$DiagnosticPanel.Dock = [System.Windows.Forms.DockStyle]::Fill
$DiagnosticPanel.Padding = New-Object System.Windows.Forms.Padding(5)
$TabDiag.Controls.Add($DiagnosticPanel)
$DiagSourceTabs = New-Object System.Windows.Forms.TabControl
$DiagSourceTabs.Dock = [System.Windows.Forms.DockStyle]::Fill
$DiagSourceTabs.Multiline = $True
$DiagnosticPanel.Controls.Add($DiagSourceTabs)
function New-DiagnosticListPage {
    param(
        [string]$TabText,
        [string]$Heading,
        [object[]]$Columns,
        [switch]$IncludeFilter
    )
    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = $TabText
    $page.Padding = New-Object System.Windows.Forms.Padding(4)
    [void]$DiagSourceTabs.TabPages.Add($page)
    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = [System.Windows.Forms.DockStyle]::Fill
    $layout.ColumnCount = 1
    $layout.RowCount = 2
    $layout.Margin = New-Object System.Windows.Forms.Padding(0)
    [void]$layout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $headerHeight = if ($IncludeFilter) { 58 } else { 30 }
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, $headerHeight)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $page.Controls.Add($layout)
    $header = New-Object System.Windows.Forms.Panel
    $header.Dock = [System.Windows.Forms.DockStyle]::Fill
    $header.Margin = New-Object System.Windows.Forms.Padding(0)
    $headingLabel = New-Object System.Windows.Forms.Label
    $headingLabel.Text = $Heading
    $headingLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $headingLabel.Location = New-Object System.Drawing.Point(4, 5)
    $headingLabel.Size = New-Object System.Drawing.Size(330, 20)
    $headingLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $headingLabel.AutoEllipsis = $True
    $header.Controls.Add($headingLabel)
    $filterTextBox = $null
    if ($IncludeFilter) {
        $filterLabel = New-Object System.Windows.Forms.Label
        $filterLabel.Text = "Filter:"
        $filterLabel.Location = New-Object System.Drawing.Point(4, 32)
        $filterLabel.Size = New-Object System.Drawing.Size(40, 20)
        $header.Controls.Add($filterLabel)
        $filterTextBox = New-Object System.Windows.Forms.TextBox
        $filterTextBox.Location = New-Object System.Drawing.Point(51, 29)
        $filterTextBox.Size = New-Object System.Drawing.Size(283, 23)
        $filterTextBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
        $header.Controls.Add($filterTextBox)
    }
    $listView = New-Object System.Windows.Forms.ListView
    $listView.Dock = [System.Windows.Forms.DockStyle]::Fill
    $listView.Margin = New-Object System.Windows.Forms.Padding(0)
    $listView.View = "Details"
    $listView.FullRowSelect = $True
    $listView.MultiSelect = $False
    $listView.HideSelection = $False
    $listView.HeaderStyle = "Nonclickable"
    foreach ($column in $Columns) {
        [void]$listView.Columns.Add([string]$column.Text, [int]$column.Width)
    }
    [void]$layout.Controls.Add($header, 0, 0)
    [void]$layout.Controls.Add($listView, 0, 1)
    return [PSCustomObject]@{
        Page = $page
        ListView = $listView
        FilterTextBox = $filterTextBox
    }
}
$DiagWinCredsView = script:New-DiagnosticListPage -TabText "Windows" -Heading "Windows Credential Manager (cmdkey.exe / DPAPI)" -Columns @(
    @{ Text = "Source"; Width = 80 }, @{ Text = "Target"; Width = 200 }, @{ Text = "Username"; Width = 200 },
    @{ Text = "Type"; Width = 80 }, @{ Text = "Status"; Width = 100 }
)
$LV_WinCreds = $DiagWinCredsView.ListView
$DiagPasswordVaultView = script:New-DiagnosticListPage -TabText "Password Vault" -Heading "PasswordVault API (WinRT / System.Windows.Security)" -Columns @(
    @{ Text = "Source"; Width = 80 }, @{ Text = "Resource"; Width = 200 }, @{ Text = "Username"; Width = 200 },
    @{ Text = "Count"; Width = 80 }, @{ Text = "Status"; Width = 100 }
)
$LV_PasswordVault = $DiagPasswordVaultView.ListView
function Add-ListViewRow {
    param([System.Windows.Forms.ListView]$ListView, [object[]]$Values, [System.Drawing.Color]$Color = [System.Drawing.Color]::Black, $Tag = $null)
    if ($null -eq $ListView -or $ListView.IsDisposed -or $Values.Count -eq 0) { return }
    $item = New-Object System.Windows.Forms.ListViewItem([string]$Values[0])
    $item.ForeColor = $Color
    for ($i = 1; $i -lt $Values.Count; $i++) { [void]$item.SubItems.Add([string]$Values[$i]) }
    $item.Tag = $Tag
    [void]$ListView.Items.Add($item)
}
function Update-EdgeDiagnosticsViews {
    foreach ($list in @($LV_EdgeOverview, $LV_EdgeTrace, $LV_EdgeSchema, $LV_EdgeErrors)) {
        if ($null -ne $list -and -not $list.IsDisposed) { $list.Items.Clear() }
    }
    $overviewRows = [EdgeDiagnosticsEngine]::GetDatabaseOverview()
    foreach ($row in $overviewRows) {
        $color = if ($row.IntegrityResult -eq 'ok') { [System.Drawing.Color]::DarkGreen } else { [System.Drawing.Color]::DarkOrange }
        script:Add-ListViewRow $LV_EdgeOverview @(
            $row.ProfileName, $row.ProfileDirectory, $row.DatabasePath, $row.QueryDatabasePath,
            [Math]::Round(([double]$row.DatabaseSizeBytes / 1KB), 1), $row.SqliteVersion, $row.EdgeRunning, $row.OpenMode,
            $row.LoginRowCount, $row.StatsRowCount, $row.UserVersion, $row.MetaVersion, $row.JournalMode,
            $row.PageCount, $row.FreelistCount, $row.WalPresent, $row.ShmPresent,
            $row.V10Count, $row.V11Count, $row.V20Count, $row.RawDpapiCount, $row.EmptyCount, $row.UnknownCount,
            $row.DecryptSuccessCount, $row.DecryptFailureCount, $row.IntegrityResult, $row.LastScan
        ) $color $row
    }
    if ($LV_EdgeOverview.Items.Count -eq 0) {
        script:Add-ListViewRow $LV_EdgeOverview @('[No Edge profile databases found]') ([System.Drawing.Color]::Gray)
    }
    $traceRows = [EdgeDiagnosticsEngine]::GetSqlTrace()
    foreach ($row in $traceRows) {
        $color = if ($row.Result -match 'ERROR|BUSY|LOCKED|CORRUPT|CANTOPEN|NOTADB|CONSTRAINT') { [System.Drawing.Color]::Red } else { [System.Drawing.Color]::Black }
        script:Add-ListViewRow $LV_EdgeTrace @($row.Timestamp, $row.ProfileName, $row.Operation, $row.ObjectName, $row.Result, $row.Rows, $row.DurationMs, $row.Detail, $row.Sql) $color $row
    }
    if ($LV_EdgeTrace.Items.Count -eq 0) { script:Add-ListViewRow $LV_EdgeTrace @('[No SQL operations recorded]') ([System.Drawing.Color]::Gray) }
    $schemaRows = [EdgeDiagnosticsEngine]::GetSchemaInventory()
    foreach ($row in $schemaRows) {
        script:Add-ListViewRow $LV_EdgeSchema @($row.ProfileName, $row.ObjectName, $row.ObjectType, $row.ColumnName, $row.DataType, $row.Nullable, $row.DefaultValue, $row.PrimaryKeyOrder) ([System.Drawing.Color]::DarkSlateBlue) $row
    }
    if ($LV_EdgeSchema.Items.Count -eq 0) { script:Add-ListViewRow $LV_EdgeSchema @('[No schema information available]') ([System.Drawing.Color]::Gray) }
    $errorRows = [EdgeDiagnosticsEngine]::GetDiagnosticErrors()
    foreach ($row in $errorRows) {
        script:Add-ListViewRow $LV_EdgeErrors @($row.Timestamp, $row.ProfileName, $row.DatabasePath, $row.Stage, $row.SqliteCode, $row.SqliteResult, $row.Message, $row.Operation, $row.Sql) ([System.Drawing.Color]::Red) $row
    }
    if ($LV_EdgeErrors.Items.Count -eq 0) { script:Add-ListViewRow $LV_EdgeErrors @('[No Edge / SQLite errors recorded]') ([System.Drawing.Color]::DarkGreen) }
}
function New-EdgeDiagnosticsPage {
    $page = New-Object System.Windows.Forms.TabPage
    $page.Text = 'Edge / SQLite'
    $page.Padding = New-Object System.Windows.Forms.Padding(4)
    [void]$DiagSourceTabs.TabPages.Add($page)
    $layout = New-Object System.Windows.Forms.TableLayoutPanel
    $layout.Dock = [System.Windows.Forms.DockStyle]::Fill
    $layout.ColumnCount = 1
    $layout.RowCount = 2
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34)))
    [void]$layout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100)))
    $page.Controls.Add($layout)
    $toolbar = New-Object System.Windows.Forms.Panel
    $toolbar.Dock = [System.Windows.Forms.DockStyle]::Fill
    $toolbarLabel = New-Object System.Windows.Forms.Label
    $toolbarLabel.Text = 'Read-only observability. SQL trace omits credential values and encryption keys.'
    $toolbarLabel.Location = New-Object System.Drawing.Point(4, 8)
    $toolbarLabel.Size = New-Object System.Drawing.Size(300, 20)
    $toolbarLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $toolbar.Controls.Add($toolbarLabel)
    $clearTraceButton = New-Object System.Windows.Forms.Button
    $clearTraceButton.Text = 'Clear SQL Trace'
    $clearTraceButton.Location = New-Object System.Drawing.Point(305, 3)
    $clearTraceButton.Size = New-Object System.Drawing.Size(105, 27)
    $clearTraceButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $clearTraceButton.Add_Click({
        try {
            [EdgeDiagnosticsEngine]::ClearSqlTrace()
            script:Update-EdgeDiagnosticsViews
        } catch {
            script:Write-KeyMgrRuntimeLog 'EDGE-UI' $_
        }
    })
    $toolbar.Controls.Add($clearTraceButton)
    [void]$layout.Controls.Add($toolbar, 0, 0)
    $tabs = New-Object System.Windows.Forms.TabControl
    $tabs.Dock = [System.Windows.Forms.DockStyle]::Fill
    [void]$layout.Controls.Add($tabs, 0, 1)
    function New-EdgeDiagnosticSubview {
        param([string]$Title, [object[]]$Columns)
        $subPage = New-Object System.Windows.Forms.TabPage
        $subPage.Text = $Title
        [void]$tabs.TabPages.Add($subPage)
        $list = New-Object System.Windows.Forms.ListView
        $list.Dock = [System.Windows.Forms.DockStyle]::Fill
        $list.View = [System.Windows.Forms.View]::Details
        $list.FullRowSelect = $true
        $list.MultiSelect = $false
        $list.HideSelection = $false
        $list.HeaderStyle = [System.Windows.Forms.ColumnHeaderStyle]::Nonclickable
        foreach ($column in $Columns) { [void]$list.Columns.Add([string]$column.Text, [int]$column.Width) }
        $subPage.Controls.Add($list)
        return [PSCustomObject]@{ Page = $subPage; ListView = $list }
    }
    $overview = New-EdgeDiagnosticSubview -Title 'Overview' -Columns @(
        @{Text='Profile';Width=110}, @{Text='Directory';Width=85}, @{Text='Source DB';Width=320}, @{Text='Queried Copy';Width=280},
        @{Text='Size KB';Width=70}, @{Text='SQLite';Width=75}, @{Text='Edge Running';Width=85}, @{Text='Open Mode';Width=100},
        @{Text='Logins';Width=60}, @{Text='Stats';Width=55}, @{Text='User Ver';Width=60}, @{Text='Meta Ver';Width=65},
        @{Text='Journal';Width=60}, @{Text='Pages';Width=55}, @{Text='Free';Width=50}, @{Text='WAL';Width=45}, @{Text='SHM';Width=45},
        @{Text='v10';Width=45}, @{Text='v11';Width=45}, @{Text='v20';Width=45}, @{Text='DPAPI';Width=50}, @{Text='Empty';Width=50}, @{Text='Unknown';Width=60},
        @{Text='Decrypt OK';Width=70}, @{Text='Decrypt Fail';Width=75}, @{Text='Integrity';Width=100}, @{Text='Last Scan';Width=130}
    )
    $trace = New-EdgeDiagnosticSubview -Title 'SQL Trace' -Columns @(
        @{Text='Time';Width=90}, @{Text='Profile';Width=110}, @{Text='Operation';Width=70}, @{Text='Object';Width=100},
        @{Text='Result';Width=95}, @{Text='Rows';Width=55}, @{Text='Duration ms';Width=75}, @{Text='Detail';Width=330}, @{Text='SQL / Path';Width=520}
    )
    $schema = New-EdgeDiagnosticSubview -Title 'Schema' -Columns @(
        @{Text='Profile';Width=110}, @{Text='Object';Width=130}, @{Text='Kind';Width=60}, @{Text='Column';Width=140},
        @{Text='Type';Width=90}, @{Text='Nullable';Width=60}, @{Text='Default';Width=180}, @{Text='PK';Width=40}
    )
    $errors = New-EdgeDiagnosticSubview -Title 'Errors' -Columns @(
        @{Text='Time';Width=90}, @{Text='Profile';Width=110}, @{Text='Database';Width=300}, @{Text='Stage';Width=140},
        @{Text='Code';Width=50}, @{Text='Result';Width=100}, @{Text='Message';Width=360}, @{Text='Operation';Width=75}, @{Text='SQL';Width=420}
    )
    return [PSCustomObject]@{
        Page = $page
        Tabs = $tabs
        Overview = $overview.ListView
        Trace = $trace.ListView
        Schema = $schema.ListView
        Errors = $errors.ListView
    }
}
$DiagEdgeView = script:New-EdgeDiagnosticsPage
$LV_EdgeOverview = $DiagEdgeView.Overview
$LV_EdgeTrace = $DiagEdgeView.Trace
$LV_EdgeSchema = $DiagEdgeView.Schema
$LV_EdgeErrors = $DiagEdgeView.Errors
$LV_EdgeDiagnostics = $LV_EdgeOverview
$TxtEdgeFilter = $null
$DiagVaultApiView = script:New-DiagnosticListPage -TabText 'Vault Map' -Heading 'vaultcli.dll VAULT_ITEM metadata correlated with vaultcmd.exe' -Columns @(
    @{Text='Source';Width=75}, @{Text='Vault GUID';Width=230}, @{Text='Schema ID';Width=230}, @{Text='Friendly Name';Width=170},
    @{Text='Resource';Width=220}, @{Text='Identity';Width=160}, @{Text='Native Package SID';Width=360},
    @{Text='Flags';Width=90}, @{Text='Set Bits';Width=90}, @{Text='Properties';Width=70}, @{Text='Property Layout / ID / Type / Value / Raw';Width=680},
    @{Text='CLI Package SID';Width=360}, @{Text='CLI Saved By';Width=140}, @{Text='CLI Hidden';Width=70}, @{Text='CLI Roaming';Width=75},
    @{Text='Match';Width=210}, @{Text='Mapping Evidence';Width=560}, @{Text='Metadata Source';Width=115}, @{Text='GetItem HRESULT';Width=110}, @{Text='Detail';Width=360}
)
$LV_VaultApi = $DiagVaultApiView.ListView
$DiagVaultDecryptView = script:New-DiagnosticListPage -TabText "Vault Files" -Heading "Physical Vault filesystem artifacts (independent of logical Vault APIs)" -Columns @(
    @{Text="Root";Width=150}, @{Text="Root Path";Width=330}, @{Text="Vault GUID / Directory";Width=230}, @{Text="Vault Path";Width=360},
    @{Text="Policy";Width=50}, @{Text="Schema";Width=55}, @{Text=".vcrd";Width=50}, @{Text="Decrypted";Width=65},
    @{Text="Status";Width=120}, @{Text="Detail";Width=420}
)
$LV_VaultDecryption = $DiagVaultDecryptView.ListView
$DiagVaultcmdView = script:New-DiagnosticListPage -TabText "vaultcmd" -Heading "vaultcmd.exe CLI Reference (System-Protected Items)" -Columns @(
    @{ Text = "Source"; Width = 80 }, @{ Text = "Vault"; Width = 160 }, @{ Text = "Vault GUID"; Width = 250 },
    @{ Text = "Location"; Width = 320 }, @{ Text = "Protection"; Width = 90 }, @{ Text = "Reported Count"; Width = 95 },
    @{ Text = "Schema"; Width = 210 }, @{ Text = "Resource"; Width = 210 }, @{ Text = "Identity"; Width = 160 },
    @{ Text = "Package SID"; Width = 430 }, @{ Text = "Saved By"; Width = 140 }, @{ Text = "Hidden"; Width = 60 },
    @{ Text = "Roaming"; Width = 65 }, @{ Text = "Status"; Width = 80 }
)
$LV_Vaultcmd = $DiagVaultcmdView.ListView
$DiagErrorView = script:New-DiagnosticListPage -TabText "Errors" -Heading "Error Log" -Columns @(
    @{ Text = "Timestamp"; Width = 100 }, @{ Text = "Source"; Width = 120 }, @{ Text = "Error Message"; Width = 520 }
)
$LV_ErrorLog = $DiagErrorView.ListView
$Global:DiagnosticPageListViews = @(
    $LV_WinCreds, $LV_PasswordVault, $LV_EdgeOverview, $LV_VaultApi, $LV_VaultDecryption, $LV_Vaultcmd, $LV_ErrorLog
)
# Each diagnostic source owns an independent dataset; rows are not treated as equivalent records across providers.
$Global:DiagnosticListViews = @{
    'WinCreds'      = $LV_WinCreds
    'PasswordVault' = $LV_PasswordVault
    'EdgeOverview'  = $LV_EdgeOverview
    'EdgeTrace'     = $LV_EdgeTrace
    'EdgeSchema'    = $LV_EdgeSchema
    'EdgeErrors'    = $LV_EdgeErrors
    'VaultApi'      = $LV_VaultApi
    'VaultDecrypt'  = $LV_VaultDecryption
    'Vaultcmd'      = $LV_Vaultcmd
    'ErrorLog'      = $LV_ErrorLog
}
$Global:EdgeCollection = @()
$Global:LegacyEdgeBrowserCollection = @()
$Global:IE11BrowserCollection = @()
$Global:IEStorage2Collection = @()
$Global:BrowserPendingChanges = New-Object System.Collections.Generic.List[System.Object]
$Global:LastBrowserApplyRecovery = $null
function Get-KeyMgrIEStorage2Entries {
    $entries = New-Object System.Collections.Generic.List[System.Object]
    $path = 'HKCU:\Software\Microsoft\Internet Explorer\IntelliForms\Storage2'
    if (-not (Test-Path -LiteralPath $path)) { return $entries }
    try {
        $item = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
        foreach ($property in $item.PSObject.Properties) {
            if ($property.Name -match '^PS(Path|ParentPath|ChildName|Drive|Provider)$') { continue }
            $bytes = $property.Value -as [byte[]]
            [void]$entries.Add([pscustomobject]@{
                BrowserProvider = 'IEStorage2'; Provider = 'IEIntelliForms'; Browser = 'Internet Explorer 7/9'
                ProfileName = 'Current User'; Website = [string]$property.Name; Username = '[encrypted record]'
                EncryptionVersion = 'Storage2/DPAPI'; State = 'Inventory only'; RegistryPath = $path
                BlobSize = if ($null -ne $bytes) { $bytes.Length } else { 0 }; SourceItem = $null
            })
        }
    } catch { script:Write-KeyMgrRuntimeLog 'IE-STORAGE2' $_ }
    return $entries
}
function Get-KeyMgrLegacyEdgeEvidence {
    param($Credential)
    if ($null -eq $Credential) { return $null }
    $fields = [ordered]@{}
    foreach ($name in @('SavedBy','Target','Schema','PackageSid','VaultLocation')) {
        $property = $Credential.PSObject.Properties[$name]
        if ($null -ne $property -and -not [string]::IsNullOrWhiteSpace([string]$property.Value)) {
            $fields[$name] = [string]$property.Value
        }
    }
    foreach ($entry in $fields.GetEnumerator()) {
        if ($entry.Value -match '(?i)(Microsoft\.MicrosoftEdge|Microsoft\s+Edge|MicrosoftEdge|EdgeHTML)') {
            return ("{0}: {1}" -f $entry.Key, $entry.Value)
        }
    }
    return $null
}
function Update-KeyMgrBrowserProjections {
    $Global:LegacyEdgeBrowserCollection = @()
    $Global:IE11BrowserCollection = @()
    foreach ($credential in $Global:WebCollection) {
        if ($null -eq $credential) { continue }
        $provider = if ($credential.PSObject.Properties['Provider']) { [string]$credential.Provider } else { 'VaultApi' }
        $Global:IE11BrowserCollection += [pscustomobject]@{
            BrowserProvider = 'IE11'; Provider = $provider; Browser = 'Internet Explorer 11'
            ProfileName = 'Windows Web Credentials'; Website = [string]$credential.Target; Username = [string]$credential.Username
            EncryptionVersion = 'Windows Vault'; State = 'Saved / linked'; SourceItem = $credential
        }
        $legacyEvidence = script:Get-KeyMgrLegacyEdgeEvidence -Credential $credential
        if (-not [string]::IsNullOrWhiteSpace($legacyEvidence)) {
            $Global:LegacyEdgeBrowserCollection += [pscustomobject]@{
                BrowserProvider = 'LegacyEdge'; Provider = $provider; Browser = 'Microsoft Edge Legacy (EdgeHTML)'
                ProfileName = $legacyEvidence; Detection = $legacyEvidence; Website = [string]$credential.Target; Username = [string]$credential.Username
                EncryptionVersion = 'Windows Vault'; State = 'Saved / linked'; SourceItem = $credential
            }
        }
    }
    $Global:IEStorage2Collection = @(script:Get-KeyMgrIEStorage2Entries)
}
function Update-BrowserPendingState {
    if ($null -eq $LblBrowserPending -or $LblBrowserPending.IsDisposed) { return }
    $adds = 0; $edits = 0; $removes = 0
    foreach ($change in $Global:BrowserPendingChanges) {
        switch ([string]$change.Operation) { 'Add' { $adds++ } 'Edit' { $edits++ } 'Remove' { $removes++ } }
    }
    $count = $Global:BrowserPendingChanges.Count
    $LblBrowserPending.Text = if ($count -eq 0) { 'No pending Edge changes.' } else { "$count pending Edge change(s): $adds Add, $edits Edit, $removes Remove. Apply writes one verified batch." }
    $LblBrowserPending.ForeColor = if ($count -eq 0) { [System.Drawing.Color]::DimGray } else { [System.Drawing.Color]::DarkOrange }
    if ($null -ne $BtnApplyBrowser -and -not $BtnApplyBrowser.IsDisposed) { $BtnApplyBrowser.Enabled = $count -gt 0 }
    if ($null -ne $BtnRevertBrowser -and -not $BtnRevertBrowser.IsDisposed) { $BtnRevertBrowser.Enabled = $count -gt 0 }
}
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
function Get-KeyMgrBrowserPendingState {
    param($Row)
    if ($null -eq $Row -or -not $Row.PSObject.Properties['LoginId']) { return [string]$Row.State }
    foreach ($change in $Global:BrowserPendingChanges) {
        if ([string]$change.ProfilePath -eq [string]$Row.ProfilePath -and [int64]$change.LoginId -eq [int64]$Row.LoginId) {
            if ([string]$change.Operation -eq 'Edit') { return "Edit pending: $($change.OriginalProtection) -> $($change.Protection)" }
            if ([string]$change.Operation -eq 'Remove') { return 'Remove pending' }
        }
    }
    return 'Saved'
}
function Test-KeyMgrBrowserFilterMatch {
    param($Row, [string]$Query)
    if ([string]::IsNullOrWhiteSpace($Query)) { return $true }
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($propertyName in @('Browser','ProfileName','Detection','Website','Username','EncryptionVersion','State','BlobSize')) {
        $property = $Row.PSObject.Properties[$propertyName]
        if ($null -ne $property -and $null -ne $property.Value) { [void]$parts.Add([string]$property.Value) }
    }
    return (($parts -join ' ').IndexOf($Query.Trim(), [System.StringComparison]::CurrentCultureIgnoreCase) -ge 0)
}
function Add-EdgeDiagnosticListViewItem {
    param([Parameter(Mandatory=$true)][System.Windows.Forms.ListView]$ListView, [Parameter(Mandatory=$true)]$CredentialRow)
    $browserProvider = if ($CredentialRow.PSObject.Properties['BrowserProvider']) { [string]$CredentialRow.BrowserProvider } else { 'Edge' }
    $profile = if ($CredentialRow.PSObject.Properties['ProfileName']) { [string]$CredentialRow.ProfileName } else { '' }
    $website = if ($CredentialRow.PSObject.Properties['Website']) { [string]$CredentialRow.Website } else { '' }
    $username = if ($CredentialRow.PSObject.Properties['Username']) { [string]$CredentialRow.Username } else { '' }
    $protection = if ($CredentialRow.PSObject.Properties['EncryptionVersion']) { [string]$CredentialRow.EncryptionVersion } else { '' }
    $state = script:Get-KeyMgrBrowserPendingState -Row $CredentialRow
    $lvItem = New-Object System.Windows.Forms.ListViewItem($profile)
    if ($protection -eq 'ERROR') { $lvItem.ForeColor = [System.Drawing.Color]::Red }
    elseif ($browserProvider -like 'IE*') { $lvItem.ForeColor = [System.Drawing.Color]::DarkSlateBlue }
    else { $lvItem.ForeColor = [System.Drawing.Color]::DarkCyan }
    [void]$lvItem.SubItems.Add($website)
    if ($browserProvider -eq 'IEStorage2') {
        $blobSize = if ($CredentialRow.PSObject.Properties['BlobSize']) { [string]$CredentialRow.BlobSize } else { '0' }
        [void]$lvItem.SubItems.Add($blobSize)
    } else {
        [void]$lvItem.SubItems.Add($username)
    }
    [void]$lvItem.SubItems.Add($protection)
    [void]$lvItem.SubItems.Add($state)
    $lvItem.Tag = $CredentialRow
    [void]$ListView.Items.Add($lvItem)
}
function Add-KeyMgrBrowserPlaceholder {
    param([System.Windows.Forms.ListView]$ListView, [string]$Text)
    $item = New-Object System.Windows.Forms.ListViewItem($Text)
    $item.ForeColor = [System.Drawing.Color]::Gray
    1..4 | ForEach-Object { [void]$item.SubItems.Add('-') }
    [void]$ListView.Items.Add($item)
}
function Update-EdgeTabList {
    $browserLists = @($LV_EdgeTab, $LV_LegacyEdgeTab, $LV_IE11Tab, $LV_IE79Tab)
    foreach ($listView in $browserLists) {
        if ($null -eq $listView -or $listView.IsDisposed) { return }
        $listView.BeginUpdate()
        $listView.Items.Clear()
    }
    $edgeCount = 0; $legacyEdgeCount = 0; $ie11Count = 0; $ie79Count = 0
    try {
        $query = if ($null -ne $TxtEdgeTabFilter -and -not $TxtEdgeTabFilter.IsDisposed) { $TxtEdgeTabFilter.Text } else { '' }
        foreach ($edgeRow in $Global:EdgeCollection) {
            if ($null -eq $edgeRow) { continue }
            if (-not $edgeRow.PSObject.Properties['BrowserProvider']) { $edgeRow | Add-Member -NotePropertyName BrowserProvider -NotePropertyValue 'Edge' -Force }
            if (-not $edgeRow.PSObject.Properties['Provider']) { $edgeRow | Add-Member -NotePropertyName Provider -NotePropertyValue 'Edge' -Force }
            if (-not $edgeRow.PSObject.Properties['Browser']) { $edgeRow | Add-Member -NotePropertyName Browser -NotePropertyValue 'Edge Chromium' -Force }
            if (script:Test-KeyMgrBrowserFilterMatch -Row $edgeRow -Query $query) {
                script:Add-EdgeDiagnosticListViewItem -ListView $LV_EdgeTab -CredentialRow $edgeRow
                $edgeCount++
            }
        }
        foreach ($change in $Global:BrowserPendingChanges) {
            if ([string]$change.Operation -ne 'Add') { continue }
            $pendingRow = [pscustomobject]@{ BrowserProvider='Edge'; Provider='Edge'; Browser='Edge Chromium'; ProfileName=$change.ProfileName; ProfilePath=$change.ProfilePath; Website=$change.Website; Username=$change.Username; EncryptionVersion=$change.Protection; State='Add pending'; LoginId=0 }
            if (script:Test-KeyMgrBrowserFilterMatch -Row $pendingRow -Query $query) {
                script:Add-EdgeDiagnosticListViewItem -ListView $LV_EdgeTab -CredentialRow $pendingRow
                $edgeCount++
            }
        }
        foreach ($row in $Global:LegacyEdgeBrowserCollection) {
            if (script:Test-KeyMgrBrowserFilterMatch -Row $row -Query $query) {
                script:Add-EdgeDiagnosticListViewItem -ListView $LV_LegacyEdgeTab -CredentialRow $row
                $legacyEdgeCount++
            }
        }
        foreach ($row in $Global:IE11BrowserCollection) {
            if (script:Test-KeyMgrBrowserFilterMatch -Row $row -Query $query) {
                script:Add-EdgeDiagnosticListViewItem -ListView $LV_IE11Tab -CredentialRow $row
                $ie11Count++
            }
        }
        foreach ($row in $Global:IEStorage2Collection) {
            if (script:Test-KeyMgrBrowserFilterMatch -Row $row -Query $query) {
                script:Add-EdgeDiagnosticListViewItem -ListView $LV_IE79Tab -CredentialRow $row
                $ie79Count++
            }
        }
        if ($edgeCount -eq 0) { script:Add-KeyMgrBrowserPlaceholder -ListView $LV_EdgeTab -Text $(if ([string]::IsNullOrWhiteSpace($query)) { '[No Chromium Edge credentials found]' } else { '[No Chromium Edge entries match the current filter]' }) }
        if ($legacyEdgeCount -eq 0) { script:Add-KeyMgrBrowserPlaceholder -ListView $LV_LegacyEdgeTab -Text $(if ([string]::IsNullOrWhiteSpace($query)) { '[No Legacy Edge (EdgeHTML) Web Credentials identified]' } else { '[No Legacy Edge entries match the current filter]' }) }
        if ($ie11Count -eq 0) { script:Add-KeyMgrBrowserPlaceholder -ListView $LV_IE11Tab -Text $(if ([string]::IsNullOrWhiteSpace($query)) { '[No IE11 Web Credentials found]' } else { '[No IE11 entries match the current filter]' }) }
        if ($ie79Count -eq 0) { script:Add-KeyMgrBrowserPlaceholder -ListView $LV_IE79Tab -Text $(if ([string]::IsNullOrWhiteSpace($query)) { '[No IE7/9 Storage2 records found]' } else { '[No IE7/9 entries match the current filter]' }) }
        $TabBrowserEdge.Text = "Edge (Chromium) ($edgeCount)"
        $TabBrowserLegacyEdge.Text = "Edge (Legacy) ($legacyEdgeCount)"
        $TabBrowserIE11.Text = "IE 11 ($ie11Count)"
        $TabBrowserIE79.Text = "IE 9/7 ($ie79Count)"
    } finally {
        foreach ($listView in $browserLists) { $listView.EndUpdate() }
    }
    script:Update-BrowserPendingState
}
function Get-KeyMgrActiveBrowserListView {
    if ($null -eq $BrowserCategoryTabs -or $BrowserCategoryTabs.IsDisposed) { return $LV_EdgeTab }
    switch ($BrowserCategoryTabs.SelectedIndex) {
        1 { return $LV_LegacyEdgeTab }
        2 { return $LV_IE11Tab }
        3 { return $LV_IE79Tab }
        default { return $LV_EdgeTab }
    }
}
function Get-SelectedBrowserCredentialRow {
    $listView = script:Get-KeyMgrActiveBrowserListView
    if ($null -eq $listView -or $listView.IsDisposed -or $listView.SelectedIndices.Count -eq 0) { return $null }
    $item = $listView.Items[$listView.SelectedIndices[0]]
    if ($null -eq $item) { return $null }
    return $item.Tag
}
# Retain the original helper name for command-console and compatibility callers.
function Get-SelectedEdgeTabRow { return script:Get-SelectedBrowserCredentialRow }
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
        script:Write-KeyMgrRuntimeLog 'UI-EVENT' $_
        try {
            if ($Global:DiagnosticListViews -and $Global:DiagnosticListViews.ContainsKey('ErrorLog')) {
                $errorList = $Global:DiagnosticListViews['ErrorLog']
                if ($null -ne $errorList -and -not $errorList.IsDisposed) {
                    script:Add-DiagnosticErrorLogEntry -Source 'UI Event' -Message $_
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
    if ($null -ne $BtnImportCrd -and -not $BtnImportCrd.IsDisposed) { $BtnImportCrd.Visible = ($TabControl.SelectedIndex -eq 3) }
    if ($null -ne $BtnApplyBrowser -and -not $BtnApplyBrowser.IsDisposed) { $BtnApplyBrowser.Visible = ($TabControl.SelectedIndex -eq 2 -and $BrowserCategoryTabs.SelectedIndex -eq 0) }
    if ($null -ne $BtnRevertBrowser -and -not $BtnRevertBrowser.IsDisposed) { $BtnRevertBrowser.Visible = ($TabControl.SelectedIndex -eq 2 -and $BrowserCategoryTabs.SelectedIndex -eq 0) }
    script:Update-BrowserPendingState
    $context = script:Get-KeyMgrActiveProviderContext
    $addContext = script:Get-KeyMgrOperationContext -Operation 'Add'
    $BtnAdd.Enabled = script:Test-KeyMgrProviderCapability -Capability 'CanCreate' -Context $addContext
    $savedEdgeSelection = -not ($context.ProviderId -eq 'Edge' -and $context.HasSelection -and [int64]$context.SelectedItem.LoginId -le 0)
    $BtnEdit.Enabled = $context.HasSelection -and $savedEdgeSelection -and (script:Test-KeyMgrProviderCapability -Capability 'CanEdit' -Context $context)
    $BtnRemove.Enabled = $context.HasSelection -and $savedEdgeSelection -and (script:Test-KeyMgrProviderCapability -Capability 'CanDelete' -Context $context)
    $BtnAdd.Tag = $context.ProviderId
    $BtnEdit.Tag = $context.ProviderId
    $BtnRemove.Tag = $context.ProviderId
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
    script:Update-ButtonStates
}
function Clear-BrowserSelections($ActiveGrid) {
    if ($null -eq $ActiveGrid -or $ActiveGrid.IsDisposed) { return }
    $Global:LastFocusedGrid = $ActiveGrid
    foreach ($grid in @($LV_EdgeTab, $LV_LegacyEdgeTab, $LV_IE11Tab, $LV_IE79Tab)) {
        if ($null -ne $grid -and -not $grid.IsDisposed -and $grid -ne $ActiveGrid) { $grid.SelectedIndices.Clear() }
    }
    script:Update-ButtonStates
}
function Clear-DiagnosticSelections {
    param(
        [System.Windows.Forms.ListView]$ActiveListView
    )
    foreach ($listView in @($LV_WinCreds, $LV_PasswordVault, $LV_EdgeOverview, $LV_EdgeTrace, $LV_EdgeSchema, $LV_EdgeErrors, $LV_VaultApi, $LV_VaultDecryption, $LV_Vaultcmd, $LV_ErrorLog)) {
        if ($null -ne $listView -and -not $listView.IsDisposed -and $listView -ne $ActiveListView) {
            $listView.SelectedIndices.Clear()
        }
    }
    $Global:LastFocusedGrid = $ActiveListView
    script:Update-ButtonStates
}
function Show-EdgePropertyDialog {
    param($SelectedObj = $null)
    $isEdit = $null -ne $SelectedObj
    $profiles = [EdgeDiagnosticsEngine]::ListProfiles()
    if (-not $isEdit -and $profiles.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('No writable Edge profile with a Login Data database was found.', 'Add Edge Credential', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return $null
    }
    $propForm = New-Object System.Windows.Forms.Form
    $propForm.Text = if ($isEdit) { 'Stage Edge Credential Edit / Conversion' } else { 'Stage Edge Credential Add' }
    $propForm.ClientSize = New-Object System.Drawing.Size(470, 330)
    $propForm.StartPosition = 'CenterParent'
    $propForm.FormBorderStyle = 'FixedDialog'
    $propForm.MaximizeBox = $false; $propForm.MinimizeBox = $false
    $propForm.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $labels = @('Profile:', 'Website / realm:', 'User name:', 'Password:', 'Protection format:')
    for ($i = 0; $i -lt $labels.Count; $i++) {
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $labels[$i]; $label.Location = New-Object System.Drawing.Point(15, (23 + (38 * $i))); $label.AutoSize = $true
        $propForm.Controls.Add($label)
    }
    $cmbProfile = New-Object System.Windows.Forms.ComboBox
    $cmbProfile.Location = New-Object System.Drawing.Point(140, 20); $cmbProfile.Size = New-Object System.Drawing.Size(305, 23)
    $cmbProfile.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList; $cmbProfile.DisplayMember = 'DisplayName'
    foreach ($profile in $profiles) { [void]$cmbProfile.Items.Add($profile) }
    $propForm.Controls.Add($cmbProfile)
    $txtWebsite = New-Object System.Windows.Forms.TextBox
    $txtWebsite.Location = New-Object System.Drawing.Point(140, 58); $txtWebsite.Size = New-Object System.Drawing.Size(305, 23)
    $propForm.Controls.Add($txtWebsite)
    $txtUsername = New-Object System.Windows.Forms.TextBox
    $txtUsername.Location = New-Object System.Drawing.Point(140, 96); $txtUsername.Size = New-Object System.Drawing.Size(305, 23)
    $propForm.Controls.Add($txtUsername)
    $txtPassword = New-Object System.Windows.Forms.TextBox
    $txtPassword.Location = New-Object System.Drawing.Point(140, 134); $txtPassword.Size = New-Object System.Drawing.Size(305, 23); $txtPassword.UseSystemPasswordChar = $true
    $propForm.Controls.Add($txtPassword)
    $cmbProtection = New-Object System.Windows.Forms.ComboBox
    $cmbProtection.Location = New-Object System.Drawing.Point(140, 172); $cmbProtection.Size = New-Object System.Drawing.Size(130, 23)
    $cmbProtection.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    [void]$cmbProtection.Items.Add('v10'); [void]$cmbProtection.Items.Add('v11'); [void]$cmbProtection.Items.Add('v20')
    $propForm.Controls.Add($cmbProtection)
    $chkReveal = New-Object System.Windows.Forms.CheckBox
    $chkReveal.Text = 'Show password'; $chkReveal.Location = New-Object System.Drawing.Point(285, 174); $chkReveal.AutoSize = $true
    $chkReveal.Add_CheckedChanged({ $txtPassword.UseSystemPasswordChar = -not $chkReveal.Checked })
    $propForm.Controls.Add($chkReveal)
    $notice = New-Object System.Windows.Forms.Label
    $notice.Text = 'Save stages the change only. Apply snapshots the profile, closes Edge if required, writes the batch, re-reads each row, decrypts it, verifies the selected format, and rolls back on failure.'
    $notice.Location = New-Object System.Drawing.Point(15, 213); $notice.Size = New-Object System.Drawing.Size(430, 58); $notice.ForeColor = [System.Drawing.Color]::DimGray
    $propForm.Controls.Add($notice)
    if ($isEdit) {
        $profileInfo = $null
        foreach ($profile in $profiles) { if ([string]$profile.ProfilePath -eq [string]$SelectedObj.ProfilePath) { $profileInfo = $profile; break } }
        if ($null -eq $profileInfo) { $profileInfo = [pscustomobject]@{ DisplayName = [string]$SelectedObj.ProfileName; ProfilePath = [string]$SelectedObj.ProfilePath; DirectoryName = '' }; [void]$cmbProfile.Items.Add($profileInfo) }
        $cmbProfile.SelectedItem = $profileInfo; $cmbProfile.Enabled = $false
        $txtWebsite.Text = [string]$SelectedObj.Website; $txtWebsite.ReadOnly = $true
        $txtUsername.Text = [string]$SelectedObj.Username; $txtPassword.Text = [string]$SelectedObj.Password
        $formatIndex = $cmbProtection.Items.IndexOf([string]$SelectedObj.EncryptionVersion)
        $cmbProtection.SelectedIndex = if ($formatIndex -ge 0) { $formatIndex } else { 0 }
    } else {
        $cmbProfile.SelectedIndex = 0; $cmbProtection.SelectedIndex = 0
    }
    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = if ($isEdit) { 'Stage' } else { 'Stage Add' }; $btnOk.Location = New-Object System.Drawing.Point(285, 288); $btnOk.Size = New-Object System.Drawing.Size(75, 26)
    $propForm.Controls.Add($btnOk)
    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = 'Cancel'; $btnCancel.Location = New-Object System.Drawing.Point(370, 288); $btnCancel.Size = New-Object System.Drawing.Size(75, 26); $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $propForm.Controls.Add($btnCancel)
    $btnOk.Add_Click({
        $errors = New-Object System.Collections.Generic.List[string]
        if ($null -eq $cmbProfile.SelectedItem) { [void]$errors.Add('- Select an Edge profile.') }
        if ([string]::IsNullOrWhiteSpace($txtWebsite.Text)) { [void]$errors.Add('- Website / realm cannot be empty.') }
        if ([string]::IsNullOrWhiteSpace($txtUsername.Text)) { [void]$errors.Add('- User name cannot be empty.') }
        if ($cmbProtection.SelectedIndex -lt 0) { [void]$errors.Add('- Select v10, v11, or v20.') }
        if ($errors.Count -gt 0) {
            [System.Windows.Forms.MessageBox]::Show(($errors -join "`n"), 'Browser Credential Validation', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
            return
        }
        $newProtection = [string]$cmbProtection.SelectedItem
        $oldProtection = if ($isEdit) { [string]$SelectedObj.EncryptionVersion } else { '' }
        if ($isEdit -and $oldProtection -eq 'v20' -and $newProtection -in @('v10','v11')) {
            $downgrade = [System.Windows.Forms.MessageBox]::Show("Protection downgrade`n`nThis credential currently uses v20. Converting it to $newProtection may reduce protection but can improve compatibility with older software.`n`nThe original database will be retained for one-session recovery after Apply. Continue staging?", 'Edge Protection Downgrade', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($downgrade -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        }
        $profile = $cmbProfile.SelectedItem
        $propForm.Tag = [pscustomobject]@{
            LoginId = if ($isEdit) { [int64]$SelectedObj.LoginId } else { [int64]0 }
            ProfileName = [string]$profile.DisplayName; ProfilePath = [string]$profile.ProfilePath
            Website = [string]$txtWebsite.Text; Username = [string]$txtUsername.Text; Password = [string]$txtPassword.Text
            OriginalProtection = $oldProtection; Protection = $newProtection
        }
        $propForm.DialogResult = [System.Windows.Forms.DialogResult]::OK; $propForm.Close()
    })
    $propForm.AcceptButton = $btnOk; $propForm.CancelButton = $btnCancel
    $dialogResult = $propForm.ShowDialog($MainForm)
    $result = if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) { $propForm.Tag } else { $null }
    $txtPassword.Clear(); $chkReveal.Checked = $false
    return $result
}
function Add-KeyMgrBrowserPendingChange {
    param([Parameter(Mandatory=$true)][ValidateSet('Add','Edit','Remove')][string]$Operation, [Parameter(Mandatory=$true)]$Data)
    $loginId = if ($Data.PSObject.Properties['LoginId']) { [int64]$Data.LoginId } else { [int64]0 }
    $profilePath = [string]$Data.ProfilePath
    if ($Operation -ne 'Add') {
        for ($i = $Global:BrowserPendingChanges.Count - 1; $i -ge 0; $i--) {
            $existing = $Global:BrowserPendingChanges[$i]
            if ([string]$existing.ProfilePath -eq $profilePath -and [int64]$existing.LoginId -eq $loginId) {
                script:Clear-KeyMgrSecretObject $existing
                $Global:BrowserPendingChanges.RemoveAt($i)
            }
        }
    }
    $change = [pscustomobject]@{
        PendingId = [guid]::NewGuid().ToString('N'); Operation = $Operation; LoginId = $loginId
        ProfileName = [string]$Data.ProfileName; ProfilePath = $profilePath; Website = [string]$Data.Website
        Username = [string]$Data.Username; Password = if ($Data.PSObject.Properties['Password']) { [string]$Data.Password } else { $null }
        OriginalProtection = if ($Data.PSObject.Properties['OriginalProtection']) { [string]$Data.OriginalProtection } elseif ($Data.PSObject.Properties['EncryptionVersion']) { [string]$Data.EncryptionVersion } else { '' }
        Protection = if ($Data.PSObject.Properties['Protection']) { [string]$Data.Protection } elseif ($Data.PSObject.Properties['EncryptionVersion']) { [string]$Data.EncryptionVersion } else { '' }
        AppliedLoginId = [int64]0
    }
    [void]$Global:BrowserPendingChanges.Add($change)
    script:Update-EdgeTabList
}
function Clear-KeyMgrBrowserPendingChanges {
    script:Clear-KeyMgrSecretCollection -Collection $Global:BrowserPendingChanges
    $Global:BrowserPendingChanges.Clear()
    script:Update-EdgeTabList
}
function Close-KeyMgrEdgeForApply {
    $running = [EdgeDiagnosticsEngine]::IsEdgeRunning()
    if (-not $running) { return $true }
    try {
        [EdgeDiagnosticsEngine]::KillEdgeProcesses(); Start-Sleep -Milliseconds 750
        if ([EdgeDiagnosticsEngine]::IsEdgeRunning()) { throw 'Microsoft Edge is still running after the close request.' }
        return $true
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Unable to close Microsoft Edge before Apply.`n`n$($_.Exception.Message)", 'Browser Credentials Apply', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return $false
    }
}
function Apply-KeyMgrBrowserChanges {
    if ($Global:BrowserPendingChanges.Count -eq 0) { return $null }
    $started = Get-Date
    $running = [EdgeDiagnosticsEngine]::IsEdgeRunning()
    $summary = "$($Global:BrowserPendingChanges.Count) staged Edge change(s) will be applied as a verified batch."
    if ($running) { $summary += "`n`nMicrosoft Edge is running and will be closed now. Unsaved tabs or form data may be lost." }
    $summary += "`n`nA per-profile database snapshot will be retained for one-session recovery after a successful Apply. Continue?"
    if ([System.Windows.Forms.MessageBox]::Show($summary, 'Apply Browser Credential Changes', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning) -ne [System.Windows.Forms.DialogResult]::Yes) { return $null }
    if (-not (script:Close-KeyMgrEdgeForApply)) { return $null }
    $snapshots = New-Object System.Collections.Generic.List[System.Object]
    $rollbackSucceeded = $false
    try {
        $profilePaths = @($Global:BrowserPendingChanges | Select-Object -ExpandProperty ProfilePath -Unique)
        foreach ($profilePath in $profilePaths) { [void]$snapshots.Add((script:New-KeyMgrEdgeDatabaseSnapshot -ProfilePath ([string]$profilePath))) }
        foreach ($change in $Global:BrowserPendingChanges) {
            switch ([string]$change.Operation) {
                'Add' {
                    $newId = [EdgeDiagnosticsEngine]::AddCredential([string]$change.ProfilePath, [string]$change.Website, [string]$change.Username, [string]$change.Password, [string]$change.Protection)
                    $change.AppliedLoginId = $newId
                    if (-not [EdgeDiagnosticsEngine]::VerifyCredentialDetails($newId, [string]$change.ProfilePath, [string]$change.Website, [string]$change.Username, [string]$change.Password, [string]$change.Protection)) { throw "Add verification failed for '$($change.Website)'." }
                }
                'Edit' {
                    [EdgeDiagnosticsEngine]::UpdateCredential([int64]$change.LoginId, [string]$change.ProfilePath, [string]$change.Username, [string]$change.Password, [string]$change.Protection)
                    if (-not [EdgeDiagnosticsEngine]::VerifyCredentialDetails([int64]$change.LoginId, [string]$change.ProfilePath, [string]$change.Website, [string]$change.Username, [string]$change.Password, [string]$change.Protection)) { throw "Edit/conversion verification failed for '$($change.Website)'." }
                }
                'Remove' {
                    [EdgeDiagnosticsEngine]::DeleteCredential([int64]$change.LoginId, [string]$change.ProfilePath)
                    if ([EdgeDiagnosticsEngine]::CredentialExists([int64]$change.LoginId, [string]$change.ProfilePath)) { throw "Removal verification failed for '$($change.Website)'." }
                }
            }
        }
        if ($null -ne $Global:LastBrowserApplyRecovery) {
            foreach ($oldSnapshot in $Global:LastBrowserApplyRecovery.Snapshots) { script:Remove-KeyMgrEdgeDatabaseSnapshot -Snapshot $oldSnapshot }
        }
        $Global:LastBrowserApplyRecovery = [pscustomobject]@{
            AppliedAt = Get-Date; Snapshots = $snapshots; Count = $Global:BrowserPendingChanges.Count
            Summary = ($Global:BrowserPendingChanges | ForEach-Object { "$($_.Operation): $($_.Website) [$($_.OriginalProtection) -> $($_.Protection)]" }) -join [Environment]::NewLine
        }
        script:Clear-KeyMgrSecretCollection -Collection $Global:BrowserPendingChanges
        $Global:BrowserPendingChanges.Clear()
        script:Refresh-TabbedUI
        script:Update-BrowserPendingState
        [System.Windows.Forms.MessageBox]::Show('All staged Edge changes were written, re-read, decrypted, and verified successfully. The original profile database snapshot is available from Tools > Browser Credentials recovery.', 'Browser Credentials Apply', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return script:Complete-KeyMgrOperation -Operation 'Apply Browser Batch' -Provider 'Edge Chromium (staged)' -Success $true -Changed $true -RollbackAvailable $true -DiagnosticMessage 'The staged batch passed row, plaintext, metadata, and protection-format verification.' -StartedAt $started
    } catch {
        $failure = $_.Exception.Message
        try {
            foreach ($snapshot in $snapshots) { script:Restore-KeyMgrEdgeDatabaseSnapshot -Snapshot $snapshot }
            $rollbackSucceeded = $true
        } catch { $failure += " Rollback failed: $($_.Exception.Message)" }
        foreach ($snapshot in $snapshots) { script:Remove-KeyMgrEdgeDatabaseSnapshot -Snapshot $snapshot }
        script:Refresh-TabbedUI
        [System.Windows.Forms.MessageBox]::Show("Apply failed. Rollback $(if ($rollbackSucceeded) { 'succeeded' } else { 'did not complete' }).`n`n$failure", 'Browser Credentials Apply', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return script:Complete-KeyMgrOperation -Operation 'Apply Browser Batch' -Provider 'Edge Chromium (staged)' -Changed (-not $rollbackSucceeded) -DiagnosticMessage $failure -StartedAt $started
    }
}
function Undo-KeyMgrLastBrowserApply {
    $recovery = $Global:LastBrowserApplyRecovery
    if ($null -eq $recovery) {
        [System.Windows.Forms.MessageBox]::Show('No successful Browser Credentials Apply snapshot is available in this session.', 'Browser Credentials Recovery', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }
    if ($Global:BrowserPendingChanges.Count -gt 0) {
        [System.Windows.Forms.MessageBox]::Show('Revert or Apply the current pending Edge changes before restoring the previous batch snapshot.', 'Browser Credentials Recovery', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }
    $message = "Restore the profile database state captured before the last Browser Apply?`n`nApplied: $($recovery.AppliedAt)`nChanges: $($recovery.Count)`n`n$($recovery.Summary)"
    if ([System.Windows.Forms.MessageBox]::Show($message, 'Browser Credentials Recovery', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning) -ne [System.Windows.Forms.DialogResult]::Yes) { return }
    if (-not (script:Close-KeyMgrEdgeForApply)) { return }
    try {
        foreach ($snapshot in $recovery.Snapshots) { script:Restore-KeyMgrEdgeDatabaseSnapshot -Snapshot $snapshot }
        foreach ($snapshot in $recovery.Snapshots) { script:Remove-KeyMgrEdgeDatabaseSnapshot -Snapshot $snapshot }
        $Global:LastBrowserApplyRecovery = $null
        script:Refresh-TabbedUI
        [System.Windows.Forms.MessageBox]::Show('The database state from before the last Browser Apply was restored.', 'Browser Credentials Recovery', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Recovery failed.`n`n$($_.Exception.Message)", 'Browser Credentials Recovery', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
}

# Provider-aware Add/Edit/Remove controls.
$BtnAdd = New-Object System.Windows.Forms.Button; 
$BtnAdd.Text = "&Add..."; $BtnAdd.Location = New-Object System.Drawing.Point(430, 124); 
$BtnAdd.Size = New-Object System.Drawing.Size(100, 25); 
$BtnAdd.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$MainForm.Controls.Add($BtnAdd)
$BtnRemove = New-Object System.Windows.Forms.Button; 
$BtnRemove.Text = "&Remove"; 
$BtnRemove.Location = New-Object System.Drawing.Point(430, 154); 
$BtnRemove.Size = New-Object System.Drawing.Size(100, 25); 
$BtnRemove.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$BtnRemove.Enabled = $False; $MainForm.Controls.Add($BtnRemove)
$BtnEdit = New-Object System.Windows.Forms.Button; 
$BtnEdit.Text = "&Edit..."; 
$BtnEdit.Location = New-Object System.Drawing.Point(430, 184); 
$BtnEdit.Size = New-Object System.Drawing.Size(100, 25); 
$BtnEdit.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$BtnEdit.Enabled = $False; $MainForm.Controls.Add($BtnEdit)
$BtnApplyBrowser = New-Object System.Windows.Forms.Button
$BtnApplyBrowser.Text = '&Apply'
$BtnApplyBrowser.Location = New-Object System.Drawing.Point(430, 214)
$BtnApplyBrowser.Size = New-Object System.Drawing.Size(100, 25)
$BtnApplyBrowser.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$BtnApplyBrowser.Visible = $false; $BtnApplyBrowser.Enabled = $false; $MainForm.Controls.Add($BtnApplyBrowser)
$BtnRevertBrowser = New-Object System.Windows.Forms.Button
$BtnRevertBrowser.Text = 'Re&vert'
$BtnRevertBrowser.Location = New-Object System.Drawing.Point(430, 244)
$BtnRevertBrowser.Size = New-Object System.Drawing.Size(100, 25)
$BtnRevertBrowser.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$BtnRevertBrowser.Visible = $false; $BtnRevertBrowser.Enabled = $false; $MainForm.Controls.Add($BtnRevertBrowser)
# Keep credential transfer and password-reset media visibly distinct. The first button launches
# credwiz.exe (the screenshot's Stored User Names and Passwords flow); the second retains the
# removable-media password-reset-disk workflow that the previous build mislabeled as backup/restore.
$GroupPanel = New-Object System.Windows.Forms.GroupBox
$GroupPanel.Text = "Credential backup and account recovery"
$GroupPanel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$GroupPanel.Location = New-Object System.Drawing.Point(12, 469)
$GroupPanel.Size = New-Object System.Drawing.Size(400, 100)
$GroupPanel.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$MainForm.Controls.Add($GroupPanel)
$PanelSubLabel = New-Object System.Windows.Forms.Label
$PanelSubLabel.Text = "Credential wizard transfers remembered Windows logons (.crd), not browser passwords. Password reset disk uses removable media."
$PanelSubLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$PanelSubLabel.Location = New-Object System.Drawing.Point(10, 20)
$PanelSubLabel.Size = New-Object System.Drawing.Size(380, 40)
$PanelSubLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
$GroupPanel.Controls.Add($PanelSubLabel)
$BtnBackup = New-Object System.Windows.Forms.Button
$BtnBackup.Text = "&Credential wizard..."
$BtnBackup.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$BtnBackup.Location = New-Object System.Drawing.Point(10, 67)
$BtnBackup.Size = New-Object System.Drawing.Size(140, 25)
$GroupPanel.Controls.Add($BtnBackup)
$BtnRestore = New-Object System.Windows.Forms.Button
$BtnRestore.Text = "Password reset &disk..."
$BtnRestore.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$BtnRestore.Location = New-Object System.Drawing.Point(240, 67)
$BtnRestore.Size = New-Object System.Drawing.Size(150, 25)
$BtnRestore.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$GroupPanel.Controls.Add($BtnRestore)
$BackupRestoreToolTip = New-Object System.Windows.Forms.ToolTip
$BackupRestoreToolTip.SetToolTip($BtnBackup, 'Open Microsoft credwiz.exe to back up or restore remembered Windows logon credentials to or from a .crd file.')
$BackupRestoreToolTip.SetToolTip($BtnRestore, 'Create or use a removable-media password reset disk for the current local account.')
$BtnImportCrd = New-Object System.Windows.Forms.Button
$BtnImportCrd.Text = "&Import .crd"
$BtnImportCrd.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Regular)
$BtnImportCrd.Location = New-Object System.Drawing.Point(430, 234)
$BtnImportCrd.Size = New-Object System.Drawing.Size(100, 25)
$BtnImportCrd.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$BtnImportCrd.Visible = $false
$MainForm.Controls.Add($BtnImportCrd)
$BtnClose = New-Object System.Windows.Forms.Button
$BtnClose.Text = "Close"
$BtnClose.Location = New-Object System.Drawing.Point(430, 536)
$BtnClose.Size = New-Object System.Drawing.Size(100, 25)
$BtnClose.Anchor = [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Right
$MainForm.Controls.Add($BtnClose)
$MainForm.AcceptButton = $BtnClose
$Global:WebCollection = New-Object System.Collections.Generic.List[System.Object]
$Global:WinCoreColl   = New-Object System.Collections.Generic.List[System.Object]
$Global:WinCertColl   = New-Object System.Collections.Generic.List[System.Object]
$Global:WinGenColl    = New-Object System.Collections.Generic.List[System.Object]
# -------------------------------------------------------------
# 7. VAULT ENUMERATION, FILE-PROBE, AND LEGACY DIRECT-VAULT HELPERS
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
    # vaultcmd.exe is the only implemented source for the vault GUID list; no
    # VaultEnumerateVaults binding is present in this build.
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
    # Legacy compatibility helper; the active refresh path uses dedicated source functions.
    # It combines native Vault enumeration with a narrow CredMan name/description heuristic.
    $vaultItems = @()
    try {
        $allVaults = script:Get-AllVaultGuids
        script:Write-TraceLog "Found $($allVaults.Count) vaults"
        foreach ($schemaGuid in $allVaults) {
            try {
                script:Write-TraceLog "Opening vault with GUID: $schemaGuid"
                $vaultMgr = New-Object VaultManager($schemaGuid)
                try {
                    $items = $vaultMgr.EnumerateItems()
                    script:Write-TraceLog "Vault $schemaGuid contains $($items.Count) items"
                    foreach ($item in $items) {
                        script:Write-TraceLog "  - Resource: $($item.Resource), Identity: $($item.Identity), FriendlyName: $($item.FriendlyName)"
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
    # Compatibility heuristic for Snapshot/MicrosoftStore-like entries surfaced through CredMan.
    script:Write-TraceLog "Attempting alternative enumeration for web credentials..."
    try {
        $webFilters = @("MicrosoftAccount:*", "WindowsLive:*", "*")
        foreach ($filter in $webFilters) {
            try {
                script:Write-TraceLog "  Enumerating with filter: $filter"
                $creds = [Credential]::LoadAll()  # This uses CredEnumerate internally
                foreach ($cred in $creds) {
                    # Match only the legacy Snapshot/MicrosoftStore/web-description heuristic.
                    if ($cred.Target -match "Snapshot|MicrosoftStore" -or $cred.Description -like "*web*") {
                        script:Write-TraceLog "    Found potential web credential: $($cred.Target)"
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
    script:Write-TraceLog "Total vault credentials found: $($vaultItems.Count)"
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
    # Core item fields exposed by the legacy direct-vault dialog.
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
            # Select the identifier used by this legacy direct-vault path.
            if ($SelectedObj) {
                # Reuse the selected item's SchemaId, as required by the existing legacy path.
                $schemaGuid = $SelectedObj.SchemaId
            } else {
                # For a new item, select the first vault GUID reported by vaultcmd.exe.
                $availableVaults = script:Get-AllVaultGuids
                if ($availableVaults.Count -eq 0) {
                    [System.Windows.Forms.MessageBox]::Show("No vaults are available on this system. Cannot add credential.", "Vault Error")
                    return
                }
                $schemaGuid = $availableVaults[0]
            }
            $vaultMgr = New-Object VaultManager($schemaGuid)
            if ($SelectedObj) {
                # Non-transactional replacement: delete the old item, then create the new core fields.
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
    $dialogResult = $PropForm.ShowDialog($MainForm)
    $txtAuth.Clear()
    $chkShowSecret.Checked = $false
    return $dialogResult
}
# -------------------------------------------------------------
# 8. REFRESH PIPELINE AND SOURCE-TO-VIEW ROUTING
# -------------------------------------------------------------
function Refresh-TabbedUI {
    script:Write-KeyMgrRuntimeLog 'REFRESH' 'Refresh-TabbedUI started.'
    script:Clear-KeyMgrSecretCollection -Collection $Global:WebCollection
    script:Clear-KeyMgrSecretCollection -Collection $Global:WinCoreColl
    script:Clear-KeyMgrSecretCollection -Collection $Global:WinCertColl
    script:Clear-KeyMgrSecretCollection -Collection $Global:WinGenColl
    script:Clear-KeyMgrSecretCollection -Collection $Global:EdgeCollection
    $ListViewWeb.Items.Clear(); $Global:WebCollection.Clear()
    $LV_WinCore.Items.Clear();  $Global:WinCoreColl.Clear()
    $LV_WinCert.Items.Clear();  $Global:WinCertColl.Clear()
    $LV_WinGen.Items.Clear();   $Global:WinGenColl.Clear()
    foreach ($browserList in @($LV_EdgeTab, $LV_LegacyEdgeTab, $LV_IE11Tab, $LV_IE79Tab)) {
        if ($null -ne $browserList -and -not $browserList.IsDisposed) { $browserList.Items.Clear() }
    }
    $Global:EdgeCollection = @()
    $passwordVaultCreds = @(script:Get-PasswordVaultCredentials)
    $webCreds = @(script:Get-WebCredentials -PasswordVaultCredentials $passwordVaultCreds)
    foreach ($w in $webCreds) {
        $Global:WebCollection.Add($w)
        $webTarget = if ($null -ne $w.Target) { [string]$w.Target } else { '' }
        $webUser = if ($null -ne $w.Username) { [string]$w.Username } else { '' }
        $lvItem = New-Object System.Windows.Forms.ListViewItem($webTarget)
        [void]$lvItem.SubItems.Add($webUser)
        $lvItem.Tag = $w
        [void]$ListViewWeb.Items.Add($lvItem)
    }
    try {
        # LoadAll performs the CredMan multi-filter enumeration and overlap deduplication.
        foreach ($r in [Credential]::LoadAll()) {
            switch ( [int]$r.Type ) {
                1 { $Global:WinGenColl.Add($r) }
                3 { $Global:WinCertColl.Add($r) }
                5 { $Global:WinCertColl.Add($r) }
                default { $Global:WinCoreColl.Add($r) }
            }
        }
    } catch {
        Write-Host "Error loading Windows credentials: $_"
    }
    script:Update-WindowsCredentialLists
    try {
        script:Write-KeyMgrRuntimeLog 'EDGE' 'Starting Edge profile and SQLite diagnostics.'
        $Global:EdgeCollection = @([EdgeDiagnosticsEngine]::LoadDiagnostics() | ForEach-Object { $_ })
        script:Write-KeyMgrRuntimeLog 'EDGE' ("Edge diagnostics completed with {0} operational row(s)." -f $Global:EdgeCollection.Count)
    } catch {
        $Global:EdgeCollection = @([pscustomobject]@{
            LoginId = 0
            ProfileName = '[Edge enumeration error]'
            ProfileDirectory = ''
            ProfilePath = ''
            Website = '-'
            ActionUrl = ''
            Username = '-'
            Password = $null
            SecretLoaded = $false
            LastUsed = '-'
            EncryptionVersion = 'ERROR'
        })
    }
    script:Update-KeyMgrBrowserProjections
    script:Update-EdgeTabList
    # Rebuild every diagnostic source view from a fresh provider-specific dataset.
    $Global:DiagnosticListViews['WinCreds'].Items.Clear()
    $Global:DiagnosticListViews['PasswordVault'].Items.Clear()
    $Global:DiagnosticListViews['EdgeOverview'].Items.Clear()
    $Global:DiagnosticListViews['EdgeTrace'].Items.Clear()
    $Global:DiagnosticListViews['EdgeSchema'].Items.Clear()
    $Global:DiagnosticListViews['EdgeErrors'].Items.Clear()
    $Global:DiagnosticListViews['VaultApi'].Items.Clear()
    $Global:DiagnosticListViews['VaultDecrypt'].Items.Clear()
    $Global:DiagnosticListViews['Vaultcmd'].Items.Clear()
    $Global:DiagnosticListViews['ErrorLog'].Items.Clear()
    # --- Section 1: Windows Credential Manager (cmdkey.exe / DPAPI) ---
    try {
        $cmdkeyCreds = script:Get-CmdkeyCredentials
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
        script:Add-DiagnosticErrorLogEntry -Source "cmdkey.exe" -Message $_
    }
    # --- Section 2: PasswordVault API (WinRT / System.Windows.Security) ---
    try {
        if ($passwordVaultCreds.Count -gt 0) {
            # PasswordVault diagnostics use only the WinRT endpoint dataset.
            $byResource = $passwordVaultCreds | Group-Object -Property Target
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
        script:Add-DiagnosticErrorLogEntry -Source "PasswordVault API" -Message $_
    }
    # --- Section 3: Browser / Edge SQLite observability ---
    try {
        script:Update-EdgeDiagnosticsViews
        foreach ($edgeError in [EdgeDiagnosticsEngine]::GetDiagnosticErrors()) {
            script:Add-DiagnosticErrorLogEntry -Source 'Edge / SQLite' -Message ("{0} [{1}] {2}" -f $edgeError.ProfileName, $edgeError.Stage, $edgeError.Message)
        }
    } catch {
        script:Add-ListViewRow $LV_EdgeErrors @('[Edge diagnostics render error]', '', '', 'UI render', -1, 'ERROR', $_.Exception.Message, 'RENDER', '') ([System.Drawing.Color]::Red)
        script:Add-DiagnosticErrorLogEntry -Source 'Edge / SQLite' -Message $_
    }
    # Capture the CLI projection once so the native and rendered records can be compared in the same refresh.
    $vaultcmdCreds = @()
    try {
        $vaultcmdCreds = @(script:Get-VaultcmdCredentials)
    } catch {
        script:Add-DiagnosticErrorLogEntry -Source 'vaultcmd.exe correlation' -Message $_
    }
    # --- Section 4A: Vault API logical enumeration and metadata correlation ---
    try {
        script:Write-KeyMgrRuntimeLog 'VAULT-API' 'Starting vaultcli.dll enumeration and vaultcmd metadata correlation.'
        $allVaults = @(script:Get-AllVaultGuids)
        foreach ($vaultGuid in $allVaults) {
            $vaultMgr = $null
            try {
                $vaultMgr = New-Object VaultManager($vaultGuid)
                $items = $vaultMgr.EnumerateItems()
                $summary = $vaultMgr.GetLastEnumerationSummary()
                if ($items.Count -gt 0) {
                    foreach ($item in $items) {
                        $mapping = script:Find-VaultcmdNativeMatch -VaultGuid $vaultGuid -NativeItem $item -VaultcmdCredentials $vaultcmdCreds
                        $cli = $mapping.Credential
                        $cliPackageSid = if ($null -ne $cli) { [string]$cli.PackageSid } else { '' }
                        $cliSavedBy = if ($null -ne $cli) { [string]$cli.SavedBy } else { '' }
                        $cliHidden = if ($null -ne $cli) { [string]$cli.Hidden } else { '' }
                        $cliRoaming = if ($null -ne $cli) { [string]$cli.Roaming } else { '' }
                        $mappingEvidence = script:Get-VaultMetadataMappingEvidence -NativeItem $item -VaultcmdCredential $cli
                        $getItemHr = ('0x{0:X8}' -f $item.GetItemHResult)
                        $rowColor = if ($null -ne $cli) { [System.Drawing.Color]::DarkGreen } else { [System.Drawing.Color]::DarkOrange }
                        script:Add-ListViewRow $LV_VaultApi @(
                            'Vault API', $vaultGuid, $item.SchemaId, $item.FriendlyName, $item.Resource, $item.Identity,
                            $item.PackageSid, $item.FlagsHex, $item.FlagBits, $item.PropertiesCount, ("$($item.PropertyLayout): $($item.PropertySummary)"),
                            $cliPackageSid, $cliSavedBy, $cliHidden, $cliRoaming, $mapping.Match, $mappingEvidence,
                            $item.MetadataSource, $getItemHr, $summary
                        ) $rowColor $item
                    }
                } else {
                    script:Add-ListViewRow $LV_VaultApi @('Vault API', $vaultGuid, '', '', '[No items returned]', '', '', '', '', 0, '', '', '', '', '', 'No match', '', '', '', $summary) ([System.Drawing.Color]::Blue)
                }
            } catch {
                script:Add-ListViewRow $LV_VaultApi @('Vault API', $vaultGuid, '', '', '[Vault API error]', '', '', '', '', 0, '', '', '', '', '', 'Error', '', '', '', $_.Exception.Message) ([System.Drawing.Color]::Red)
                script:Add-DiagnosticErrorLogEntry -Source 'Vault API' -Message ("Vault {0}: {1}" -f $vaultGuid, $_.Exception.Message)
            } finally {
                if ($null -ne $vaultMgr) { $vaultMgr.Dispose() }
            }
        }
        if ($LV_VaultApi.Items.Count -eq 0) {
            script:Add-ListViewRow $LV_VaultApi @('Vault API', '[No logical vaults found]', '', '', '', '', '', '', '', 0, '', '', '', '', '', 'No match', '', '', '', 'vaultcmd.exe did not report any vault GUIDs.') ([System.Drawing.Color]::Gray)
        }
    } catch {
        script:Add-ListViewRow $LV_VaultApi @('Vault API', '[Enumeration error]', '', '', '', '', '', '', '', 0, '', '', '', '', '', 'Error', '', '', '', $_.Exception.Message) ([System.Drawing.Color]::Red)
        script:Add-DiagnosticErrorLogEntry -Source 'Vault API' -Message $_
    }
    # --- Section 4B: physical Vault inventory and heuristic decryption results (independent dataset) ---
    try {
        $fileProbes = [VaultEncryptionEngine]::ProbeVaultFiles()
        foreach ($probe in $fileProbes) {
            $color = switch -Regex ($probe.Status) {
                'DECRYPTED' { [System.Drawing.Color]::DarkGreen; break }
                'EMPTY|MISSING|POLICY-ONLY|POLICY-SCHEMA-ONLY|NO-POLICY' { [System.Drawing.Color]::Blue; break }
                'FAIL|ERROR|DENIED' { [System.Drawing.Color]::Red; break }
                default { [System.Drawing.Color]::Black }
            }
            script:Add-ListViewRow $LV_VaultDecryption @(
                $probe.RootName, $probe.RootPath, $probe.VaultGuid, $probe.VaultPath,
                $probe.PolicyFileCount, $probe.SchemaFileCount, $probe.CredentialFileCount,
                $probe.DecryptedCredentialCount, $probe.Status, $probe.Detail
            ) $color $probe
            if ($probe.Status -match 'FAIL|ERROR|DENIED') {
                script:Add-DiagnosticErrorLogEntry -Source 'Vault Files' -Message ("{0} | {1} | {2}" -f $probe.VaultPath, $probe.Status, $probe.Detail)
            }
        }
        if ($LV_VaultDecryption.Items.Count -eq 0) {
            script:Add-ListViewRow $LV_VaultDecryption @('[No filesystem probe results]') ([System.Drawing.Color]::Gray)
        }
    } catch {
        script:Add-ListViewRow $LV_VaultDecryption @('[Vault filesystem enumeration error]', '', '', '', 0, 0, 0, 0, 'ERROR', $_.Exception.Message) ([System.Drawing.Color]::Red)
        script:Add-DiagnosticErrorLogEntry -Source 'Vault Files' -Message $_
    }
    # --- Section 5: vaultcmd.exe metadata and CLI operation reference ---
    try {
        if ($vaultcmdCreds.Count -gt 0) {
            # Preserve one row per vaultcmd credential record so provider metadata remains visible.
            foreach ($cred in $vaultcmdCreds) {
                $lvItem = New-Object System.Windows.Forms.ListViewItem("vaultcmd.exe")
                $lvItem.ForeColor = [System.Drawing.Color]::DarkMagenta
                [void]$lvItem.SubItems.Add([string]$cred.VaultName)
                [void]$lvItem.SubItems.Add([string]$cred.VaultGuid)
                [void]$lvItem.SubItems.Add([string]$cred.VaultLocation)
                [void]$lvItem.SubItems.Add([string]$cred.VaultProtection)
                [void]$lvItem.SubItems.Add([string]$cred.VaultReportedCount)
                [void]$lvItem.SubItems.Add([string]$cred.Schema)
                [void]$lvItem.SubItems.Add([string]$cred.Target)
                [void]$lvItem.SubItems.Add([string]$cred.Username)
                [void]$lvItem.SubItems.Add([string]$cred.PackageSid)
                [void]$lvItem.SubItems.Add([string]$cred.SavedBy)
                [void]$lvItem.SubItems.Add([string]$cred.Hidden)
                [void]$lvItem.SubItems.Add([string]$cred.Roaming)
                [void]$lvItem.SubItems.Add("CLI-CRUD")
                $lvItem.Tag = $cred
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
        script:Add-DiagnosticErrorLogEntry -Source "vaultcmd.exe" -Message $_
    }
    # ===================================================================
    script:Update-ButtonStates
    script:Write-KeyMgrRuntimeLog 'REFRESH' 'Refresh-TabbedUI completed.'
}
$Global:LastFocusedGrid = $ListViewWeb
# Explicit script: qualification keeps WinForms delegates anchored to this script scope in Windows PowerShell 5.1.
$ListViewWeb.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { script:Update-ButtonStates } })
$LV_WinCore.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_WinCore.SelectedIndices.Count -gt 0) { script:Clear-OtherSelections $LV_WinCore } else { script:Update-ButtonStates } } })
$LV_WinCert.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_WinCert.SelectedIndices.Count -gt 0) { script:Clear-OtherSelections $LV_WinCert } else { script:Update-ButtonStates } } })
$LV_WinGen.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_WinGen.SelectedIndices.Count -gt 0) { script:Clear-OtherSelections $LV_WinGen } else { script:Update-ButtonStates } } })
$TxtWinFilter.Add_TextChanged({ script:Invoke-UiEventSafely { script:Update-WindowsCredentialLists; script:Update-ButtonStates } })
$WinCategoryTabs.Add_SelectedIndexChanged({
    script:Invoke-UiEventSafely {
        switch ($WinCategoryTabs.SelectedIndex) {
            1 { $Global:LastFocusedGrid = $LV_WinCert }
            2 { $Global:LastFocusedGrid = $LV_WinGen }
            default { $Global:LastFocusedGrid = $LV_WinCore }
        }
        script:Update-ButtonStates
    }
})
$LV_EdgeTab.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_EdgeTab.SelectedIndices.Count -gt 0) { script:Clear-BrowserSelections $LV_EdgeTab } else { script:Update-ButtonStates } } })
$LV_LegacyEdgeTab.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_LegacyEdgeTab.SelectedIndices.Count -gt 0) { script:Clear-BrowserSelections $LV_LegacyEdgeTab } else { script:Update-ButtonStates } } })
$LV_IE11Tab.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_IE11Tab.SelectedIndices.Count -gt 0) { script:Clear-BrowserSelections $LV_IE11Tab } else { script:Update-ButtonStates } } })
$LV_IE79Tab.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_IE79Tab.SelectedIndices.Count -gt 0) { script:Clear-BrowserSelections $LV_IE79Tab } else { script:Update-ButtonStates } } })
$BrowserCategoryTabs.Add_SelectedIndexChanged({
    script:Invoke-UiEventSafely {
        $Global:LastFocusedGrid = script:Get-KeyMgrActiveBrowserListView
        script:Update-ButtonStates
    }
})
$LV_WinCreds.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_WinCreds.SelectedIndices.Count -gt 0) { script:Clear-DiagnosticSelections $LV_WinCreds } else { script:Update-ButtonStates } } })
$LV_PasswordVault.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_PasswordVault.SelectedIndices.Count -gt 0) { script:Clear-DiagnosticSelections $LV_PasswordVault } else { script:Update-ButtonStates } } })
$LV_EdgeOverview.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_EdgeOverview.SelectedIndices.Count -gt 0) { script:Clear-DiagnosticSelections $LV_EdgeOverview } else { script:Update-ButtonStates } } })
$LV_EdgeTrace.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_EdgeTrace.SelectedIndices.Count -gt 0) { script:Clear-DiagnosticSelections $LV_EdgeTrace } else { script:Update-ButtonStates } } })
$LV_EdgeSchema.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_EdgeSchema.SelectedIndices.Count -gt 0) { script:Clear-DiagnosticSelections $LV_EdgeSchema } else { script:Update-ButtonStates } } })
$LV_EdgeErrors.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_EdgeErrors.SelectedIndices.Count -gt 0) { script:Clear-DiagnosticSelections $LV_EdgeErrors } else { script:Update-ButtonStates } } })
$LV_VaultApi.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_VaultApi.SelectedIndices.Count -gt 0) { script:Clear-DiagnosticSelections $LV_VaultApi } else { script:Update-ButtonStates } } })
$LV_VaultDecryption.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_VaultDecryption.SelectedIndices.Count -gt 0) { script:Clear-DiagnosticSelections $LV_VaultDecryption } else { script:Update-ButtonStates } } })
$LV_Vaultcmd.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_Vaultcmd.SelectedIndices.Count -gt 0) { script:Clear-DiagnosticSelections $LV_Vaultcmd } else { script:Update-ButtonStates } } })
$LV_ErrorLog.Add_SelectedIndexChanged({ script:Invoke-UiEventSafely { if ($LV_ErrorLog.SelectedIndices.Count -gt 0) { script:Clear-DiagnosticSelections $LV_ErrorLog } else { script:Update-ButtonStates } } })
$TxtEdgeTabFilter.Add_TextChanged({ script:Invoke-UiEventSafely { script:Update-EdgeTabList } })
$DiagSourceTabs.Add_SelectedIndexChanged({
    script:Invoke-UiEventSafely {
        if ($DiagSourceTabs.SelectedIndex -ge 0 -and $DiagSourceTabs.SelectedIndex -lt $Global:DiagnosticPageListViews.Count) {
            $Global:LastFocusedGrid = $Global:DiagnosticPageListViews[$DiagSourceTabs.SelectedIndex]
        }
        script:Update-ButtonStates
    }
})
$TabControl.Add_SelectedIndexChanged({ 
    script:Invoke-UiEventSafely {
        if ($TabControl.SelectedIndex -eq 0) { $Global:LastFocusedGrid = $ListViewWeb }
        if ($TabControl.SelectedIndex -eq 1) {
            switch ($WinCategoryTabs.SelectedIndex) {
                1 { $Global:LastFocusedGrid = $LV_WinCert }
                2 { $Global:LastFocusedGrid = $LV_WinGen }
                default { $Global:LastFocusedGrid = $LV_WinCore }
            }
        }
        if ($TabControl.SelectedIndex -eq 2) { $Global:LastFocusedGrid = script:Get-KeyMgrActiveBrowserListView }
        if ($TabControl.SelectedIndex -eq 3 -and $DiagSourceTabs.SelectedIndex -ge 0) {
            $Global:LastFocusedGrid = $Global:DiagnosticPageListViews[$DiagSourceTabs.SelectedIndex]
        }
        script:Update-ButtonStates
    }
})
# -------------------------------------------------------------
# 9. CREDMAN/PASSWORDVAULT PROPERTY DIALOG AND TYPE-SPECIFIC INPUTS
# -------------------------------------------------------------
function Show-PropertyDialog ($SelectedObj, $TargetType) {
    $PropForm = New-Object System.Windows.Forms.Form
    $PropForm.StartPosition = "CenterParent"
    $PropForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $PropForm.MaximizeBox = $False
    $PropForm.MinimizeBox = $False
    $PropForm.ShowIcon = $False
    $PropForm.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Font
    $PropForm.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $PropForm.Text = if ($SelectedObj) { "Stored Credential Properties" } else { "Add Stored Credential" }
    $isEdit = $null -ne $SelectedObj
    $isWebContext = $TargetType -eq "Web"
    $showCertificateOption = -not $isWebContext
    $clientHeight = if ($showCertificateOption) { 473 } else { 407 }
    $PropForm.ClientSize = New-Object System.Drawing.Size(360, $clientHeight)
    $lblInstruction = New-Object System.Windows.Forms.Label
    $lblInstruction.Location = New-Object System.Drawing.Point(16, 16)
    $lblInstruction.Size = New-Object System.Drawing.Size(328, 42)
    $lblInstruction.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $lblInstruction.Text = if ($isEdit) {
        "You can change the user name and password for the logon location shown below."
    } else {
        "Type the name of a server or Web site, and the user name and password you use to access it."
    }
    $PropForm.Controls.Add($lblInstruction)
    $fieldLabelX = 16
    $fieldControlX = 108
    $fieldControlWidth = 236
    $fieldTop = 67
    $fieldSpacing = 31
    $lblT = New-Object System.Windows.Forms.Label
    $lblT.Text = "Log on to:"
    $lblT.Location = New-Object System.Drawing.Point($fieldLabelX, $($fieldTop + 3))
    $lblT.AutoSize = $True
    $PropForm.Controls.Add($lblT)
    $txtT = New-Object System.Windows.Forms.TextBox
    $txtT.Location = New-Object System.Drawing.Point($fieldControlX, $fieldTop)
    $txtT.Size = New-Object System.Drawing.Size($fieldControlWidth, 23)
    $PropForm.Controls.Add($txtT)
    $lblU = New-Object System.Windows.Forms.Label
    $lblU.Text = "User name:"
    $lblU.Location = New-Object System.Drawing.Point($fieldLabelX, $($fieldTop + $fieldSpacing + 3))
    $lblU.AutoSize = $True
    $PropForm.Controls.Add($lblU)
    $txtU = New-Object System.Windows.Forms.TextBox
    $txtU.Location = New-Object System.Drawing.Point($fieldControlX, $($fieldTop + $fieldSpacing))
    $txtU.Size = New-Object System.Drawing.Size($fieldControlWidth, 23)
    $PropForm.Controls.Add($txtU)
    $lblP = New-Object System.Windows.Forms.Label
    $lblP.Text = "Password:"
    $lblP.Location = New-Object System.Drawing.Point($fieldLabelX, $($fieldTop + (2 * $fieldSpacing) + 3))
    $lblP.AutoSize = $True
    $PropForm.Controls.Add($lblP)
    $txtP = New-Object System.Windows.Forms.TextBox
    $txtP.Location = New-Object System.Drawing.Point($fieldControlX, $($fieldTop + (2 * $fieldSpacing)))
    $txtP.Size = New-Object System.Drawing.Size($fieldControlWidth, 23)
    $txtP.UseSystemPasswordChar = $True
    $PropForm.Controls.Add($txtP)
    $btnBrowseCertificate = New-Object System.Windows.Forms.Button
    $btnBrowseCertificate.Text = "Browse..."
    $btnBrowseCertificate.Location = New-Object System.Drawing.Point(269, $($fieldTop + (2 * $fieldSpacing) - 1))
    $btnBrowseCertificate.Size = New-Object System.Drawing.Size(75, 25)
    $btnBrowseCertificate.Visible = $False
    $PropForm.Controls.Add($btnBrowseCertificate)
    $chkShowPassword = New-Object System.Windows.Forms.CheckBox
    $chkShowPassword.Text = "Show password"
    $chkShowPassword.Location = New-Object System.Drawing.Point($fieldControlX, 160)
    $chkShowPassword.AutoSize = $True
    $PropForm.Controls.Add($chkShowPassword)
    $credentialGroupHeight = if ($showCertificateOption) { 226 } else { 160 }
    $grpCredentialType = New-Object System.Windows.Forms.GroupBox
    $grpCredentialType.Text = "Credential type"
    $grpCredentialType.Location = New-Object System.Drawing.Point(16, 187)
    $grpCredentialType.Size = New-Object System.Drawing.Size(328, $credentialGroupHeight)
    $PropForm.Controls.Add($grpCredentialType)
    $rdoWindows = New-Object System.Windows.Forms.RadioButton
    $rdoWindows.Text = "A Windows logon credential"
    $rdoWindows.Location = New-Object System.Drawing.Point(16, 22)
    $rdoWindows.Size = New-Object System.Drawing.Size(292, 22)
    $grpCredentialType.Controls.Add($rdoWindows)
    $lblWindowsDescription = New-Object System.Windows.Forms.Label
    $lblWindowsDescription.Text = "Choose this option to save a user name and password for a Windows server or other Windows computer."
    $lblWindowsDescription.Location = New-Object System.Drawing.Point(38, 45)
    $lblWindowsDescription.Size = New-Object System.Drawing.Size(270, 38)
    $lblWindowsDescription.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $grpCredentialType.Controls.Add($lblWindowsDescription)
    $rdoProgram = New-Object System.Windows.Forms.RadioButton
    $rdoProgram.Text = "A Web site or program credential"
    $rdoProgram.Location = New-Object System.Drawing.Point(16, 86)
    $rdoProgram.Size = New-Object System.Drawing.Size(292, 22)
    $grpCredentialType.Controls.Add($rdoProgram)
    $lblProgramDescription = New-Object System.Windows.Forms.Label
    $lblProgramDescription.Text = "Choose this option to save a user name and password for a Web site or program."
    $lblProgramDescription.Location = New-Object System.Drawing.Point(38, 109)
    $lblProgramDescription.Size = New-Object System.Drawing.Size(270, 38)
    $lblProgramDescription.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $grpCredentialType.Controls.Add($lblProgramDescription)
    $rdoCertificate = New-Object System.Windows.Forms.RadioButton
    $rdoCertificate.Text = "A certificate-based credential"
    $rdoCertificate.Location = New-Object System.Drawing.Point(16, 150)
    $rdoCertificate.Size = New-Object System.Drawing.Size(292, 22)
    $rdoCertificate.Visible = $showCertificateOption
    $grpCredentialType.Controls.Add($rdoCertificate)
    $lblCertificateDescription = New-Object System.Windows.Forms.Label
    $lblCertificateDescription.Text = "Choose this option to use a certificate from Current User > Personal. Select a certificate or enter its SHA-1 thumbprint."
    $lblCertificateDescription.Location = New-Object System.Drawing.Point(38, 173)
    $lblCertificateDescription.Size = New-Object System.Drawing.Size(270, 43)
    $lblCertificateDescription.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $lblCertificateDescription.Visible = $showCertificateOption
    $grpCredentialType.Controls.Add($lblCertificateDescription)
    # The hidden ComboBox is the state model behind the three radio-button choices:
    # 0 = Windows/domain, 1 = certificate, 2 = generic/program.
    $cmbType = $null
    if (-not $isEdit -and -not $isWebContext) {
        $cmbType = New-Object System.Windows.Forms.ComboBox
        [void]$cmbType.Items.Add("Windows Credential")
        [void]$cmbType.Items.Add("Certificate-Based Credential")
        [void]$cmbType.Items.Add("Generic Credential")
        $cmbType.SelectedIndex = switch ($TargetType) { "Windows_Cert" { 1 } "Windows_Gen" { 2 } default { 0 } }
    }
    $credentialTypeCanChange = $null -ne $cmbType
    $rdoWindows.Enabled = $credentialTypeCanChange
    $rdoProgram.Enabled = $credentialTypeCanChange
    $rdoCertificate.Enabled = $credentialTypeCanChange
    $lblWindowsDescription.Enabled = $credentialTypeCanChange
    $lblProgramDescription.Enabled = $credentialTypeCanChange
    $lblCertificateDescription.Enabled = $credentialTypeCanChange
    $UpdateFieldLabels = {
        $isCertificateCredentialUi = $False
        if ($isWebContext) {
            $rdoWindows.Checked = $False
            $rdoProgram.Checked = $True
            $rdoCertificate.Checked = $False
        } elseif ($cmbType) {
            switch ($cmbType.SelectedIndex) {
                1 {
                    $rdoWindows.Checked = $False
                    $rdoProgram.Checked = $False
                    $rdoCertificate.Checked = $True
                    $isCertificateCredentialUi = $True
                }
                2 {
                    $rdoWindows.Checked = $False
                    $rdoProgram.Checked = $True
                    $rdoCertificate.Checked = $False
                }
                default {
                    $rdoWindows.Checked = $True
                    $rdoProgram.Checked = $False
                    $rdoCertificate.Checked = $False
                }
            }
        } elseif ($SelectedObj -and ([int]$SelectedObj.Type -eq 3 -or [int]$SelectedObj.Type -eq 5)) {
            $rdoWindows.Checked = $False
            $rdoProgram.Checked = $False
            $rdoCertificate.Checked = $True
            $isCertificateCredentialUi = $True
        } elseif ($SelectedObj -and [int]$SelectedObj.Type -eq 1) {
            $rdoWindows.Checked = $False
            $rdoProgram.Checked = $True
            $rdoCertificate.Checked = $False
        } else {
            $rdoWindows.Checked = $True
            $rdoProgram.Checked = $False
            $rdoCertificate.Checked = $False
        }
        if ($isCertificateCredentialUi) {
            $lblInstruction.Text = if ($isEdit) {
                "You can change the user name and certificate for the logon location shown below."
            } else {
                "Type the logon location and user name, and select the certificate you use to access it."
            }
            $lblP.Text = "Thumbprint:"
            $txtP.Width = 155
            $txtP.UseSystemPasswordChar = $False
            $chkShowPassword.Checked = $False
            $chkShowPassword.Visible = $False
            $btnBrowseCertificate.Visible = $True
        } else {
            $lblInstruction.Text = if ($isEdit) {
                "You can change the user name and password for the logon location shown below."
            } else {
                "Type the name of a server or Web site, and the user name and password you use to access it."
            }
            $lblP.Text = "Password:"
            $txtP.Width = $fieldControlWidth
            $txtP.UseSystemPasswordChar = $True
            $chkShowPassword.Text = "Show password"
            $chkShowPassword.Visible = $True
            $chkShowPassword.Checked = $False
            $btnBrowseCertificate.Visible = $False
        }
    }
    if ($cmbType) {
        $rdoWindows.Add_CheckedChanged({
            if ($rdoWindows.Checked) {
                $cmbType.SelectedIndex = 0
                &$UpdateFieldLabels
            }
        })
        $rdoProgram.Add_CheckedChanged({
            if ($rdoProgram.Checked) {
                $cmbType.SelectedIndex = 2
                &$UpdateFieldLabels
            }
        })
        $rdoCertificate.Add_CheckedChanged({
            if ($rdoCertificate.Checked) {
                $cmbType.SelectedIndex = 1
                &$UpdateFieldLabels
            }
        })
    }
    $btnBrowseCertificate.Add_Click({
        $selectedThumbprint = script:Show-CertificatePickerDialog -Owner $PropForm
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
        $txtT.Text = $SelectedObj.Target
        $txtT.ReadOnly = $True
        $txtU.Text = $SelectedObj.Username
        if ([string]::IsNullOrEmpty($SelectedObj.Password)) {
            $txtP.Text = "************"
        } else {
            $txtP.Text = $SelectedObj.Password
        }
    }
    &$UpdateFieldLabels
    $buttonTop = if ($showCertificateOption) { 431 } else { 365 }
    $btnOK = New-Object System.Windows.Forms.Button
    $btnOK.Text = "OK"
    $btnOK.Location = New-Object System.Drawing.Point(186, $buttonTop)
    $btnOK.Size = New-Object System.Drawing.Size(75, 25)
    $PropForm.Controls.Add($btnOK)
    $btnCan = New-Object System.Windows.Forms.Button
    $btnCan.Text = "Cancel"
    $btnCan.Location = New-Object System.Drawing.Point(269, $buttonTop)
    $btnCan.Size = New-Object System.Drawing.Size(75, 25)
    $btnCan.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $PropForm.Controls.Add($btnCan)
    $PropForm.AcceptButton = $btnOK
    $PropForm.CancelButton = $btnCan
    $btnOK.Add_Click({
        $errors = New-Object System.Collections.Generic.List[string]
        $isCertificateCredential = if ($TargetType -ne "Web" -and $cmbType) { $cmbType.SelectedIndex -eq 1 } elseif ($SelectedObj) { ([int]$SelectedObj.Type -eq 3 -or [int]$SelectedObj.Type -eq 5) } else { $false }
        $normalizedThumbprint = $null
        $selectedCertificate = $null
        if ([string]::IsNullOrWhiteSpace($txtT.Text)) { [void]$errors.Add("- 'Log on to' cannot be left blank.") }
        if ([string]::IsNullOrWhiteSpace($txtU.Text)) { [void]$errors.Add("- 'User name' cannot be left blank.") }
        if ($isCertificateCredential) {
            $normalizedThumbprint = script:Normalize-CertificateThumbprint $txtP.Text
            if ([string]::IsNullOrWhiteSpace($normalizedThumbprint)) {
                [void]$errors.Add("- Certificate-Based Credentials require a certificate from Current User > Personal or a SHA-1 thumbprint.")
            } elseif ($normalizedThumbprint.Length -ne 40) {
                [void]$errors.Add("- Certificate thumbprints must contain exactly 40 hexadecimal characters.")
            } elseif ([string]::IsNullOrWhiteSpace($txtU.Text)) {
                [void]$errors.Add("- Certificate-Based Credentials require the user name field to identify the associated account.")
            } else {
                $selectedCertificate = script:Find-CertificateCredential $normalizedThumbprint
                if ($null -eq $selectedCertificate) {
                    [void]$errors.Add("- The certificate thumbprint was not found in Current User > Personal.")
                } else {
                    $certificateUsability = script:Test-CertificateCredentialUsability $normalizedThumbprint
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
        $credentialType = if ($TargetType -eq 'Web') {
            0
        } elseif ($SelectedObj) {
            [int]$SelectedObj.Type
        } else {
            switch ($cmbType.SelectedIndex) { 1 { 3 } 2 { 1 } default { 2 } }
        }
        $secretWasChanged = -not ($SelectedObj -and $txtP.Text -eq '************' -and -not $isCertificateCredential)
        $PropForm.Tag = [pscustomobject]@{
            TargetType = [string]$TargetType
            Target = [string]$txtT.Text
            Username = [string]$txtU.Text
            Secret = if ($secretWasChanged) { [string]$txtP.Text } else { $null }
            SecretHash = ''
            SecretWasChanged = [bool]$secretWasChanged
            CredentialType = [int]$credentialType
            Persist = if ($SelectedObj -and $SelectedObj.PSObject.Properties['PersistenceType']) { [int]$SelectedObj.PersistenceType } else { 2 }
            IsCertificateCredential = [bool]$isCertificateCredential
            CertificateThumbprint = if ($isCertificateCredential) { [string]$normalizedThumbprint } else { $null }
        }
        $PropForm.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $PropForm.Close()
    })
    $btnCan.Add_Click({ $PropForm.Close() })
    $dialogResult = $PropForm.ShowDialog($MainForm)
    $result = if ($dialogResult -eq [System.Windows.Forms.DialogResult]::OK) { $PropForm.Tag } else { $null }
    $txtP.Clear()
    $chkShowPassword.Checked = $false
    return $result
}
# -------------------------------------------------------------
# 10. CAPABILITY-GATED OPERATION DISPATCH
# -------------------------------------------------------------
function Invoke-KeyMgrAddOperation {
    $started = Get-Date
    $context = script:Get-KeyMgrOperationContext -Operation 'Add'
    if (-not (script:Test-KeyMgrProviderCapability -Capability 'CanCreate' -Context $context)) {
        return script:Show-KeyMgrUnsupportedOperation -Operation 'Add' -Context $context
    }
    $providerId = $context.ProviderId
    $providerName = $context.ProviderName
    $data = $null
    try {
        if ($TabControl.SelectedIndex -eq 2 -and $BrowserCategoryTabs.SelectedIndex -eq 0) {
            $providerId = 'Edge'
            $providerName = (script:Get-KeyMgrProviderCapabilities -ProviderId $providerId).DisplayName
            $data = script:Show-EdgePropertyDialog -SelectedObj $null
            if ($null -eq $data) { return script:Complete-KeyMgrOperation -Operation 'Add' -Provider $providerName -Cancelled $true -DiagnosticMessage 'The Edge add dialog was closed without staging.' -StartedAt $started }
            script:Add-KeyMgrBrowserPendingChange -Operation 'Add' -Data $data
            return script:Complete-KeyMgrOperation -Operation 'Add' -Provider $providerName -Target ([string]$data.Website) -Success $true -Changed $false -DiagnosticMessage 'The Edge add was staged. No browser process or database was changed.' -StartedAt $started
        } elseif ($TabControl.SelectedIndex -eq 0 -or ($TabControl.SelectedIndex -eq 2 -and $BrowserCategoryTabs.SelectedIndex -in @(1,2))) {
            $providerChoice = [System.Windows.Forms.MessageBox]::Show("Create the new entry in the Windows Web Credentials vault through vaultcmd.exe?`n`nYes: vaultcmd Web Credentials`nNo: WinRT PasswordVault`nCancel: do nothing", 'Choose Web Credential Provider', [System.Windows.Forms.MessageBoxButtons]::YesNoCancel, [System.Windows.Forms.MessageBoxIcon]::Question)
            if ($providerChoice -eq [System.Windows.Forms.DialogResult]::Cancel) {
                return script:Complete-KeyMgrOperation -Operation 'Add' -Provider $context.ProviderName -Cancelled $true -DiagnosticMessage 'The user cancelled provider selection.' -StartedAt $started
            }
            if ($providerChoice -eq [System.Windows.Forms.DialogResult]::Yes) {
                $providerId = 'VaultCmd'
                $providerName = (script:Get-KeyMgrProviderCapabilities -ProviderId $providerId).DisplayName
                $data = script:Show-VaultcmdWebCredentialDialog $null
            } else {
                $providerId = 'PasswordVault'
                $providerName = (script:Get-KeyMgrProviderCapabilities -ProviderId $providerId).DisplayName
                $data = script:Show-PropertyDialog $null 'Web'
            }
        } else {
            $activeType = 'Windows_Core'
            $providerId = 'CredManCore'
            if ($Global:LastFocusedGrid -eq $LV_WinCert) { $activeType = 'Windows_Cert'; $providerId = 'CredManCertificate' }
            elseif ($Global:LastFocusedGrid -eq $LV_WinGen) { $activeType = 'Windows_Gen'; $providerId = 'CredManGeneric' }
            $providerName = (script:Get-KeyMgrProviderCapabilities -ProviderId $providerId).DisplayName
            $data = script:Show-PropertyDialog $null $activeType
        }
        if ($null -eq $data) {
            return script:Complete-KeyMgrOperation -Operation 'Add' -Provider $providerName -Cancelled $true -DiagnosticMessage 'The credential dialog was closed without saving.' -StartedAt $started
        }
        $tx = script:Invoke-KeyMgrProviderMutation -ProviderId $providerId -Operation 'Add' -MutationData $data
        if ($tx.Success) {
            script:Refresh-TabbedUI
            return script:Complete-KeyMgrOperation -Operation 'Add' -Provider $providerName -Target $tx.Target -Success $true -Changed $true -DiagnosticMessage $tx.DiagnosticMessage -Transaction $tx -StartedAt $started
        }
        [System.Windows.Forms.MessageBox]::Show("The credential could not be created or verified.`n`n$($tx.DiagnosticMessage)`n`nRollback: $(if ($tx.RollbackAttempted) { if ($tx.RollbackSucceeded) { 'succeeded' } else { 'failed - ' + $tx.RollbackDiagnostic } } else { 'not required or unavailable' })", 'Add Credential', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        script:Refresh-TabbedUI
        return script:Complete-KeyMgrOperation -Operation 'Add' -Provider $providerName -Target $tx.Target -Changed $tx.Changed -ErrorCode $tx.ErrorCode -DiagnosticMessage $tx.DiagnosticMessage -Transaction $tx -StartedAt $started
    } catch {
        $message = $_.Exception.Message
        [System.Windows.Forms.MessageBox]::Show("Failed to add the credential.`n`n$message", 'Add Credential', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return script:Complete-KeyMgrOperation -Operation 'Add' -Provider $providerName -Target $context.Target -DiagnosticMessage $message -StartedAt $started
    } finally {
        script:Clear-KeyMgrSecretObject $data
    }
}
function Invoke-KeyMgrEditOperation {
    $started = Get-Date
    $context = script:Get-KeyMgrActiveProviderContext
    if (-not $context.HasSelection) { return $null }
    if (-not (script:Test-KeyMgrProviderCapability -Capability 'CanEdit' -Context $context)) {
        return script:Show-KeyMgrUnsupportedOperation -Operation 'Edit' -Context $context
    }
    $data = $null
    $dialogObject = $null
    try {
        if ($context.ProviderId -eq 'VaultCmd') {
            $data = script:Show-VaultcmdWebCredentialDialog $context.SelectedItem
        } elseif ($context.ProviderId -eq 'PasswordVault') {
            $dialogObject = script:Get-KeyMgrPasswordVaultSnapshot -Target ([string]$context.SelectedItem.Target) -Username ([string]$context.SelectedItem.Username)
            if ($null -eq $dialogObject) { throw 'The selected PasswordVault credential could not be reopened for editing.' }
            $dialogObject | Add-Member -NotePropertyName Type -NotePropertyValue 'Web' -Force
            $data = script:Show-PropertyDialog $dialogObject 'Web'
        } elseif ($context.ProviderId -match '^CredMan') {
            $dialogObject = New-Object Credential
            $dialogObject.Target = [string]$context.SelectedItem.Target
            $dialogObject.Type = [CredentialType]$context.SelectedItem.Type
            if (-not $dialogObject.Load()) { throw 'The selected CredMan credential could not be reopened for editing.' }
            $targetType = switch ($context.ProviderId) { 'CredManCertificate' { 'Windows_Cert' } 'CredManGeneric' { 'Windows_Gen' } default { 'Windows_Core' } }
            $data = script:Show-PropertyDialog $dialogObject $targetType
        } elseif ($context.ProviderId -eq 'Edge') {
            if ([int64]$context.SelectedItem.LoginId -le 0) { throw 'Select a saved Edge credential, not a pending add row.' }
            $dialogObject = [EdgeDiagnosticsEngine]::CaptureCredentialSnapshot([int64]$context.SelectedItem.LoginId, [string]$context.SelectedItem.ProfilePath)
            if ($null -eq $dialogObject) { throw 'The selected Edge row no longer exists.' }
            $dialogRow = [pscustomobject]@{
                LoginId = $context.SelectedItem.LoginId; ProfileName = $context.SelectedItem.ProfileName
                ProfilePath = $context.SelectedItem.ProfilePath; Website = $dialogObject.Website
                Username = $dialogObject.Username; Password = $dialogObject.Password; EncryptionVersion = $dialogObject.EncryptionVersion
            }
            $data = script:Show-EdgePropertyDialog -SelectedObj $dialogRow
            if ($null -ne $data) {
                script:Add-KeyMgrBrowserPendingChange -Operation 'Edit' -Data $data
                script:Clear-KeyMgrSecretObject $dialogRow
                return script:Complete-KeyMgrOperation -Operation 'Edit' -Provider $context.ProviderName -Target $context.Target -Success $true -Changed $false -DiagnosticMessage 'The Edge edit/conversion was staged. No browser process or database was changed.' -StartedAt $started
            }
            script:Clear-KeyMgrSecretObject $dialogRow
        }
        if ($null -eq $data) {
            return script:Complete-KeyMgrOperation -Operation 'Edit' -Provider $context.ProviderName -Target $context.Target -Cancelled $true -DiagnosticMessage 'The credential dialog was closed without saving.' -StartedAt $started
        }
        $tx = script:Invoke-KeyMgrProviderMutation -ProviderId $context.ProviderId -Operation 'Edit' -SelectedItem $context.SelectedItem -MutationData $data
        if ($tx.Success) {
            script:Refresh-TabbedUI
            [System.Windows.Forms.MessageBox]::Show('The selected credential was updated and verified successfully.', 'Credential Update', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            return script:Complete-KeyMgrOperation -Operation 'Edit' -Provider $context.ProviderName -Target $context.Target -Success $true -Changed $true -DiagnosticMessage $tx.DiagnosticMessage -Transaction $tx -StartedAt $started
        }
        [System.Windows.Forms.MessageBox]::Show("The selected credential could not be updated or verified.`n`n$($tx.DiagnosticMessage)`n`nRollback: $(if ($tx.RollbackAttempted) { if ($tx.RollbackSucceeded) { 'succeeded' } else { 'failed - ' + $tx.RollbackDiagnostic } } else { 'not required or unavailable' })", 'Edit Credential', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        script:Refresh-TabbedUI
        return script:Complete-KeyMgrOperation -Operation 'Edit' -Provider $context.ProviderName -Target $context.Target -Changed $tx.Changed -ErrorCode $tx.ErrorCode -DiagnosticMessage $tx.DiagnosticMessage -Transaction $tx -StartedAt $started
    } catch {
        $message = $_.Exception.Message
        [System.Windows.Forms.MessageBox]::Show("Failed to update the selected credential.`n`n$message", 'Edit Credential', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return script:Complete-KeyMgrOperation -Operation 'Edit' -Provider $context.ProviderName -Target $context.Target -DiagnosticMessage $message -StartedAt $started
    } finally {
        script:Clear-KeyMgrSecretObject $data
        script:Clear-KeyMgrSecretObject $dialogObject
    }
}
function Invoke-KeyMgrRemoveOperation {
    $started = Get-Date
    $context = script:Get-KeyMgrActiveProviderContext
    if (-not $context.HasSelection) { return $null }
    if (-not (script:Test-KeyMgrProviderCapability -Capability 'CanDelete' -Context $context)) {
        return script:Show-KeyMgrUnsupportedOperation -Operation 'Remove' -Context $context
    }
    try {
        if ($context.ProviderId -eq 'Edge') {
            if ([int64]$context.SelectedItem.LoginId -le 0) { throw 'Select a saved Edge credential, not a pending add row.' }
            $confirmText = "Stage removal of the Edge credential for '$($context.SelectedItem.Website)' in profile '$($context.SelectedItem.ProfileName)'?`n`nNothing is deleted until Apply."
        } else {
            $confirmText = "Remove the selected $($context.ProviderName) credential matching '$($context.Target)'?`n`nKeyMgr will re-read the provider after deletion and roll back when that provider supports restoration."
        }
        $confirm = [System.Windows.Forms.MessageBox]::Show($confirmText, 'Confirm Removal', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) {
            return script:Complete-KeyMgrOperation -Operation 'Remove' -Provider $context.ProviderName -Target $context.Target -Cancelled $true -DiagnosticMessage 'The user cancelled credential removal.' -StartedAt $started
        }
        if ($context.ProviderId -eq 'Edge') {
            script:Add-KeyMgrBrowserPendingChange -Operation 'Remove' -Data $context.SelectedItem
            return script:Complete-KeyMgrOperation -Operation 'Remove' -Provider $context.ProviderName -Target $context.Target -Success $true -Changed $false -DiagnosticMessage 'The Edge removal was staged. No browser process or database was changed.' -StartedAt $started
        }
        $tx = script:Invoke-KeyMgrProviderMutation -ProviderId $context.ProviderId -Operation 'Remove' -SelectedItem $context.SelectedItem
        if ($tx.Success) {
            script:Refresh-TabbedUI
            return script:Complete-KeyMgrOperation -Operation 'Remove' -Provider $context.ProviderName -Target $context.Target -Success $true -Changed $true -DiagnosticMessage $tx.DiagnosticMessage -Transaction $tx -StartedAt $started
        }
        [System.Windows.Forms.MessageBox]::Show("The selected credential could not be removed or verified.`n`n$($tx.DiagnosticMessage)`n`nRollback: $(if ($tx.RollbackAttempted) { if ($tx.RollbackSucceeded) { 'succeeded' } else { 'failed - ' + $tx.RollbackDiagnostic } } else { 'not required or unavailable' })", 'Remove Credential', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        script:Refresh-TabbedUI
        return script:Complete-KeyMgrOperation -Operation 'Remove' -Provider $context.ProviderName -Target $context.Target -Changed $tx.Changed -ErrorCode $tx.ErrorCode -DiagnosticMessage $tx.DiagnosticMessage -Transaction $tx -StartedAt $started
    } catch {
        $message = $_.Exception.Message
        [System.Windows.Forms.MessageBox]::Show("Failed to remove the selected credential.`n`n$message", 'Remove Credential', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
        return script:Complete-KeyMgrOperation -Operation 'Remove' -Provider $context.ProviderName -Target $context.Target -DiagnosticMessage $message -StartedAt $started
    }
}
$BtnAdd.Add_Click({ script:Invoke-UiEventSafely { [void](script:Invoke-KeyMgrAddOperation) } })
$BtnEdit.Add_Click({ script:Invoke-UiEventSafely { [void](script:Invoke-KeyMgrEditOperation) } })
$BtnRemove.Add_Click({ script:Invoke-UiEventSafely { [void](script:Invoke-KeyMgrRemoveOperation) } })
$BtnApplyBrowser.Add_Click({ script:Invoke-UiEventSafely { [void](script:Apply-KeyMgrBrowserChanges) } })
$BtnRevertBrowser.Add_Click({ script:Invoke-UiEventSafely { script:Clear-KeyMgrBrowserPendingChanges } })
# ===================================================================
# 11. COPY-TO-CLIPBOARD SUPPORT FOR MAIN AND DIAGNOSTIC LIST VIEWS
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
function Show-KeyMgrSecretOnDemand {
    param([Parameter(Mandatory=$true)]$SelectedItem, [Parameter(Mandatory=$true)][string]$ProviderId)
    $secretHolder = $null
    $secret = $null
    $secretStatus = $null
    $target = if ($SelectedItem.PSObject.Properties['Target']) { [string]$SelectedItem.Target } elseif ($SelectedItem.PSObject.Properties['Website']) { [string]$SelectedItem.Website } else { '' }
    $typeDisplay = if ($SelectedItem.PSObject.Properties['Type']) { [string]$SelectedItem.Type } else { 'Not reported' }
    try {
        switch -Regex ($ProviderId) {
            '^Edge$' {
                $secretHolder = [EdgeDiagnosticsEngine]::CaptureCredentialSnapshot([int64]$SelectedItem.LoginId, [string]$SelectedItem.ProfilePath)
                if ($null -ne $secretHolder -and -not [string]::IsNullOrEmpty([string]$secretHolder.Password)) {
                    $secret = [string]$secretHolder.Password
                } else {
                    $secretStatus = 'Edge returned no decrypted password for this row. The row may be empty, unsupported by the available decryption context, or no longer present.'
                }
            }
            '^PasswordVault$' {
                try {
                    $secretHolder = script:Get-KeyMgrPasswordVaultSnapshot -Target ([string]$SelectedItem.Target) -Username ([string]$SelectedItem.Username)
                    if ($null -ne $secretHolder -and -not [string]::IsNullOrEmpty([string]$secretHolder.Password)) {
                        $secret = [string]$secretHolder.Password
                    } else {
                        $secretStatus = 'PasswordVault returned no non-empty password. Retrieve/PasswordCredential.RetrievePassword may be unavailable for this resource, or the stored password is empty.'
                    }
                } catch {
                    $secretStatus = "PasswordVault could not retrieve this password: $($_.Exception.Message)"
                }
            }
            '^CredMan' {
                $credType = [CredentialType]$SelectedItem.Type
                $typeDisplay = script:Get-CredentialTypeDisplayName -Type ([int]$credType)
                $secretHolder = [SecurityEngineMatrix]::ReadCredentialSecret([string]$SelectedItem.Target, $credType)
                if ($null -ne $secretHolder -and $secretHolder.Success -and -not [string]::IsNullOrEmpty([string]$secretHolder.Secret)) {
                    $secret = [string]$secretHolder.Secret
                    $secretStatus = "$($secretHolder.Message) Source: $($secretHolder.Source)"
                } elseif ($null -ne $secretHolder) {
                    $secretStatus = "$($secretHolder.Message) Status: $($secretHolder.Status). Source: $($secretHolder.Source). Blob size: $($secretHolder.BlobSize) bytes."
                } else {
                    $secretStatus = 'CredMan returned no reveal result for the selected credential.'
                }
            }
            '^VaultCmd$' {
                $secretStatus = 'vaultcmd.exe exposes metadata and supports add/delete operations, but it does not expose a public plaintext authenticator read operation for this item.'
            }
            '^VaultApi$' {
                $secretStatus = 'The Windows Vault API projection did not expose a readable authenticator for this item. KeyMgr will not infer a password from provider-owned Vault elements.'
            }
            default {
                $secretStatus = "Provider '$ProviderId' has no supported on-demand plaintext reveal path."
            }
        }
        if ([string]::IsNullOrEmpty([string]$secret)) {
            if ([string]::IsNullOrWhiteSpace($secretStatus)) { $secretStatus = 'The provider did not return a readable non-empty secret for the selected item.' }
            $providerName = (script:Get-KeyMgrProviderCapabilities -ProviderId $ProviderId).DisplayName
            $statusMessage = "$secretStatus`n`nProvider: $providerName`nCredential type: $typeDisplay`nTarget: $target"
            script:Write-TraceLog "Reveal unavailable. Provider=$ProviderId; Type=$typeDisplay; Target=$target; Status=$secretStatus"
            [System.Windows.Forms.MessageBox]::Show($statusMessage, 'Reveal Secret - unavailable', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            return
        }
        $form = New-Object System.Windows.Forms.Form
        $form.Text = 'Reveal Secret (on demand)'
        $form.StartPosition = 'CenterParent'
        $form.FormBorderStyle = 'FixedDialog'
        $form.MaximizeBox = $false
        $form.MinimizeBox = $false
        $form.ClientSize = New-Object System.Drawing.Size(430, 135)
        $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
        $label = New-Object System.Windows.Forms.Label
        $label.Text = 'The secret is held only for this dialog. Clipboard contents remain until overwritten.'
        $label.Location = New-Object System.Drawing.Point(15, 12)
        $label.Size = New-Object System.Drawing.Size(400, 34)
        $form.Controls.Add($label)
        $box = New-Object System.Windows.Forms.TextBox
        $box.Location = New-Object System.Drawing.Point(15, 48)
        $box.Size = New-Object System.Drawing.Size(400, 23)
        $box.ReadOnly = $true
        $box.UseSystemPasswordChar = $true
        $box.Text = $secret
        $form.Controls.Add($box)
        $show = New-Object System.Windows.Forms.CheckBox
        $show.Text = 'Show'
        $show.Location = New-Object System.Drawing.Point(15, 79)
        $show.AutoSize = $true
        $show.Tag = $box
        $show.Add_CheckedChanged({
            $secretBox = $this.Tag
            if ($null -ne $secretBox -and -not $secretBox.IsDisposed) { $secretBox.UseSystemPasswordChar = -not $this.Checked }
        })
        $form.Controls.Add($show)
        $copy = New-Object System.Windows.Forms.Button
        $copy.Text = 'Copy'
        $copy.Location = New-Object System.Drawing.Point(255, 94)
        $copy.Size = New-Object System.Drawing.Size(75, 25)
        $copy.Tag = $box
        $copy.Add_Click({
            try {
                $secretBox = $this.Tag
                $copyText = if ($null -ne $secretBox -and -not $secretBox.IsDisposed) { [string]$secretBox.Text } else { $null }
                if ([string]::IsNullOrEmpty($copyText)) {
                    [System.Windows.Forms.MessageBox]::Show('No non-empty text value is available to copy.', 'Reveal Secret - nothing to copy', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
                    return
                }
                [System.Windows.Forms.Clipboard]::SetText($copyText)
            } catch {
                [System.Windows.Forms.MessageBox]::Show("The secret could not be copied to the clipboard.`n`n$($_.Exception.Message)", 'Reveal Secret - copy failed', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
            }
        })
        $form.Controls.Add($copy)
        $close = New-Object System.Windows.Forms.Button
        $close.Text = 'Close'
        $close.Location = New-Object System.Drawing.Point(340, 94)
        $close.Size = New-Object System.Drawing.Size(75, 25)
        $close.Add_Click({ $dialog = $this.FindForm(); if ($null -ne $dialog) { $dialog.Close() } })
        $form.Controls.Add($close)
        $form.CancelButton = $close
        [void]$form.ShowDialog($MainForm)
        $box.Clear()
        $show.Checked = $false
    } finally {
        $secret = $null
        script:Clear-KeyMgrSecretObject $secretHolder
    }
}
function Add-ListViewContextMenu {
    param(
        [System.Windows.Forms.ListView]$ListView,
        [string]$ListViewName
    )
    # Create context menu
    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    if ($ListViewName -in @('EdgeDiagnostics','WebCredentials','WindowsCore','WindowsGeneric')) {
        $revealSecretMenu = New-Object System.Windows.Forms.ToolStripMenuItem
        $revealSecretMenu.Text = 'Reveal / copy secret...'
        $revealSecretMenu.Add_Click({
            try {
                $lv = $this.Owner.SourceControl
                if ($null -eq $lv -or $lv.SelectedIndices.Count -eq 0) { return }
                $selected = $lv.Items[$lv.SelectedIndices[0]].Tag
                if ($null -eq $selected) { return }
                $providerId = if ($selected.PSObject.Properties['Provider']) { [string]$selected.Provider } elseif ($selected.PSObject.Properties['LoginId']) { 'Edge' } elseif ([int]$selected.Type -eq 1) { 'CredManGeneric' } else { 'CredManCore' }
                $secretItem = if ($selected.PSObject.Properties['SourceItem'] -and $null -ne $selected.SourceItem) { $selected.SourceItem } else { $selected }
                script:Show-KeyMgrSecretOnDemand -SelectedItem $secretItem -ProviderId $providerId
            } catch {
                [System.Windows.Forms.MessageBox]::Show("Unable to retrieve the selected secret.`n`n$($_.Exception.Message)", 'Reveal Secret', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            }
        })
        [void]$contextMenu.Items.Add($revealSecretMenu)
        [void]$contextMenu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
    }
    if ($ListViewName -eq 'EdgeDiagnostics') {
        foreach ($edgeCopySpec in @(
            @{ Text = 'Copy Website'; SubItemIndex = 2 },
            @{ Text = 'Copy Username'; SubItemIndex = 3 }
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
# Attach context menus and keyboard shortcuts to every diagnostic list view.
script:Add-ListViewContextMenu -ListView $Global:DiagnosticListViews['WinCreds'] -ListViewName "WinCreds"
script:Add-ListViewContextMenu -ListView $Global:DiagnosticListViews['PasswordVault'] -ListViewName "PasswordVault"
foreach ($edgeListKey in @('EdgeOverview','EdgeTrace','EdgeSchema','EdgeErrors','VaultApi')) {
    script:Add-ListViewContextMenu -ListView $Global:DiagnosticListViews[$edgeListKey] -ListViewName $edgeListKey
}
script:Add-ListViewContextMenu -ListView $Global:DiagnosticListViews['VaultDecrypt'] -ListViewName "VaultDecrypt"
script:Add-ListViewContextMenu -ListView $Global:DiagnosticListViews['Vaultcmd'] -ListViewName "Vaultcmd"
script:Add-ListViewContextMenu -ListView $Global:DiagnosticListViews['ErrorLog'] -ListViewName "ErrorLog"
script:Add-ListViewKeyboardShortcuts -ListView $Global:DiagnosticListViews['WinCreds']
script:Add-ListViewKeyboardShortcuts -ListView $Global:DiagnosticListViews['PasswordVault']
foreach ($edgeListKey in @('EdgeOverview','EdgeTrace','EdgeSchema','EdgeErrors','VaultApi')) {
    script:Add-ListViewKeyboardShortcuts -ListView $Global:DiagnosticListViews[$edgeListKey]
}
script:Add-ListViewKeyboardShortcuts -ListView $Global:DiagnosticListViews['VaultDecrypt']
script:Add-ListViewKeyboardShortcuts -ListView $Global:DiagnosticListViews['ErrorLog']
script:Add-ListViewKeyboardShortcuts -ListView $Global:DiagnosticListViews['Vaultcmd']
# Apply the same copy behavior to the main provider views.
script:Add-ListViewContextMenu -ListView $ListViewWeb -ListViewName "WebCredentials"
script:Add-ListViewContextMenu -ListView $LV_EdgeTab -ListViewName "EdgeCredentials"
script:Add-ListViewContextMenu -ListView $LV_LegacyEdgeTab -ListViewName "LegacyEdgeCredentials"
script:Add-ListViewContextMenu -ListView $LV_IE11Tab -ListViewName "IE11Credentials"
script:Add-ListViewContextMenu -ListView $LV_IE79Tab -ListViewName "IE79Storage2"
script:Add-ListViewContextMenu -ListView $LV_WinCore -ListViewName "WindowsCore"
script:Add-ListViewContextMenu -ListView $LV_WinCert -ListViewName "WindowsCertificate"
script:Add-ListViewContextMenu -ListView $LV_WinGen -ListViewName "WindowsGeneric"
script:Add-ListViewKeyboardShortcuts -ListView $ListViewWeb
script:Add-ListViewKeyboardShortcuts -ListView $LV_EdgeTab
script:Add-ListViewKeyboardShortcuts -ListView $LV_LegacyEdgeTab
script:Add-ListViewKeyboardShortcuts -ListView $LV_IE11Tab
script:Add-ListViewKeyboardShortcuts -ListView $LV_IE79Tab
script:Add-ListViewKeyboardShortcuts -ListView $LV_WinCore
script:Add-ListViewKeyboardShortcuts -ListView $LV_WinCert
script:Add-ListViewKeyboardShortcuts -ListView $LV_WinGen
# ===================================================================
# 12. MENU BAR, VIEW UTILITIES, EXPORT, AND TARGETED COMMAND CONSOLE
# ===================================================================
function Get-KeyMgrActiveListView {
    if ($null -eq $TabControl -or $TabControl.IsDisposed) { return $null }
    switch ($TabControl.SelectedIndex) {
        0 { return $ListViewWeb }
        1 {
            switch ($WinCategoryTabs.SelectedIndex) {
                1 { return $LV_WinCert }
                2 { return $LV_WinGen }
                default { return $LV_WinCore }
            }
        }
        2 { return script:Get-KeyMgrActiveBrowserListView }
        3 {
            switch ($DiagSourceTabs.SelectedIndex) {
                0 { return $LV_WinCreds }
                1 { return $LV_PasswordVault }
                2 {
                    if ($null -ne $DiagEdgeView -and $null -ne $DiagEdgeView.Tabs) {
                        switch ($DiagEdgeView.Tabs.SelectedIndex) {
                            1 { return $LV_EdgeTrace }
                            2 { return $LV_EdgeSchema }
                            3 { return $LV_EdgeErrors }
                            default { return $LV_EdgeOverview }
                        }
                    }
                    return $LV_EdgeOverview
                }
                3 { return $LV_VaultApi }
                4 { return $LV_VaultDecryption }
                5 { return $LV_Vaultcmd }
                6 { return $LV_ErrorLog }
                default { return $null }
            }
        }
        default { return $null }
    }
}
function Copy-KeyMgrActiveRow {
    $activeList = script:Get-KeyMgrActiveListView
    if ($null -eq $activeList -or $activeList.IsDisposed) {
        [System.Windows.Forms.MessageBox]::Show('The current page does not expose a list that can be copied.', 'Copy', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }
    script:Copy-ListViewItemToClipboard -ListView $activeList -AllColumns $true
}
function Resize-KeyMgrActiveColumns {
    $activeList = script:Get-KeyMgrActiveListView
    if ($null -eq $activeList -or $activeList.IsDisposed -or $activeList.Columns.Count -eq 0) { return }
    $activeList.BeginUpdate()
    try {
        for ($columnIndex = 0; $columnIndex -lt $activeList.Columns.Count; $columnIndex++) {
            $activeList.Columns[$columnIndex].AutoResize([System.Windows.Forms.ColumnHeaderAutoResizeStyle]::ColumnContent)
            $contentWidth = $activeList.Columns[$columnIndex].Width
            $activeList.Columns[$columnIndex].AutoResize([System.Windows.Forms.ColumnHeaderAutoResizeStyle]::HeaderSize)
            if ($contentWidth -gt $activeList.Columns[$columnIndex].Width) {
                $activeList.Columns[$columnIndex].Width = $contentWidth
            }
            if ($activeList.Columns[$columnIndex].Width -gt 700) {
                $activeList.Columns[$columnIndex].Width = 700
            }
        }
    } finally {
        $activeList.EndUpdate()
    }
}
function Focus-KeyMgrFilter {
    if ($TabControl.SelectedIndex -eq 1) {
        $TxtWinFilter.Focus()
        $TxtWinFilter.SelectAll()
        return
    }
    if ($TabControl.SelectedIndex -eq 2) {
        $TxtEdgeTabFilter.Focus()
        $TxtEdgeTabFilter.SelectAll()
        return
    }
    [System.Windows.Forms.MessageBox]::Show('The current page does not have a text filter. Windows Credentials and Browser Credentials support Ctrl+F filtering.', 'Find / Filter', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
}
function Clear-KeyMgrFilters {
    $TxtWinFilter.Clear()
    $TxtEdgeTabFilter.Clear()
}
function Export-KeyMgrActiveView {
    $activeList = script:Get-KeyMgrActiveListView
    if ($null -eq $activeList -or $activeList.IsDisposed -or $activeList.Items.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('The current view does not contain rows to export.', 'Export Current View', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
        return
    }
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Title = 'Export Current KeyMgr View'
    $saveDialog.Filter = 'CSV files (*.csv)|*.csv|Tab-separated text (*.tsv)|*.tsv|All files (*.*)|*.*'
    $saveDialog.DefaultExt = 'csv'
    $saveDialog.AddExtension = $true
    $saveDialog.FileName = 'KeyMgr-{0:yyyyMMdd-HHmmss}.csv' -f (Get-Date)
    if ($saveDialog.ShowDialog($MainForm) -ne [System.Windows.Forms.DialogResult]::OK) { return }
    try {
        $headers = New-Object System.Collections.Generic.List[string]
        $usedHeaders = @{}
        for ($columnIndex = 0; $columnIndex -lt $activeList.Columns.Count; $columnIndex++) {
            $baseName = [string]$activeList.Columns[$columnIndex].Text
            if ([string]::IsNullOrWhiteSpace($baseName)) { $baseName = 'Column{0}' -f ($columnIndex + 1) }
            $headerName = $baseName
            $suffix = 2
            while ($usedHeaders.ContainsKey($headerName)) {
                $headerName = '{0}_{1}' -f $baseName, $suffix
                $suffix++
            }
            $usedHeaders[$headerName] = $true
            [void]$headers.Add($headerName)
        }
        $rows = foreach ($item in $activeList.Items) {
            $record = [ordered]@{}
            for ($columnIndex = 0; $columnIndex -lt $headers.Count; $columnIndex++) {
                $record[$headers[$columnIndex]] = if ($item.SubItems.Count -gt $columnIndex) { [string]$item.SubItems[$columnIndex].Text } else { '' }
            }
            [pscustomobject]$record
        }
        if ([System.IO.Path]::GetExtension($saveDialog.FileName) -ieq '.tsv') {
            $lines = New-Object System.Collections.Generic.List[string]
            [void]$lines.Add(($headers -join "`t"))
            foreach ($row in $rows) {
                $fields = foreach ($header in $headers) { ('' + $row.$header) -replace "`t", ' ' -replace '[\r\n]+', ' ' }
                [void]$lines.Add(($fields -join "`t"))
            }
            [System.IO.File]::WriteAllLines($saveDialog.FileName, $lines, (New-Object System.Text.UTF8Encoding($true)))
        } else {
            $csvLines = @($rows | ConvertTo-Csv -NoTypeInformation)
            [System.IO.File]::WriteAllLines($saveDialog.FileName, $csvLines, (New-Object System.Text.UTF8Encoding($true)))
        }
        [System.Windows.Forms.MessageBox]::Show("Exported $($activeList.Items.Count) row(s) to:`n$($saveDialog.FileName)", 'Export Complete', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
    } catch {
        [System.Windows.Forms.MessageBox]::Show("The current view could not be exported.`n`n$_", 'Export Failed', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    }
}
function Get-KeyMgrCommandTemplates {
    param([string]$Target)
    switch ($Target) {
        'PowerShell (current KeyMgr runspace)' {
            [pscustomobject]@{ Name = 'Process summary (read-only)'; Command = 'Get-Process | Sort-Object ProcessName | Select-Object -First 25 ProcessName, Id, CPU, WorkingSet' }
            [pscustomobject]@{ Name = 'Current identity (read-only)'; Command = '[System.Security.Principal.WindowsIdentity]::GetCurrent() | Select-Object Name, AuthenticationType, IsAuthenticated, ImpersonationLevel' }
        }
        'KeyMgr / .NET APIs (current runspace)' {
            [pscustomobject]@{ Name = 'CredMan credentials'; Command = '[Credential]::LoadAll() | Select-Object Target, Username, Type, PersistenceType, LastWriteTime' }
            [pscustomobject]@{ Name = 'PasswordVault credentials'; Command = 'Get-PasswordVaultCredentials | Select-Object Target, Username, Provider' }
            [pscustomobject]@{ Name = 'vaultcmd projection'; Command = 'Get-VaultcmdCredentials | Select-Object VaultName, VaultGuid, Schema, Target, Username, PackageSid, SavedBy, Hidden, Roaming' }
            [pscustomobject]@{ Name = 'Vault GUIDs'; Command = 'Get-AllVaultGuids' }
            [pscustomobject]@{ Name = 'Edge profiles'; Command = '[EdgeDiagnosticsEngine]::ListProfiles() | Select-Object DisplayName, DirectoryName, ProfilePath' }
            [pscustomobject]@{ Name = 'Edge database overview'; Command = '[EdgeDiagnosticsEngine]::GetDatabaseOverview() | Format-Table ProfileName, DatabasePath, LoginRowCount, IntegrityResult -AutoSize' }
            [pscustomobject]@{ Name = 'Physical Vault probe'; Command = '[VaultEncryptionEngine]::ProbeVaultFiles() | Format-Table RootName, VaultGuid, CredentialFileCount, Status, Detail -AutoSize' }
            [pscustomobject]@{ Name = 'Current User certificates'; Command = 'Get-CertificateCredentials | Select-Object Subject, Thumbprint, NotAfter, HasPrivateKey' }
        }
        'cmdkey.exe' {
            [pscustomobject]@{ Name = 'List credentials'; Command = '/list' }
            [pscustomobject]@{ Name = 'List one target (edit target)'; Command = '/list:TERMSRV/example-host' }
        }
        'vaultcmd.exe' {
            [pscustomobject]@{ Name = 'List vaults'; Command = '/list' }
            [pscustomobject]@{ Name = 'List Web Credentials'; Command = '/listcreds:"Web Credentials" /all' }
            [pscustomobject]@{ Name = 'List Web Credential properties'; Command = '/listproperties:"Web Credentials"' }
        }
        'rundll32.exe' {
            [pscustomobject]@{ Name = 'Open native Stored User Names and Passwords'; Command = 'keymgr.dll,KRShowKeyMgr' }
            [pscustomobject]@{ Name = 'Create local-account password reset disk'; Command = 'keymgr.dll,PRShowSaveWizardExW' }
            [pscustomobject]@{ Name = 'Restore with local-account password reset disk'; Command = 'keymgr.dll,PRShowRestoreWizardExW' }
        }
        'Command Prompt (cmd.exe)' {
            [pscustomobject]@{ Name = 'Current identity'; Command = 'whoami /all' }
            [pscustomobject]@{ Name = 'Credential-related processes'; Command = 'tasklist /fi "imagename eq lsass.exe" /fi "imagename eq vaultcmd.exe"' }
            [pscustomobject]@{ Name = 'Open credential backup/restore wizard'; Command = 'start "" "%SystemRoot%\System32\credwiz.exe"' }
        }
    }
}
function Invoke-KeyMgrConsoleCommand {
    param(
        [Parameter(Mandatory=$true)][string]$Target,
        [Parameter(Mandatory=$true)][string]$CommandText
    )
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        if ($Target -eq 'PowerShell (current KeyMgr runspace)' -or $Target -eq 'KeyMgr / .NET APIs (current runspace)') {
            $scriptBlock = [scriptblock]::Create($CommandText)
            $records = @(& $scriptBlock *>&1)
            $commandSucceeded = $?
            $rendered = $records | Out-String -Width 240
            return [pscustomobject]@{
                ExitCode = if ($commandSucceeded) { 0 } else { 1 }
                Output = if ([string]::IsNullOrWhiteSpace($rendered)) { '[Command completed without output]' } else { $rendered.TrimEnd() }
                DurationMs = $stopwatch.ElapsedMilliseconds
            }
        }
        $fileName = $null
        $arguments = $CommandText
        switch ($Target) {
            'cmdkey.exe' { $fileName = Join-Path $env:SystemRoot 'System32\cmdkey.exe' }
            'vaultcmd.exe' { $fileName = Join-Path $env:SystemRoot 'System32\vaultcmd.exe' }
            'rundll32.exe' { $fileName = Join-Path $env:SystemRoot 'System32\rundll32.exe' }
            'Command Prompt (cmd.exe)' {
                $fileName = if ([string]::IsNullOrWhiteSpace($env:ComSpec)) { 'cmd.exe' } else { $env:ComSpec }
                $arguments = '/d /s /c ' + $CommandText
            }
            default { throw "Unsupported command target: $Target" }
        }
        if ([string]::IsNullOrWhiteSpace($fileName) -or (-not (Test-Path -LiteralPath $fileName) -and $fileName -ne 'cmd.exe')) {
            throw "The selected command target is unavailable: $fileName"
        }
        if ($Target -eq 'rundll32.exe') {
            Start-Process -FilePath $fileName -ArgumentList $arguments
            return [pscustomobject]@{
                ExitCode = 0
                Output = '[The rundll32 command was started as a separate interactive process]'
                DurationMs = $stopwatch.ElapsedMilliseconds
            }
        }
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $fileName
        $startInfo.Arguments = $arguments
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $startInfo.WorkingDirectory = if ([string]::IsNullOrWhiteSpace($env:USERPROFILE)) { [Environment]::CurrentDirectory } else { $env:USERPROFILE }
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        if (-not $process.Start()) { throw "The selected command target did not start: $fileName" }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(120000)) {
            try { $process.Kill() } catch {}
            throw 'The command exceeded the 120-second console limit and was terminated.'
        }
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        $combined = @($stdout, $stderr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Output = if ($combined.Count -eq 0) { '[Command completed without output]' } else { ($combined -join [Environment]::NewLine).TrimEnd() }
            DurationMs = $stopwatch.ElapsedMilliseconds
        }
    } finally {
        $stopwatch.Stop()
    }
}
function Show-KeyMgrCommandConsole {
    param(
        [string]$InitialTarget = 'KeyMgr / .NET APIs (current runspace)',
        [string]$InitialCommand = ''
    )
    $consoleForm = New-Object System.Windows.Forms.Form
    $consoleForm.Text = 'KeyMgr Command Console'
    $consoleForm.Size = New-Object System.Drawing.Size(900, 680)
    $consoleForm.MinimumSize = New-Object System.Drawing.Size(720, 560)
    $consoleForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterParent
    $consoleForm.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::Sizable
    $consoleForm.MaximizeBox = $true
    $consoleForm.MinimizeBox = $false
    $consoleForm.Font = New-Object System.Drawing.Font('Consolas', 9)
    $warningPanel = New-Object System.Windows.Forms.Panel
    $warningPanel.Dock = [System.Windows.Forms.DockStyle]::Top
    $warningPanel.Height = 58
    $warningPanel.BackColor = [System.Drawing.Color]::FromArgb(255, 248, 220)
    $consoleForm.Controls.Add($warningPanel)
    $warningLabel = New-Object System.Windows.Forms.Label
    $warningLabel.Text = 'Commands run unsandboxed with your current user rights. Review commands before running them; output may contain credential metadata or secrets.'
    $warningLabel.Location = New-Object System.Drawing.Point(10, 9)
    $warningLabel.Size = New-Object System.Drawing.Size(850, 40)
    $warningLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $warningLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $warningPanel.Controls.Add($warningLabel)
    $targetLabel = New-Object System.Windows.Forms.Label
    $targetLabel.Text = 'Target:'
    $targetLabel.Location = New-Object System.Drawing.Point(12, 72)
    $targetLabel.AutoSize = $true
    $targetLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $consoleForm.Controls.Add($targetLabel)
    $targetCombo = New-Object System.Windows.Forms.ComboBox
    $targetCombo.Location = New-Object System.Drawing.Point(82, 68)
    $targetCombo.Size = New-Object System.Drawing.Size(340, 24)
    $targetCombo.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $targetCombo.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    foreach ($targetName in @('PowerShell (current KeyMgr runspace)', 'KeyMgr / .NET APIs (current runspace)', 'cmdkey.exe', 'vaultcmd.exe', 'rundll32.exe', 'Command Prompt (cmd.exe)')) {
        [void]$targetCombo.Items.Add($targetName)
    }
    $consoleForm.Controls.Add($targetCombo)
    $templateLabel = New-Object System.Windows.Forms.Label
    $templateLabel.Text = 'Template:'
    $templateLabel.Location = New-Object System.Drawing.Point(435, 72)
    $templateLabel.AutoSize = $true
    $templateLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $consoleForm.Controls.Add($templateLabel)
    $templateCombo = New-Object System.Windows.Forms.ComboBox
    $templateCombo.Location = New-Object System.Drawing.Point(505, 68)
    $templateCombo.Size = New-Object System.Drawing.Size(365, 24)
    $templateCombo.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $templateCombo.DropDownStyle = [System.Windows.Forms.ComboBoxStyle]::DropDownList
    $templateCombo.DisplayMember = 'Name'
    $templateCombo.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $consoleForm.Controls.Add($templateCombo)
    $commandLabel = New-Object System.Windows.Forms.Label
    $commandLabel.Text = 'Command (Ctrl+Enter to run):'
    $commandLabel.Location = New-Object System.Drawing.Point(12, 103)
    $commandLabel.AutoSize = $true
    $commandLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $consoleForm.Controls.Add($commandLabel)
    $commandBox = New-Object System.Windows.Forms.TextBox
    $commandBox.Location = New-Object System.Drawing.Point(12, 124)
    $commandBox.Size = New-Object System.Drawing.Size(858, 115)
    $commandBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $commandBox.Multiline = $true
    $commandBox.AcceptsReturn = $true
    $commandBox.AcceptsTab = $true
    $commandBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
    $commandBox.WordWrap = $false
    $consoleForm.Controls.Add($commandBox)
    $runButton = New-Object System.Windows.Forms.Button
    $runButton.Text = 'Run'
    $runButton.Location = New-Object System.Drawing.Point(12, 247)
    $runButton.Size = New-Object System.Drawing.Size(90, 28)
    $runButton.Font = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
    $consoleForm.Controls.Add($runButton)
    $clearButton = New-Object System.Windows.Forms.Button
    $clearButton.Text = 'Clear Output'
    $clearButton.Location = New-Object System.Drawing.Point(110, 247)
    $clearButton.Size = New-Object System.Drawing.Size(100, 28)
    $clearButton.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $consoleForm.Controls.Add($clearButton)
    $copyButton = New-Object System.Windows.Forms.Button
    $copyButton.Text = 'Copy Output'
    $copyButton.Location = New-Object System.Drawing.Point(218, 247)
    $copyButton.Size = New-Object System.Drawing.Size(100, 28)
    $copyButton.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $consoleForm.Controls.Add($copyButton)
    $refreshCheck = New-Object System.Windows.Forms.CheckBox
    $refreshCheck.Text = 'Refresh KeyMgr after command'
    $refreshCheck.Location = New-Object System.Drawing.Point(335, 251)
    $refreshCheck.AutoSize = $true
    $refreshCheck.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $consoleForm.Controls.Add($refreshCheck)
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = 'Close'
    $closeButton.Location = New-Object System.Drawing.Point(780, 247)
    $closeButton.Size = New-Object System.Drawing.Size(90, 28)
    $closeButton.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
    $closeButton.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $consoleForm.Controls.Add($closeButton)
    $outputLabel = New-Object System.Windows.Forms.Label
    $outputLabel.Text = 'Output:'
    $outputLabel.Location = New-Object System.Drawing.Point(12, 285)
    $outputLabel.AutoSize = $true
    $outputLabel.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $consoleForm.Controls.Add($outputLabel)
    $outputBox = New-Object System.Windows.Forms.TextBox
    $outputBox.Location = New-Object System.Drawing.Point(12, 306)
    $outputBox.Size = New-Object System.Drawing.Size(858, 315)
    $outputBox.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right
    $outputBox.Multiline = $true
    $outputBox.ReadOnly = $true
    $outputBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Both
    $outputBox.WordWrap = $false
    $outputBox.BackColor = [System.Drawing.Color]::White
    $consoleForm.Controls.Add($outputBox)
    $loadTemplates = {
        $templateCombo.BeginUpdate()
        try {
            $templateCombo.Items.Clear()
            foreach ($template in @(script:Get-KeyMgrCommandTemplates -Target ([string]$targetCombo.SelectedItem))) {
                [void]$templateCombo.Items.Add($template)
            }
            $templateCombo.SelectedIndex = -1
        } finally {
            $templateCombo.EndUpdate()
        }
    }
    $targetCombo.Add_SelectedIndexChanged({ & $loadTemplates })
    $templateCombo.Add_SelectedIndexChanged({
        if ($templateCombo.SelectedIndex -ge 0 -and $null -ne $templateCombo.SelectedItem) {
            $commandBox.Text = [string]$templateCombo.SelectedItem.Command
            $commandBox.Focus()
            $commandBox.SelectAll()
        }
    })
    $executeCommand = {
        $commandText = $commandBox.Text
        if ([string]::IsNullOrWhiteSpace($commandText)) {
            [System.Windows.Forms.MessageBox]::Show('Enter a command or select a template first.', 'KeyMgr Command Console', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            return
        }
        if (-not $script:KeyMgrCommandConsoleConfirmed) {
            $confirmation = [System.Windows.Forms.MessageBox]::Show(
                "This console runs commands without a sandbox and with the same rights as KeyMgr.`n`nOnly run commands you understand. Continue for this KeyMgr session?",
                'Unsandboxed Command Execution',
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            )
            if ($confirmation -ne [System.Windows.Forms.DialogResult]::Yes) { return }
            $script:KeyMgrCommandConsoleConfirmed = $true
        }
        $runButton.Enabled = $false
        $consoleForm.UseWaitCursor = $true
        [System.Windows.Forms.Application]::DoEvents()
        try {
            $target = [string]$targetCombo.SelectedItem
            $result = script:Invoke-KeyMgrConsoleCommand -Target $target -CommandText $commandText
            $header = "[{0}] Target: {1}`r`nCommand: {2}`r`nExit code: {3}; Duration: {4} ms`r`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $target, $commandText, $result.ExitCode, $result.DurationMs
            if ($outputBox.TextLength -gt 0) { $outputBox.AppendText("`r`n" + ('-' * 100) + "`r`n") }
            $outputBox.AppendText($header + $result.Output + "`r`n")
            $outputBox.SelectionStart = $outputBox.TextLength
            $outputBox.ScrollToCaret()
            if ($refreshCheck.Checked) { script:Refresh-TabbedUI }
        } catch {
            if ($outputBox.TextLength -gt 0) { $outputBox.AppendText("`r`n" + ('-' * 100) + "`r`n") }
            $outputBox.AppendText(("[{0}] ERROR: {1}`r`n" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $_.Exception.Message))
        } finally {
            $consoleForm.UseWaitCursor = $false
            $runButton.Enabled = $true
        }
    }
    $runButton.Add_Click({ & $executeCommand })
    $commandBox.Add_KeyDown({
        if ($_.Control -and $_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
            $_.SuppressKeyPress = $true
            & $executeCommand
        }
    })
    $clearButton.Add_Click({ $outputBox.Clear() })
    $copyButton.Add_Click({
        if (-not [string]::IsNullOrEmpty($outputBox.Text)) {
            [System.Windows.Forms.Clipboard]::SetText($outputBox.Text)
        }
    })
    $closeButton.Add_Click({ $consoleForm.Close() })
    $consoleForm.CancelButton = $closeButton
    $selectedTargetIndex = $targetCombo.Items.IndexOf($InitialTarget)
    if ($selectedTargetIndex -lt 0) { $selectedTargetIndex = 1 }
    $targetCombo.SelectedIndex = $selectedTargetIndex
    if (-not [string]::IsNullOrWhiteSpace($InitialCommand)) { $commandBox.Text = $InitialCommand }
    [void]$consoleForm.ShowDialog($MainForm)
}
function Get-KeyMgrDetectedEdgeVersion {
    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($registryPath in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe')) {
        try { $value = (Get-ItemProperty -LiteralPath $registryPath -ErrorAction Stop).'(default)'; if (-not [string]::IsNullOrWhiteSpace([string]$value)) { [void]$candidates.Add([string]$value) } } catch {}
    }
    foreach ($path in @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe", "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe")) { if (Test-Path -LiteralPath $path) { [void]$candidates.Add($path) } }
    foreach ($path in $candidates) { try { return [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path).FileVersion } catch {} }
    return 'Not detected'
}
function Get-KeyMgrAppBoundPolicyStatus {
    foreach ($path in @('HKCU:\Software\Policies\Microsoft\Edge','HKLM:\Software\Policies\Microsoft\Edge')) {
        try {
            $value = (Get-ItemProperty -LiteralPath $path -Name ApplicationBoundEncryptionEnabled -ErrorAction Stop).ApplicationBoundEncryptionEnabled
            if ([int]$value -eq 0) { return "Disabled ($path)" }
            return "Enabled ($path)"
        } catch {}
    }
    return 'Not configured'
}
function Show-KeyMgrBrowserCompatibility {
    $edgeVersion = script:Get-KeyMgrDetectedEdgeVersion
    $policy = script:Get-KeyMgrAppBoundPolicyStatus
    $v10 = @($Global:EdgeCollection | Where-Object { $_.EncryptionVersion -eq 'v10' }).Count
    $v11 = @($Global:EdgeCollection | Where-Object { $_.EncryptionVersion -eq 'v11' }).Count
    $v20 = @($Global:EdgeCollection | Where-Object { $_.EncryptionVersion -eq 'v20' }).Count
    $text = @"
BROWSER CREDENTIAL COMPATIBILITY

Detected environment
  Microsoft Edge:       $edgeVersion
  Windows:              $([Environment]::OSVersion.VersionString)
  App-Bound policy:     $policy

Observed Edge credentials
  v10:                  $v10
  v11:                  $v11
  v20:                  $v20

KeyMgr write support
  v10                   Read / Add / Edit / Convert
  v11                   Read / Add / Edit / Convert
  v20                   Read / Add / Edit / Convert

Format guidance
  v10                   Legacy Chromium AES-GCM protection using the profile master key.
  v11                   Alternate legacy Chromium AES-GCM marker using the profile master key.
  v20                   App-Bound key path. Microsoft Edge supports Application-Bound Encryption on Windows beginning with Edge 127 where the platform and policy permit it.

Compatibility notice
  KeyMgr intentionally allows every explicit conversion among v10, v11, and v20. A selected prefix does not guarantee that a specific Edge release, Windows version, profile, or policy can consume the record. Validate the destination environment. v20 to v10/v11 displays an explicit downgrade warning but is not blocked.

Transaction and recovery behavior
  Add, Edit, Remove, and format conversion are staged in memory. Edge is not closed and Login Data is not modified until Apply. Apply snapshots each affected profile, writes the batch, re-reads each row, decrypts it, checks URL/user/secret/format, and restores every snapshot if any operation fails. After a successful Apply, Tools > Browser Credentials recovery can restore the pre-Apply database state for the current KeyMgr session.

Legacy Edge and Internet Explorer projections
  Browser Credentials is divided into Edge (Chromium), Legacy Edge (EdgeHTML), Internet Explorer 11, and Internet Explorer 7/9 provider tabs. Legacy Edge rows are conservative linked views of Windows Web Credentials only when MicrosoftEdge or EdgeHTML ownership evidence is present in vault metadata; they are not duplicate records. IE11 remains a linked view of Windows Web Credentials. IE7/9 IntelliForms Storage2 is inventoried by registry value name and blob size only in this release. KeyMgr does not infer URLs or plaintext from unidentified encrypted historical records.
"@
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Browser Credential Compatibility'
    $form.StartPosition = 'CenterParent'; $form.Size = New-Object System.Drawing.Size(790, 590); $form.MinimumSize = New-Object System.Drawing.Size(620, 420)
    $form.Font = New-Object System.Drawing.Font('Segoe UI', 9)
    $box = New-Object System.Windows.Forms.RichTextBox
    $box.Dock = [System.Windows.Forms.DockStyle]::Fill; $box.ReadOnly = $true; $box.WordWrap = $true; $box.BackColor = [System.Drawing.SystemColors]::Window
    $box.Font = New-Object System.Drawing.Font('Consolas', 9); $box.Text = $text.Trim()
    $form.Controls.Add($box)
    [void]$form.ShowDialog($MainForm)
}

function Show-KeyMgrShortcutHelp {
    $shortcutText = @'
F5                 Refresh every provider view
Ctrl+N             Add a credential in the active provider
Ctrl+E             Edit the selected credential
Delete             Remove the selected credential
Ctrl+C             Copy the selected row (all visible columns)
Ctrl+F             Focus the active Windows/Edge filter
Ctrl+Shift+F       Clear Windows and Edge filters
Ctrl+Shift+S       Export the current visible view
Ctrl+1..Ctrl+4     Switch to Web, Windows, Browser, or Diagnostics
Apply/Revert       Commit or discard staged Edge changes
Ctrl+0             Auto-size columns in the active list
Ctrl+Alt+P         Open the KeyMgr Command Console
Alt+F4             Exit KeyMgr
'@
    [System.Windows.Forms.MessageBox]::Show($shortcutText.Trim(), 'KeyMgr Keyboard Shortcuts', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
}
function Show-KeyMgrAbout {
    $build = [SecurityEngineMatrix]::CompatibilityBuild
    $aboutText = "KeyMgr 4-7`nBuild: $build`n`nA unified Windows credential inspection and management interface for CredMan, PasswordVault, vaultcmd/vaultcli, Browser Credentials (Chromium Edge, Legacy Edge/EdgeHTML, and IE projections), certificate credentials, .crd workflows, and Vault diagnostics.`n`nCredential pages use the same native WinForms ListView scrolling behavior as Diagnostics; the horizontal scrollbar appears automatically whenever the fixed-width columns exceed the visible client width.`n`nProvider capabilities drive command availability. Supported mutations now use provider snapshots, post-write re-read verification, and rollback where the provider exposes enough state to restore safely. Operation history remains secret-free and records snapshot, verification, and rollback outcomes.`n`nRoutine provider enumeration is metadata-only. Secrets are retrieved on demand for reveal, edit, or a short-lived transaction snapshot and are cleared after use. CredMan reveal is credential-type aware: readable generic Unicode blobs are supported, while domain, certificate, extended, empty, inaccessible, and provider-owned binary blobs receive an explicit status instead of being copied as text.`n`nCredential transfer uses Microsoft's credwiz.exe wizard. Password reset disks remain available as a separate removable-media workflow.`n`nThe Tools command console is unsandboxed and runs with the current user's rights."
    [System.Windows.Forms.MessageBox]::Show($aboutText, 'About KeyMgr', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
}
function New-KeyMgrMenuItem {
    param(
        [string]$Text,
        [System.Windows.Forms.Keys]$ShortcutKeys = [System.Windows.Forms.Keys]::None,
        [scriptblock]$Action = $null
    )
    $menuItem = New-Object System.Windows.Forms.ToolStripMenuItem
    $menuItem.Text = $Text
    if ($ShortcutKeys -ne [System.Windows.Forms.Keys]::None) {
        $menuItem.ShortcutKeys = $ShortcutKeys
        $menuItem.ShowShortcutKeys = $true
    }
    if ($null -ne $Action) {
        # GetNewClosure creates a dynamic module whose script scope is not the KeyMgr script scope.
        # Store both ScriptBlocks on the menu item and use the sender at click time, avoiding a
        # closure and any lookup of "script:Invoke-UiEventSafely" from the wrong script scope.
        $safeInvoker = ${function:Invoke-UiEventSafely}
        if ($null -eq $safeInvoker) {
            throw 'Invoke-UiEventSafely is unavailable while constructing a menu item.'
        }
        $menuItem.Tag = [pscustomobject]@{
            SafeInvoker = $safeInvoker
            Action = $Action
        }
        $menuItem.Add_Click({
            $binding = $this.Tag
            if ($null -eq $binding -or $null -eq $binding.SafeInvoker -or $null -eq $binding.Action) {
                throw 'The selected KeyMgr menu item has no valid action binding.'
            }
            & $binding.SafeInvoker -Action $binding.Action
        })
    }
    return $menuItem
}
$MenuStrip = New-Object System.Windows.Forms.MenuStrip
$MenuStrip.Dock = [System.Windows.Forms.DockStyle]::Top
$MenuStrip.ShowItemToolTips = $true
$MainForm.MainMenuStrip = $MenuStrip
$MainForm.Controls.Add($MenuStrip)
$FileMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$FileMenu.Text = '&File'
$FileRefreshMenu = script:New-KeyMgrMenuItem -Text '&Refresh' -ShortcutKeys ([System.Windows.Forms.Keys]::F5) -Action { script:Refresh-TabbedUI }
$FileCredentialTransferMenu = script:New-KeyMgrMenuItem -Text 'Credential &backup / restore...' -Action { script:Invoke-KeyMgrCredentialTransferWizard }
$FileCreateResetDiskMenu = script:New-KeyMgrMenuItem -Text '&Create password reset disk...' -Action { script:Invoke-KeyMgrPasswordResetWizard -Operation Create }
$FileRestoreResetDiskMenu = script:New-KeyMgrMenuItem -Text '&Restore with password reset disk...' -Action { script:Invoke-KeyMgrPasswordResetWizard -Operation Restore }
$FileImportMenu = script:New-KeyMgrMenuItem -Text '&Import .crd for diagnostics...' -Action {
    if ($TabControl.SelectedIndex -ne 3) {
        $TabControl.SelectedIndex = 3
        [System.Windows.Forms.Application]::DoEvents()
    }
    $BtnImportCrd.PerformClick()
}
$FileExportMenu = script:New-KeyMgrMenuItem -Text 'E&xport current view...' -ShortcutKeys ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::Shift -bor [System.Windows.Forms.Keys]::S) -Action { script:Export-KeyMgrActiveView }
$FileExitMenu = script:New-KeyMgrMenuItem -Text 'E&xit' -ShortcutKeys ([System.Windows.Forms.Keys]::Alt -bor [System.Windows.Forms.Keys]::F4) -Action { $MainForm.Close() }
foreach ($item in @($FileRefreshMenu, (New-Object System.Windows.Forms.ToolStripSeparator), $FileCredentialTransferMenu, $FileCreateResetDiskMenu, $FileRestoreResetDiskMenu, $FileImportMenu, (New-Object System.Windows.Forms.ToolStripSeparator), $FileExportMenu, (New-Object System.Windows.Forms.ToolStripSeparator), $FileExitMenu)) { [void]$FileMenu.DropDownItems.Add($item) }
$EditMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$EditMenu.Text = '&Edit'
$EditAddMenu = script:New-KeyMgrMenuItem -Text '&Add...' -ShortcutKeys ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::N) -Action { $BtnAdd.PerformClick() }
$EditEditMenu = script:New-KeyMgrMenuItem -Text '&Edit...' -ShortcutKeys ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::E) -Action { $BtnEdit.PerformClick() }
$EditRemoveMenu = script:New-KeyMgrMenuItem -Text '&Remove' -ShortcutKeys ([System.Windows.Forms.Keys]::Delete) -Action { $BtnRemove.PerformClick() }
$EditCopyMenu = script:New-KeyMgrMenuItem -Text '&Copy selected row' -ShortcutKeys ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::C) -Action { script:Copy-KeyMgrActiveRow }
$EditFindMenu = script:New-KeyMgrMenuItem -Text '&Find / Filter' -ShortcutKeys ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::F) -Action { script:Focus-KeyMgrFilter }
$EditClearFiltersMenu = script:New-KeyMgrMenuItem -Text 'Clear &filters' -ShortcutKeys ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::Shift -bor [System.Windows.Forms.Keys]::F) -Action { script:Clear-KeyMgrFilters }
foreach ($item in @($EditAddMenu, $EditEditMenu, $EditRemoveMenu, (New-Object System.Windows.Forms.ToolStripSeparator), $EditCopyMenu, (New-Object System.Windows.Forms.ToolStripSeparator), $EditFindMenu, $EditClearFiltersMenu)) { [void]$EditMenu.DropDownItems.Add($item) }
$ViewMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$ViewMenu.Text = '&View'
$ViewWebMenu = script:New-KeyMgrMenuItem -Text '&Web Credentials' -ShortcutKeys ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::D1) -Action { $TabControl.SelectedIndex = 0 }
$ViewWindowsMenu = script:New-KeyMgrMenuItem -Text 'Wi&ndows Credentials' -ShortcutKeys ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::D2) -Action { $TabControl.SelectedIndex = 1 }
$ViewEdgeMenu = script:New-KeyMgrMenuItem -Text '&Browser Credentials' -ShortcutKeys ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::D3) -Action { $TabControl.SelectedIndex = 2 }
$ViewDiagnosticsMenu = script:New-KeyMgrMenuItem -Text '&Diagnostics' -ShortcutKeys ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::D4) -Action { $TabControl.SelectedIndex = 3 }
$ViewAutoSizeMenu = script:New-KeyMgrMenuItem -Text '&Auto-size active columns' -ShortcutKeys ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::D0) -Action { script:Resize-KeyMgrActiveColumns }
$ViewTopMostMenu = script:New-KeyMgrMenuItem -Text 'Always on &top' -Action { $MainForm.TopMost = -not $MainForm.TopMost }
$ViewTopMostMenu.CheckOnClick = $true
foreach ($item in @($ViewWebMenu, $ViewWindowsMenu, $ViewEdgeMenu, $ViewDiagnosticsMenu, (New-Object System.Windows.Forms.ToolStripSeparator), $ViewAutoSizeMenu, $ViewTopMostMenu)) { [void]$ViewMenu.DropDownItems.Add($item) }
$ToolsMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$ToolsMenu.Text = '&Tools'
$ToolsConsoleMenu = script:New-KeyMgrMenuItem -Text '&Command Console...' -ShortcutKeys ([System.Windows.Forms.Keys]::Control -bor [System.Windows.Forms.Keys]::Alt -bor [System.Windows.Forms.Keys]::P) -Action { script:Show-KeyMgrCommandConsole }
$ToolsCmdkeyMenu = script:New-KeyMgrMenuItem -Text 'Run &cmdkey /list...' -Action { script:Show-KeyMgrCommandConsole -InitialTarget 'cmdkey.exe' -InitialCommand '/list' }
$ToolsVaultcmdMenu = script:New-KeyMgrMenuItem -Text 'Run &vaultcmd /list...' -Action { script:Show-KeyMgrCommandConsole -InitialTarget 'vaultcmd.exe' -InitialCommand '/list' }
$ToolsNativeMenu = script:New-KeyMgrMenuItem -Text 'Open native Credential &Manager' -Action { Start-Process -FilePath 'control.exe' -ArgumentList '/name Microsoft.CredentialManager' }
$ToolsCredentialWizardMenu = script:New-KeyMgrMenuItem -Text 'Open Windows credential &transfer wizard' -Action { script:Invoke-KeyMgrCredentialTransferWizard }
$ToolsCapabilitiesMenu = script:New-KeyMgrMenuItem -Text 'Active provider &capabilities...' -Action { script:Show-KeyMgrProviderCapabilities }
$ToolsOperationHistoryMenu = script:New-KeyMgrMenuItem -Text 'Operation &history...' -Action { script:Show-KeyMgrOperationHistory }
$ToolsBrowserRecoveryMenu = script:New-KeyMgrMenuItem -Text 'Browser Credentials &recovery...' -Action { script:Undo-KeyMgrLastBrowserApply }
$ToolsOpenLogMenu = script:New-KeyMgrMenuItem -Text 'Open runtime &log' -Action {
    if (Test-Path -LiteralPath $script:KeyMgrRuntimeLog) {
        Start-Process -FilePath 'notepad.exe' -ArgumentList @($script:KeyMgrRuntimeLog)
    }
}
$ToolsOpenLogFolderMenu = script:New-KeyMgrMenuItem -Text 'Open log &folder' -Action { Start-Process -FilePath 'explorer.exe' -ArgumentList @((Split-Path -Parent $script:KeyMgrRuntimeLog)) }
foreach ($item in @($ToolsConsoleMenu, (New-Object System.Windows.Forms.ToolStripSeparator), $ToolsCmdkeyMenu, $ToolsVaultcmdMenu, (New-Object System.Windows.Forms.ToolStripSeparator), $ToolsNativeMenu, $ToolsCredentialWizardMenu, (New-Object System.Windows.Forms.ToolStripSeparator), $ToolsCapabilitiesMenu, $ToolsOperationHistoryMenu, $ToolsBrowserRecoveryMenu, (New-Object System.Windows.Forms.ToolStripSeparator), $ToolsOpenLogMenu, $ToolsOpenLogFolderMenu)) { [void]$ToolsMenu.DropDownItems.Add($item) }
$HelpMenu = New-Object System.Windows.Forms.ToolStripMenuItem
$HelpMenu.Text = '&Help'
$HelpShortcutsMenu = script:New-KeyMgrMenuItem -Text '&Keyboard shortcuts' -Action { script:Show-KeyMgrShortcutHelp }
$HelpBrowserCompatibilityMenu = script:New-KeyMgrMenuItem -Text '&Browser Credential Compatibility...' -Action { script:Show-KeyMgrBrowserCompatibility }
$HelpAboutMenu = script:New-KeyMgrMenuItem -Text '&About KeyMgr' -Action { script:Show-KeyMgrAbout }
foreach ($item in @($HelpShortcutsMenu, $HelpBrowserCompatibilityMenu, (New-Object System.Windows.Forms.ToolStripSeparator), $HelpAboutMenu)) { [void]$HelpMenu.DropDownItems.Add($item) }
foreach ($menu in @($FileMenu, $EditMenu, $ViewMenu, $ToolsMenu, $HelpMenu)) { [void]$MenuStrip.Items.Add($menu) }
$FileMenu.Add_DropDownOpening({
    $activeList = script:Get-KeyMgrActiveListView
    $providerContext = script:Get-KeyMgrActiveProviderContext
    $FileExportMenu.Enabled = (script:Test-KeyMgrProviderCapability -Capability 'CanExport' -Context $providerContext) -and $null -ne $activeList -and -not $activeList.IsDisposed -and $activeList.Items.Count -gt 0
})
$EditMenu.Add_DropDownOpening({
    $activeList = script:Get-KeyMgrActiveListView
    $EditAddMenu.Enabled = $BtnAdd.Enabled
    $EditEditMenu.Enabled = $BtnEdit.Enabled
    $EditRemoveMenu.Enabled = $BtnRemove.Enabled
    $EditCopyMenu.Enabled = $null -ne $activeList -and -not $activeList.IsDisposed -and $activeList.SelectedIndices.Count -gt 0
    $EditFindMenu.Enabled = $TabControl.SelectedIndex -eq 1 -or $TabControl.SelectedIndex -eq 2
    $EditClearFiltersMenu.Enabled = -not [string]::IsNullOrWhiteSpace($TxtWinFilter.Text) -or -not [string]::IsNullOrWhiteSpace($TxtEdgeTabFilter.Text)
})
$ViewMenu.Add_DropDownOpening({
    $ViewWebMenu.Checked = $TabControl.SelectedIndex -eq 0
    $ViewWindowsMenu.Checked = $TabControl.SelectedIndex -eq 1
    $ViewEdgeMenu.Checked = $TabControl.SelectedIndex -eq 2
    $ViewDiagnosticsMenu.Checked = $TabControl.SelectedIndex -eq 3
    $ViewTopMostMenu.Checked = $MainForm.TopMost
})
$ToolsMenu.Add_DropDownOpening({ $ToolsOpenLogMenu.Enabled = Test-Path -LiteralPath $script:KeyMgrRuntimeLog; $ToolsBrowserRecoveryMenu.Enabled = $null -ne $Global:LastBrowserApplyRecovery })
$MenuStrip.BringToFront()
# ===================================================================
# 13. MAIN BUTTON ACTIONS AND STARTUP VALIDATION
# ===================================================================
$BtnBackup.Add_Click({ script:Invoke-UiEventSafely { script:Invoke-KeyMgrCredentialTransferWizard } })
$BtnRestore.Add_Click({ script:Invoke-UiEventSafely { script:Show-KeyMgrPasswordResetDialog } })
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
            $result = script:Import-CrdBackupFile -FilePath $ofd.FileName -AllowDuplicates
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
function Test-KeyMgrRuntimeBindings {
    $requiredFunctions = @(
        'Write-KeyMgrRuntimeLog',
        'Invoke-KeyMgrCredentialTransferWizard',
        'Invoke-KeyMgrPasswordResetWizard',
        'Show-KeyMgrPasswordResetDialog',
        'Load-ImportedCredentials',
        'Refresh-TabbedUI',
        'Invoke-UiEventSafely',
        'Update-ButtonStates',
        'Clear-OtherSelections',
        'Clear-BrowserSelections',
        'Clear-DiagnosticSelections',
        'Add-DiagnosticErrorLogEntry',
        'Test-KeyMgrBrowserFilterMatch',
        'Add-EdgeDiagnosticListViewItem',
        'Add-KeyMgrBrowserPlaceholder',
        'Update-EdgeTabList',
        'Get-KeyMgrActiveBrowserListView',
        'Get-SelectedBrowserCredentialRow',
        'Get-SelectedEdgeTabRow',
        'Add-ListViewRow',
        'Update-EdgeDiagnosticsViews',
        'Show-EdgePropertyDialog',
        'Get-KeyMgrLegacyEdgeEvidence',
        'Get-KeyMgrIEStorage2Entries',
        'Update-KeyMgrBrowserProjections',
        'Update-BrowserPendingState',
        'Get-KeyMgrBrowserPendingState',
        'Add-KeyMgrBrowserPendingChange',
        'Clear-KeyMgrBrowserPendingChanges',
        'Close-KeyMgrEdgeForApply',
        'Apply-KeyMgrBrowserChanges',
        'Undo-KeyMgrLastBrowserApply',
        'Get-KeyMgrDetectedEdgeVersion',
        'Get-KeyMgrAppBoundPolicyStatus',
        'Show-KeyMgrBrowserCompatibility',
        'Get-KeyMgrActiveListView',
        'Copy-KeyMgrActiveRow',
        'Resize-KeyMgrActiveColumns',
        'Focus-KeyMgrFilter',
        'Clear-KeyMgrFilters',
        'Export-KeyMgrActiveView',
        'Get-KeyMgrCommandTemplates',
        'Invoke-KeyMgrConsoleCommand',
        'Show-KeyMgrCommandConsole',
        'Show-KeyMgrShortcutHelp',
        'Show-KeyMgrAbout',
        'New-KeyMgrMenuItem',
        'Get-KeyMgrProviderCapabilities',
        'Get-KeyMgrActiveProviderContext',
        'Get-KeyMgrOperationContext',
        'Test-KeyMgrProviderCapability',
        'New-KeyMgrOperationResult',
        'Register-KeyMgrOperationResult',
        'Complete-KeyMgrOperation',
        'Show-KeyMgrUnsupportedOperation',
        'Show-KeyMgrProviderCapabilities',
        'Show-KeyMgrOperationHistory',
        'New-KeyMgrTransaction',
        'Invoke-KeyMgrProviderMutation',
        'Get-KeyMgrPasswordVaultSnapshot',
        'Clear-KeyMgrSecretObject',
        'Clear-KeyMgrSecretCollection',
        'Show-KeyMgrSecretOnDemand',
        'Invoke-KeyMgrAddOperation',
        'Invoke-KeyMgrEditOperation',
        'Invoke-KeyMgrRemoveOperation'
    )
    $missingFunctions = New-Object System.Collections.Generic.List[string]
    foreach ($functionName in $requiredFunctions) {
        $command = Get-Command -Name $functionName -CommandType Function -ErrorAction SilentlyContinue
        if ($null -eq $command) {
            [void]$missingFunctions.Add($functionName)
        }
    }
    if ($missingFunctions.Count -gt 0) {
        throw ('Required KeyMgr functions are unavailable before the UI starts: ' + ($missingFunctions -join ', '))
    }
    $requiredEdgeMethods = @(
        'LoadDiagnostics',
        'GetDatabaseOverview',
        'GetSqlTrace',
        'GetSchemaInventory',
        'GetDiagnosticErrors',
        'ClearSqlTrace',
        'IsEdgeRunning',
        'KillEdgeProcesses',
        'CaptureCredentialSnapshot',
        'CredentialExists',
        'VerifyCredential',
        'VerifyCredentialDetails',
        'UpdateCredential',
        'AddCredential',
        'DeleteCredential'
    )
    $edgeType = ([System.Management.Automation.PSTypeName]'EdgeDiagnosticsEngine').Type
    if ($null -eq $edgeType) {
        throw 'The embedded EdgeDiagnosticsEngine type is unavailable after Add-Type completed.'
    }
    $missingMethods = New-Object System.Collections.Generic.List[string]
    $bindingFlags = [System.Reflection.BindingFlags]::Public -bor [System.Reflection.BindingFlags]::Static
    foreach ($methodName in $requiredEdgeMethods) {
        if (@($edgeType.GetMethods($bindingFlags) | Where-Object { $_.Name -eq $methodName }).Count -eq 0) {
            [void]$missingMethods.Add($methodName)
        }
    }
    if ($missingMethods.Count -gt 0) {
        throw ('Required EdgeDiagnosticsEngine methods are unavailable: ' + ($missingMethods -join ', '))
    }
    script:Write-KeyMgrRuntimeLog 'BINDINGS' ('Validated {0} PowerShell functions and {1} Edge/SQLite methods before UI startup.' -f $requiredFunctions.Count, $requiredEdgeMethods.Count)
}
script:Test-KeyMgrRuntimeBindings
$script:KeyMgrUiInitialized = $false
$MainForm.Add_Shown({
    if (-not $script:KeyMgrUiInitialized) {
        $script:KeyMgrUiInitialized = $true
        script:Write-KeyMgrRuntimeLog 'UI' 'Main form shown; starting initial refresh.'
        script:Invoke-UiEventSafely {
            script:Load-ImportedCredentials
            script:Refresh-TabbedUI
        }
    }
})
$MainForm.Add_FormClosed({
    try {
        script:Clear-KeyMgrSecretCollection -Collection $Global:WebCollection
        script:Clear-KeyMgrSecretCollection -Collection $Global:WinCoreColl
        script:Clear-KeyMgrSecretCollection -Collection $Global:WinCertColl
        script:Clear-KeyMgrSecretCollection -Collection $Global:WinGenColl
        script:Clear-KeyMgrSecretCollection -Collection $Global:EdgeCollection
        script:Clear-KeyMgrSecretCollection -Collection $Global:BrowserPendingChanges
        if ($null -ne $Global:LastBrowserApplyRecovery) {
            foreach ($snapshot in $Global:LastBrowserApplyRecovery.Snapshots) { script:Remove-KeyMgrEdgeDatabaseSnapshot -Snapshot $snapshot }
        }
        $Global:LastBrowserApplyRecovery = $null
        script:Clear-KeyMgrSecretCollection -Collection $Global:ImportedCredentials
        $Global:ImportedCredentials = @()
        script:Write-KeyMgrRuntimeLog 'SECRET-CLEANUP' 'Cleared session secret holders during form shutdown.'
    } catch {
        script:Write-KeyMgrRuntimeLog 'SECRET-CLEANUP' $_
    }
})
script:Write-KeyMgrRuntimeLog 'UI' 'Entering the WinForms message loop.'
[System.Windows.Forms.Application]::Run($MainForm)
script:Write-KeyMgrRuntimeLog 'SHUTDOWN' 'WinForms message loop exited normally.'
} catch {
    script:Write-KeyMgrRuntimeLog 'FATAL' $_
    $fatalMessage = "KeyMgr could not start or continue.`n`n$($_.Exception.Message)`n`nA diagnostic log was written to:`n$script:KeyMgrRuntimeLog"
    try {
        [System.Windows.Forms.MessageBox]::Show($fatalMessage, 'KeyMgr startup/runtime error', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    } catch {
        Write-Host $fatalMessage
    }
}