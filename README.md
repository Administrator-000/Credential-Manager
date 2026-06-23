Credential Manager.ps1
---------------------
  Written in Windows PowerShell 5.1 / C# 5.0

Currently Supported Credential Sources
--------------------------------------
  Windows Credential Manager    (cmdkey.exe / DPAPI)
  PasswordVault API             (WinRT / System.Windows.Security)
  Microsoft Edge                (Chromium Login Data / winsqlite3.dll)
  Direct Vault Decryption       (Policy.vpol / .vcrd files)
  vaultcmd.exe CLI Reference    (System Protected Items)

Dependencies
------------
  Advapi32.dll        rundll32.exe        wininit.exe
  winsqlite3.dll      vaultcmd.exe        credwiz.exe
  bcrypt.dll          cmdkey.exe
  crypt32.dll         taskkill.exe
  kernel32.dll        msedge.exe
  vaultcli.dll        winlogon.exe
  netapi32.dll        services.exe
  keymgr.dll          lsass.exe

- Missing dependencies should result in graceful feature degradation.

Verified Supported Operation Systems
------------------------------------
  Windows 11          Windows Server 2025
  Windows 10          Windows Server 2022

Software License
----------------
  CC0 (Creative Commons Zero)

Known Issues
------------
  - Inconsistent launch behaviour
  - Inconsistent UI behaviour
  - Policy.vpol and .vcrd files fail to decrypt
  - Endpoint security and A/V may flag as malware
