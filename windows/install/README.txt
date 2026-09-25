Rostor for Windows (rostor-windows-amd64.zip). Unzip, then in an ELEVATED PowerShell (Run as administrator):
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -CoreUrl https://core.example:8443 -Token <enrollment token>
Mint the enrollment token in the Rostor console first. The command enrolls this workstation, installs the
RostorDeputy service and the lock-screen tile, and prints a summary. Re-running is safe.
Remove with:  powershell -ExecutionPolicy Bypass -File .\uninstall.ps1 [-Purge]
Build details and switches: docs/windows-logon-build.md in the rostor-org/app repository.
