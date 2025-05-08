Import-Module "d:\_Backup\Configuration\SSL\Tools\app_signModule.ps1" -Force

[string[]]$appFiles = @(
    "..\bin\Release\publish\JocysCom.SslScanner.Tool.exe"
)
[string]$appName = "Jocys.com SSL Scanner Tool"
[string]$appLink = "https://www.jocys.com"

ProcessFiles $appName $appLink $appFiles

pause