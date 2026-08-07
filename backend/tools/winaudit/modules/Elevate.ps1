#Requires -Version 5.1
# Elevate.ps1

function Test-WinAuditAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Request-WinAuditAdmin {
    param([string]$ScriptPath)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell.exe'
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -NoElevate"
    $psi.Verb = 'runas'
    try {
        [Diagnostics.Process]::Start($psi) | Out-Null
        return $true
    }
    catch { return $false }
}
