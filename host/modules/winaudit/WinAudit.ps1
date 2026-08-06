#Requires -Version 5.1
<#
.SYNOPSIS
  Lanceur WinAudit Pro — preferre WinAudit.exe (WebView), sinon Python, sinon Legacy.
#>
[CmdletBinding()]
param(
    [switch]$NoElevate,
    [switch]$Legacy
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Root) { $Root = $PSScriptRoot }

if ($Legacy) {
    & (Join-Path $Root 'WinAudit.Legacy.ps1') -NoElevate:$NoElevate
    exit $LASTEXITCODE
}

function Test-IsAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

$skipElevate = $NoElevate -or (Test-IsAdmin)
$exe = Join-Path $Root 'WinAudit.exe'
$hostPy = Join-Path $Root 'host\winaudit_host.py'

# Evite boucle si on est deja lance depuis un contexte odd: on demarre l'exe GUI
if (Test-Path -LiteralPath $exe) {
    $args = @()
    if ($skipElevate) { $args += '--no-elevate' }
    Start-Process -FilePath $exe -ArgumentList $args -WorkingDirectory $Root
    exit 0
}

if (Test-Path -LiteralPath $hostPy) {
    $py = $null
    foreach ($c in @('python', 'py')) {
        try {
            $null = & $c --version 2>$null
            if ($LASTEXITCODE -eq 0) { $py = $c; break }
        } catch { }
    }
    if (-not $py) {
        Write-Host 'Python introuvable — fallback UI WinForms.'
        & (Join-Path $Root 'WinAudit.Legacy.ps1') -NoElevate:$NoElevate
        exit $LASTEXITCODE
    }
    $pyArgs = @($hostPy)
    if ($skipElevate) { $pyArgs += '--no-elevate' }
    Start-Process -FilePath $py -ArgumentList $pyArgs -WorkingDirectory $Root
    exit 0
}

Write-Host 'Host WebView introuvable — fallback UI WinForms.'
& (Join-Path $Root 'WinAudit.Legacy.ps1') -NoElevate:$NoElevate
exit $LASTEXITCODE
