#Requires -Version 5.1
<#
.SYNOPSIS
  Pont JSON WinAudit — lit une requete, appelle les modules, ecrit une reponse.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$InFile,
    [Parameter(Mandatory)][string]$OutFile
)

$ErrorActionPreference = 'Continue'
try {
    [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
    [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $global:OutputEncoding = [System.Text.UTF8Encoding]::new($false)
} catch { }

$Global:WinAuditRoot = Split-Path $PSScriptRoot -Parent
$modDir = Join-Path $Global:WinAuditRoot 'modules'
@(
    'Elevate.ps1'
    'Audit.Core.ps1'
    'Audit.Hash.ps1'
    'Audit.Baseline.ps1'
    'Audit.Checklist.ps1'
    'Audit.Deduce.ps1'
    'Audit.Persistence.ps1'
    'Audit.Runtime.ps1'
    'Audit.Network.ps1'
    'Audit.Devices.ps1'
    'Audit.Accounts.ps1'
    'Audit.Traces.ps1'
    'Audit.Surface.ps1'
    'Audit.Orchestrator.ps1'
) | ForEach-Object { . (Join-Path $modDir $_) }

$logsDir = Join-Path $Global:WinAuditRoot 'logs'
if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }
$lastPath = Join-Path $logsDir 'last-result.json'
$progressPath = Join-Path $logsDir 'scan-progress.json'

function Write-ApiResponse {
    param($Obj)
    $json = $Obj | ConvertTo-Json -Depth 12 -Compress
    [System.IO.File]::WriteAllText($OutFile, $json, [System.Text.UTF8Encoding]::new($false))
}

function Ok($data = $null) {
    Write-ApiResponse @{ ok = $true; error = $null; data = $data }
}

function Fail([string]$msg) {
    Write-ApiResponse @{ ok = $false; error = $msg; data = $null }
}

function Import-LastResult {
    if (-not (Test-Path -LiteralPath $lastPath)) { return $null }
    try {
        return (Get-Content -LiteralPath $lastPath -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch { return $null }
}

function Save-LastResult {
    param($Result)
    $Result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $lastPath -Encoding UTF8
}

function Read-ScanProgress {
    if (-not (Test-Path -LiteralPath $progressPath)) {
        return @{
            percent = 0; phase = ''; detail = ''; done = $false; error = $null; updatedAt = $null
        }
    }
    try {
        return (Get-Content -LiteralPath $progressPath -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        return @{
            percent = 0; phase = ''; detail = ''; done = $false; error = $null; updatedAt = $null
        }
    }
}

function Enable-ScanProgressCallback {
    $Global:WinAuditProgressPath = $progressPath
    $Global:WinAuditProgressLastWrite = [datetime]::MinValue
    $Global:WinAuditProgressLastKey = ''
    $Global:AuditProgressCallback = {
        param($Phase, $Percent, $Detail)
        $path = $Global:WinAuditProgressPath
        if (-not $path) { return }
        $globalPct = Get-AuditGlobalProgressPercent -Phase $Phase -Percent $Percent
        $forceKey = "{0}|{1}|{2}" -f $Phase, $globalPct, $Detail
        $now = Get-Date
        $elapsed = 9999
        try { $elapsed = ($now - [datetime]$Global:WinAuditProgressLastWrite).TotalMilliseconds } catch { }
        if ($Phase -eq 'Termine') {
            Write-AuditScanProgressFile -Path $path -Percent 100 -Phase $Phase -Detail $Detail -Done $false
            $Global:WinAuditProgressLastWrite = $now
            $Global:WinAuditProgressLastKey = $forceKey
            return
        }
        if ($elapsed -lt 200 -and $forceKey -eq $Global:WinAuditProgressLastKey) { return }
        Write-AuditScanProgressFile -Path $path -Percent $globalPct -Phase $Phase -Detail $Detail -Done $false
        $Global:WinAuditProgressLastWrite = $now
        $Global:WinAuditProgressLastKey = $forceKey
    }.GetNewClosure()
}

try {
    if (-not (Test-Path -LiteralPath $InFile)) { Fail "InFile introuvable: $InFile"; exit 1 }
    $raw = [System.IO.File]::ReadAllText($InFile, [System.Text.Encoding]::UTF8)
    $req = $raw | ConvertFrom-Json
    $action = [string]$req.action
    $p = $req.payload
    if (-not $p) { $p = [pscustomobject]@{} }

    switch ($action) {
        'ping' {
            Ok @{
                admin = [bool](Test-WinAuditAdmin)
                root  = $Global:WinAuditRoot
                hasLast = [bool](Test-Path -LiteralPath $lastPath)
            }
        }

        'getScanProgress' {
            Ok (Read-ScanProgress)
        }

        'runScan' {
            Write-AuditScanProgressFile -Path $progressPath -Percent 0 -Phase 'Persistence' -Detail 'Demarrage...' -Done $false
            Enable-ScanProgressCallback
            try {
                $result = Invoke-WinAuditFullScan -Root $Global:WinAuditRoot -LogsDir $logsDir
                Save-LastResult $result
                $paths = Export-AuditReport -LogsDir $logsDir -Result $result
                Write-AuditScanProgressFile -Path $progressPath -Percent 100 -Phase 'Termine' `
                    -Detail ("{0} findings" -f @($result.Findings).Count) -Done $true
                Ok @{
                    result = $result
                    export = @{
                        Json = $paths.Json
                        Txt  = $paths.Txt
                        Html = $paths.Html
                    }
                }
            }
            catch {
                $msg = "{0}" -f $_.Exception.Message
                Write-AuditScanProgressFile -Path $progressPath -Percent 100 -Phase 'Erreur' -Detail $msg -Done $true -ErrorMessage $msg
                Fail $msg
            }
            finally {
                $Global:AuditProgressCallback = $null
            }
        }

        'getLastResult' {
            $r = Import-LastResult
            if (-not $r) { Fail 'Aucun scan precedent.'; return }
            Ok @{ result = $r }
        }

        'refreshConnections' {
            Initialize-AuditCore -Root $Global:WinAuditRoot
            $conns = @(Get-AuditConnectionInventory -SkipReverseDns)
            $r = Import-LastResult
            if ($r) {
                $r.Connections = $conns
                Save-LastResult $r
            }
            Ok @{
                connections = $conns
                count = $conns.Count
            }
        }

        'exportReport' {
            $r = Import-LastResult
            if (-not $r) { Fail 'Aucun scan a exporter.'; return }
            $paths = Export-AuditReport -LogsDir $logsDir -Result $r
            Ok @{ Json = $paths.Json; Txt = $paths.Txt; Html = $paths.Html }
        }

        'exportPrint' {
            $r = Import-LastResult
            if (-not $r) { Fail 'Aucun scan a exporter.'; return }
            $path = Export-AuditPrintReport -LogsDir $logsDir -Result $r
            Ok @{ Html = $path }
        }

        'getWhitelist' {
            Ok @{ patterns = @(Get-AuditAllowListPatterns -Root $Global:WinAuditRoot) }
        }

        'saveWhitelist' {
            $patterns = @()
            if ($p.patterns) { $patterns = @($p.patterns) }
            $path = Save-AuditAllowList -Root $Global:WinAuditRoot -Patterns $patterns
            Ok @{ path = $path; count = $patterns.Count }
        }

        default {
            Fail "Action inconnue: $action"
        }
    }
}
catch {
    Fail ("{0}" -f $_.Exception.Message)
    exit 1
}
