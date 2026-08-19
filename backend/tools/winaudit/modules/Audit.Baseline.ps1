# Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X

#Requires -Version 5.1
# Audit.Baseline.ps1 - Snapshots + diff entre scans

function Get-AuditFindingFingerprint {
    param($Finding)
    $path = if ($Finding.Path) { [string]$Finding.Path } else { '' }
    $title = if ($Finding.Title) { [string]$Finding.Title } else { '' }
    $cat = if ($Finding.Category) { [string]$Finding.Category } else { '' }
    $sev = if ($Finding.Severity) { [string]$Finding.Severity } else { '' }
    return ("{0}|{1}|{2}|{3}" -f $cat, $sev, $title, $path).ToLowerInvariant()
}

function Get-AuditConnectionFingerprint {
    param($Conn)
    return ("{0}|{1}|{2}|{3}|{4}|{5}|{6}" -f `
        $Conn.Protocol, $Conn.Direction, $Conn.ProcessName, `
        $Conn.LocalAddress, $Conn.LocalPort, $Conn.RemoteAddress, $Conn.RemotePort).ToLowerInvariant()
}

function Get-AuditLatestBaselinePath {
    param([string]$LogsDir)
    if (-not (Test-Path -LiteralPath $LogsDir)) { return $null }
    $latest = Get-ChildItem -LiteralPath $LogsDir -Filter 'baseline-*.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
    if ($latest) { return $latest.FullName }
    return $null
}

function Import-AuditBaseline {
    param([string]$LogsDir)
    $path = Get-AuditLatestBaselinePath -LogsDir $LogsDir
    if (-not $path) { return $null }
    try {
        $raw = Get-Content -LiteralPath $path -Raw -Encoding UTF8
        $obj = $raw | ConvertFrom-Json
        return [pscustomobject]@{
            Path         = $path
            GeneratedAt  = [string]$obj.GeneratedAt
            FindingKeys  = @($obj.FindingKeys)
            ConnectionKeys = @($obj.ConnectionKeys)
        }
    }
    catch { return $null }
}

function Export-AuditBaseline {
    param(
        [string]$LogsDir,
        $Result,
        [string]$Stamp = $(Get-Date -Format 'yyyyMMdd_HHmmss')
    )
    if (-not (Test-Path -LiteralPath $LogsDir)) {
        New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
    }
    $findingKeys = @($Result.Findings | ForEach-Object { Get-AuditFindingFingerprint $_ } | Select-Object -Unique)
    $connKeys = @($Result.Connections | ForEach-Object { Get-AuditConnectionFingerprint $_ } | Select-Object -Unique)
    $payload = [pscustomobject]@{
        GeneratedAt     = $Result.GeneratedAt
        Score           = $Result.Score.Score
        FindingCount    = @($Result.Findings).Count
        ConnectionCount = @($Result.Connections).Count
        FindingKeys     = $findingKeys
        ConnectionKeys  = $connKeys
    }
    $path = Join-Path $LogsDir ("baseline-{0}.json" -f $Stamp)
    $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8

    # Keep only last 8 baselines
    Get-ChildItem -LiteralPath $LogsDir -Filter 'baseline-*.json' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -Skip 8 |
        Remove-Item -Force -ErrorAction SilentlyContinue

    return $path
}

function Compare-AuditBaseline {
    param(
        $PreviousBaseline,
        $Result
    )
    if (-not $PreviousBaseline) {
        return [pscustomobject]@{
            HasPrevious        = $false
            PreviousAt         = $null
            NewFindings        = @()
            NewConnections     = @()
            NewFindingCount    = 0
            NewConnectionCount = 0
            Summary            = 'Premier scan - aucune baseline precedente.'
        }
    }

    $prevF = @{}
    foreach ($k in @($PreviousBaseline.FindingKeys)) { $prevF[[string]$k] = $true }
    $prevC = @{}
    foreach ($k in @($PreviousBaseline.ConnectionKeys)) { $prevC[[string]$k] = $true }

    $newFindings = @($Result.Findings | Where-Object {
        -not $prevF.ContainsKey((Get-AuditFindingFingerprint $_))
    })
    $newConns = @($Result.Connections | Where-Object {
        -not $prevC.ContainsKey((Get-AuditConnectionFingerprint $_))
    })

    $summary = if ($newFindings.Count -eq 0 -and $newConns.Count -eq 0) {
        'Aucun nouvel element depuis le dernier scan.'
    }
    else {
        ("+{0} finding(s), +{1} connexion(s) depuis {2}" -f $newFindings.Count, $newConns.Count, $PreviousBaseline.GeneratedAt)
    }

    [pscustomobject]@{
        HasPrevious        = $true
        PreviousAt         = $PreviousBaseline.GeneratedAt
        PreviousPath       = $PreviousBaseline.Path
        NewFindings        = $newFindings
        NewConnections     = $newConns
        NewFindingCount    = $newFindings.Count
        NewConnectionCount = $newConns.Count
        Summary            = $summary
    }
}
