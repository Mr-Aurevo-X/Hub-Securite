#Requires -Version 5.1
# Audit.Orchestrator.ps1 - scan complet + resultat agrege

function Invoke-WinAuditFullScan {
    param(
        [string]$Root,
        [string]$LogsDir = $(Join-Path $Root 'logs')
    )

    Initialize-AuditCore -Root $Root
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $all = New-Object System.Collections.Generic.List[object]
    $connections = @()

    $previous = Import-AuditBaseline -LogsDir $LogsDir

    Write-AuditProgress -Phase 'Persistence' -Percent 0 -Detail 'Demarrage...'
    foreach ($f in @(Invoke-AuditPersistenceScan)) { $all.Add($f) }

    Write-AuditProgress -Phase 'Runtime' -Percent 0 -Detail 'Demarrage...'
    foreach ($f in @(Invoke-AuditRuntimeScan)) { $all.Add($f) }

    Write-AuditProgress -Phase 'Reseau' -Percent 0 -Detail 'Demarrage...'
    $netResult = Invoke-AuditNetworkScan
    if ($netResult -and $netResult.PSObject.Properties.Name -contains 'Findings') {
        foreach ($f in @($netResult.Findings)) { $all.Add($f) }
        $connections = @($netResult.Connections)
    }
    else {
        foreach ($f in @($netResult)) { $all.Add($f) }
    }

    Write-AuditProgress -Phase 'Devices' -Percent 0 -Detail 'Demarrage...'
    foreach ($f in @(Invoke-AuditDevicesScan)) { $all.Add($f) }

    Write-AuditProgress -Phase 'Accounts' -Percent 0 -Detail 'Demarrage...'
    foreach ($f in @(Invoke-AuditAccountsScan)) { $all.Add($f) }

    Write-AuditProgress -Phase 'Traces' -Percent 0 -Detail 'Demarrage...'
    foreach ($f in @(Invoke-AuditTracesScan)) { $all.Add($f) }

    Write-AuditProgress -Phase 'Surface' -Percent 0 -Detail 'Demarrage...'
    foreach ($f in @(Invoke-AuditSurfaceScan)) { $all.Add($f) }

    Write-AuditProgress -Phase 'Deduction' -Percent 40 -Detail 'Correlations...'
    $findings = @($all.ToArray())
    $chains = @(Invoke-AuditDeduce -Findings $findings)

    Write-AuditProgress -Phase 'Deduction' -Percent 55 -Detail 'SHA256 suspects...'
    $findings = @(Add-AuditSha256ToFindings -Findings $findings)
    $connections = @(Add-AuditSha256ToConnections -Connections $connections)

    Write-AuditProgress -Phase 'Deduction' -Percent 70 -Detail 'Checklist espionnage...'
    $checklist = Invoke-AuditSpyChecklist -Findings $findings -Connections $connections -Chains $chains

    $score = Get-AuditScore -Findings $findings -Chains $chains
    $cats = @(Get-AuditCategoryStats -Findings $findings)

    $result = [pscustomobject]@{
        GeneratedAt    = (Get-Date).ToString('o')
        DurationSec    = [Math]::Round($sw.Elapsed.TotalSeconds, 1)
        ComputerName   = $env:COMPUTERNAME
        UserName       = $env:USERNAME
        Score          = $score
        CategoryStats  = $cats
        Chains         = $chains
        Findings       = $findings
        Connections    = $connections
        Checklist      = $checklist
        Diff           = $null
        BaselinePath   = $null
        Disclaimer     = 'Heuristique locale lecture seule - pas un antivirus/EDR.'
    }

    Write-AuditProgress -Phase 'Deduction' -Percent 85 -Detail 'Comparatif baseline...'
    $result.Diff = Compare-AuditBaseline -PreviousBaseline $previous -Result $result
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $result.BaselinePath = Export-AuditBaseline -LogsDir $LogsDir -Result $result -Stamp $stamp

    $sw.Stop()
    $result.DurationSec = [Math]::Round($sw.Elapsed.TotalSeconds, 1)

    Write-AuditProgress -Phase 'Termine' -Percent 100 -Detail ("{0} findings" -f $findings.Count)
    return $result
}
