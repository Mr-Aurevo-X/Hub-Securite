#Requires -Version 5.1
# Audit.Core.ps1 - Finding model, scoring, allowlist, signature cache, export

$script:AuditSignatureCache = @{}
$script:AuditAllowPatterns = @()
$script:AuditFindingCounter = 0

function Initialize-AuditCore {
    param([string]$Root)
    $script:AuditRoot = $Root
    $script:AuditSignatureCache = @{}
    $script:AuditFindingCounter = 0
    $script:AuditAllowPatterns = @()
    $allowPath = Join-Path $Root 'lists\audit-allow.txt'
    if (Test-Path -LiteralPath $allowPath) {
        Get-Content -LiteralPath $allowPath -Encoding UTF8 -ErrorAction SilentlyContinue |
            Where-Object { $_ -and $_.Trim() -and -not $_.Trim().StartsWith('#') } |
            ForEach-Object { $script:AuditAllowPatterns += $_.Trim() }
    }
}

function New-AuditFinding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][ValidateSet('Info','Low','Medium','High','Critical')]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [string]$Detail = '',
        [string]$Path = '',
        [string]$Evidence = '',
        [string]$WhySuspicious = '',
        [hashtable]$Meta = $null
    )
    $script:AuditFindingCounter++
    [pscustomobject]@{
        Id            = 'F{0:D4}' -f $script:AuditFindingCounter
        Category      = $Category
        Severity      = $Severity
        Title         = $Title
        Detail        = $Detail
        Path          = $Path
        Evidence      = $Evidence
        WhySuspicious = $WhySuspicious
        Meta          = $(if ($Meta) { $Meta } else { @{} })
        Timestamp     = (Get-Date).ToString('o')
    }
}

function Test-AuditAllowed {
    param([string]$Path, [string]$ProcessName = '')
    if ([string]::IsNullOrWhiteSpace($Path) -and [string]::IsNullOrWhiteSpace($ProcessName)) { return $false }
    $p = if ($Path) { $Path } else { '' }
    $n = if ($ProcessName) { $ProcessName } else { '' }
    foreach ($pat in $script:AuditAllowPatterns) {
        if ($pat -match '\|') {
            $parts = $pat -split '\|', 2
            $namePat = $parts[0]
            $pathPat = $parts[1]
            $nameOk = $n -and ($n -like $namePat)
            $pathOk = (-not $pathPat) -or ($p -like $pathPat)
            if ($nameOk -and $pathOk) { return $true }
        }
        else {
            if ($p -and ($p -like $pat)) { return $true }
            if ($n -and ($n -like $pat)) { return $true }
        }
    }
    return $false
}

function Test-AuditSuspiciousPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $low = $Path.ToLowerInvariant()
    $markers = @(
        '\temp\', '\tmp\', '\appdata\local\temp\',
        '\downloads\', '\recycle.bin\',
        '\appdata\roaming\', '\appdata\local\',
        '\users\public\'
    )
    foreach ($m in $markers) {
        if ($low.Contains($m)) {
            if ($low.Contains('\microsoft\') -and ($low.Contains('\appdata\local\') -or $low.Contains('\appdata\roaming\'))) {
                # keep flagging unsigned / script cases via caller
            }
            return $true
        }
    }
    if ($low.Contains('\programdata\') -and -not $low.Contains('\microsoft\') -and -not $low.Contains('\package cache\')) {
        return $true
    }
    return $false
}

function Get-AuditFileSignature {
    param([string]$FilePath)
    if ([string]::IsNullOrWhiteSpace($FilePath)) {
        return @{ Signed = $false; Status = 'NoPath'; Publisher = ''; Path = '' }
    }
    $clean = $FilePath.Trim().Trim('"')
    if ($clean -match '([A-Za-z]:\\[^"<>|]+\.(?:exe|dll|sys|scr|com|msi))') {
        $clean = $Matches[1]
    }
    $clean = [Environment]::ExpandEnvironmentVariables($clean)
    if ($script:AuditSignatureCache.ContainsKey($clean)) {
        return $script:AuditSignatureCache[$clean]
    }
    $result = @{ Signed = $false; Status = 'Missing'; Publisher = ''; Path = $clean }
    if (-not (Test-Path -LiteralPath $clean -PathType Leaf)) {
        $script:AuditSignatureCache[$clean] = $result
        return $result
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $clean -ErrorAction Stop
        $pub = ''
        if ($sig.SignerCertificate) { $pub = [string]$sig.SignerCertificate.Subject }
        $result = @{
            Signed    = ($sig.Status -eq 'Valid')
            Status    = [string]$sig.Status
            Publisher = $pub
            Path      = $clean
        }
    }
    catch {
        $result = @{ Signed = $false; Status = 'Error'; Publisher = ''; Path = $clean }
    }
    $script:AuditSignatureCache[$clean] = $result
    return $result
}

function Test-AuditMicrosoftPublisher {
    param([string]$Publisher)
    if ([string]::IsNullOrWhiteSpace($Publisher)) { return $false }
    return ($Publisher -match 'O=Microsoft Corporation') -or ($Publisher -match 'CN=Microsoft Windows')
}

function Get-AuditSeverityWeight {
    param([string]$Severity)
    # Per-finding weights (used with caps in Get-AuditScore — uncapped sum hits 0 on noisy scans).
    switch ($Severity) {
        'Critical' { 8 }
        'High'     { 3 }
        'Medium'   { 0.6 }
        'Low'      { 0.08 }
        default    { 0 }
    }
}

function Get-AuditScore {
    param(
        [object[]]$Findings,
        [object[]]$Chains = @()
    )
    # Capped penalties so hundreds of Low/Info findings don't force Score=0,
    # while Critical/High still dominate the health ring / label.
    $bySev = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($f in @($Findings)) {
        $sev = [string]$f.Severity
        if ($bySev.ContainsKey($sev)) { $bySev[$sev]++ }
    }
    $penalty = 0.0
    # 1 Critical → −20 (never "Sain"); 2 → −40; cap 55.
    $penalty += [Math]::Min(55.0, [double]$bySev.Critical * 20.0)
    $penalty += [Math]::Min(30.0, [double]$bySev.High * 5.0)
    $penalty += [Math]::Min(14.0, [double]$bySev.Medium * 0.4)
    $penalty += [Math]::Min(5.0,  [double]$bySev.Low * 0.05)
    $chainPenalty = 0.0
    foreach ($c in @($Chains)) {
        if ([int]$c.Confidence -ge 70) {
            $chainPenalty += [Math]::Min(6.0, [double]([int]$c.Confidence) / 15.0)
        }
    }
    $penalty += [Math]::Min(10.0, $chainPenalty)
    $score = [int][Math]::Round(100.0 - $penalty)
    if ($score -lt 0) { $score = 0 }
    if ($score -gt 100) { $score = 100 }
    $label = if ($score -ge 85) { 'Sain' }
        elseif ($score -ge 65) { 'Acceptable' }
        elseif ($score -ge 40) { 'Suspect' }
        else { 'Critique' }
    # Severity floors — Critical must dominate the health label.
    if ([int]$bySev.Critical -ge 3) { $label = 'Critique' }
    elseif ([int]$bySev.Critical -ge 1) {
        if ($label -in @('Sain', 'Acceptable')) { $label = 'Suspect' }
    }
    elseif ([int]$bySev.High -ge 5 -and $label -eq 'Sain') { $label = 'Acceptable' }
    [pscustomobject]@{
        Score      = $score
        Label      = $label
        BySeverity = $bySev
        Total      = @($Findings).Count
        Penalty    = [Math]::Round($penalty, 1)
    }
}

function Get-AuditCategoryStats {
    param([object[]]$Findings)
    $map = @{}
    foreach ($f in @($Findings)) {
        $cat = [string]$f.Category
        if (-not $map.ContainsKey($cat)) {
            $map[$cat] = [ordered]@{ Category = $cat; Count = 0; Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
        }
        $map[$cat].Count++
        $sev = [string]$f.Severity
        if ($map[$cat].Contains($sev)) { $map[$cat][$sev]++ }
    }
    @($map.Values) | Sort-Object Count -Descending
}

function Write-AuditProgress {
    param([string]$Phase, [int]$Percent, [string]$Detail = '')
    if (Get-Variable -Name AuditProgressCallback -Scope Global -ErrorAction SilentlyContinue) {
        try { & $Global:AuditProgressCallback $Phase $Percent $Detail } catch { }
    }
}

function Get-AuditGlobalProgressPercent {
    param([string]$Phase, [int]$Percent)
    $phaseWeight = @{
        Persistence = 0
        Runtime     = 14
        Reseau      = 28
        Devices     = 42
        Accounts    = 52
        Traces      = 60
        Surface     = 70
        Deduction   = 88
        Termine     = 100
    }
    if ($Phase -eq 'Termine') { return 100 }
    $base = 0
    if ($phaseWeight.ContainsKey($Phase)) { $base = [int]$phaseWeight[$Phase] }
    $span = 12
    switch ($Phase) {
        'Persistence' { $span = 14 }
        'Runtime'     { $span = 14 }
        'Reseau'      { $span = 14 }
        'Devices'     { $span = 10 }
        'Accounts'    { $span = 8 }
        'Traces'      { $span = 10 }
        'Surface'     { $span = 18 }
        'Deduction'   { $span = 12 }
    }
    $local = [Math]::Max(0, [Math]::Min(100, [int]$Percent))
    $v = $base + [int](($span * $local) / 100.0)
    return [Math]::Max(0, [Math]::Min(99, $v))
}

function Write-AuditScanProgressFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$Percent = 0,
        [string]$Phase = '',
        [string]$Detail = '',
        [bool]$Done = $false,
        [string]$ErrorMessage = $null
    )
    $obj = [ordered]@{
        percent = [int]$Percent
        phase   = [string]$Phase
        detail  = [string]$Detail
        done    = [bool]$Done
        error   = $ErrorMessage
        updatedAt = (Get-Date).ToString('o')
    }
    $json = ($obj | ConvertTo-Json -Compress)
    try {
        [System.IO.File]::WriteAllText($Path, $json, [System.Text.UTF8Encoding]::new($false))
    } catch { }
}

function Save-AuditAllowList {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$Patterns
    )
    $dir = Join-Path $Root 'lists'
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $path = Join-Path $dir 'audit-allow.txt'
    $header = @(
        '# WinAudit allowlist - un motif par ligne'
        '# Exemples: C:\Program Files\*\*  |  chrome|*\Google\Chrome\*'
        ''
    )
    $body = @($Patterns | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') })
    ($header + $body) | Set-Content -LiteralPath $path -Encoding UTF8
    Initialize-AuditCore -Root $Root
    return $path
}

function Get-AuditAllowListPatterns {
    param([string]$Root)
    $path = Join-Path $Root 'lists\audit-allow.txt'
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    return @(
        Get-Content -LiteralPath $path -Encoding UTF8 -ErrorAction SilentlyContinue |
            Where-Object { $_ -and $_.Trim() -and -not $_.Trim().StartsWith('#') } |
            ForEach-Object { $_.Trim() }
    )
}

function Export-AuditPrintReport {
    param(
        [Parameter(Mandatory)][string]$LogsDir,
        [Parameter(Mandatory)]$Result,
        [string]$Stamp = $(Get-Date -Format 'yyyyMMdd_HHmmss')
    )
    if (-not (Test-Path -LiteralPath $LogsDir)) {
        New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
    }
    $htmlPath = Join-Path $LogsDir ("winaudit-a4-{0}.html" -f $Stamp)
    $html = Build-AuditPrintHtmlReport -Result $Result
    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8
    return $htmlPath
}

function Build-AuditPrintHtmlReport {
    param($Result)
    $json = ($Result | ConvertTo-Json -Depth 10 -Compress) -replace '</', '<\/'
    $candidates = @()
    if ($script:AuditRoot) { $candidates += (Join-Path $script:AuditRoot 'ui\report-print.html') }
    if ($Global:WinAuditRoot) { $candidates += (Join-Path $Global:WinAuditRoot 'ui\report-print.html') }
    $candidates += (Join-Path $PSScriptRoot '..\ui\report-print.html')
    $templatePath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($templatePath) {
        $tpl = Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8
        return ($tpl.Replace('/*__WINAUDIT_DATA__*/', $json))
    }
    return "<html><body><h1>WinAudit A4</h1><p>Template manquant. Score=$($Result.Score.Score)</p></body></html>"
}

function Export-AuditReport {
    param(
        [Parameter(Mandatory)][string]$LogsDir,
        [Parameter(Mandatory)]$Result,
        [string]$Stamp = $(Get-Date -Format 'yyyyMMdd_HHmmss')
    )
    if (-not (Test-Path -LiteralPath $LogsDir)) {
        New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
    }
    $base = Join-Path $LogsDir ("winaudit-{0}" -f $Stamp)
    $jsonPath = "$base.json"
    $txtPath  = "$base.txt"
    $htmlPath = "$base.html"

    $Result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('WinAudit Pro - Rapport (lecture seule)')
    [void]$sb.AppendLine(("Date: {0}" -f $Result.GeneratedAt))
    [void]$sb.AppendLine(("Score: {0}/100 ({1})" -f $Result.Score.Score, $Result.Score.Label))
    [void]$sb.AppendLine(("Findings: {0} | Chaines: {1} | Connexions: {2}" -f @($Result.Findings).Count, @($Result.Chains).Count, @($Result.Connections).Count))
    if ($Result.Diff) {
        [void]$sb.AppendLine(("Diff: {0}" -f $Result.Diff.Summary))
    }
    if ($Result.Checklist) {
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine('=== CHECKLIST ESPIONNAGE ===')
        [void]$sb.AppendLine($Result.Checklist.Verdict)
        foreach ($it in @($Result.Checklist.Items)) {
            [void]$sb.AppendLine(("[{0}] {1} - {2}" -f $it.Status, $it.Question, $it.Detail))
        }
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== CONNEXIONS (suspectes / resume) ===')
    $connShow = @($Result.Connections) | Where-Object { $_.Risk -in @('Medium','High','Critical') } | Select-Object -First 40
    if (-not $connShow.Count) { $connShow = @($Result.Connections) | Select-Object -First 20 }
    foreach ($c in $connShow) {
        $remote = if ($c.Direction -eq 'Listen') { '-' } else { "{0}:{1}" -f $c.RemoteAddress, $c.RemotePort }
        [void]$sb.AppendLine(("[{0}] {1} {2} local={3}:{4} remote={5} est={6}" -f $c.Risk, $c.Direction, $c.ProcessName, $c.LocalAddress, $c.LocalPort, $remote, $c.Estimate))
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('=== CHAINES ===')
    foreach ($c in @($Result.Chains)) {
        [void]$sb.AppendLine(("[{0}] {1} (confiance {2}%)" -f $c.Severity, $c.Title, $c.Confidence))
        [void]$sb.AppendLine(("  {0}" -f $c.Narrative))
        foreach ($h in @($c.InvestigateHints)) { [void]$sb.AppendLine(("  -> {0}" -f $h)) }
        [void]$sb.AppendLine('')
    }
    [void]$sb.AppendLine('=== FINDINGS ===')
    $sorted = @($Result.Findings) | Sort-Object @{
        Expression = {
            switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
        }
    }, Category
    foreach ($f in $sorted) {
        [void]$sb.AppendLine(("[{0}][{1}] {2} - {3}" -f $f.Severity, $f.Category, $f.Id, $f.Title))
        if ($f.Path) { [void]$sb.AppendLine(("  Path: {0}" -f $f.Path)) }
        $hash = $null
        try {
            if ($f.Meta -and $f.Meta.Sha256) { $hash = $f.Meta.Sha256 }
            elseif ($f.Sha256) { $hash = $f.Sha256 }
        } catch { }
        if ($hash) { [void]$sb.AppendLine(("  SHA256: {0}" -f $hash)) }
        if ($f.Detail) { [void]$sb.AppendLine(("  {0}" -f $f.Detail)) }
        if ($f.WhySuspicious) { [void]$sb.AppendLine(("  Pourquoi: {0}" -f $f.WhySuspicious)) }
        [void]$sb.AppendLine('')
    }
    $sb.ToString() | Set-Content -LiteralPath $txtPath -Encoding UTF8

    $html = Build-AuditHtmlReport -Result $Result
    Set-Content -LiteralPath $htmlPath -Value $html -Encoding UTF8

    # Chart.js is referenced as vendor/chart.umd.min.js from the HTML file location (logs/).
    $chartSrc = $null
    if ($script:AuditRoot) { $chartSrc = Join-Path $script:AuditRoot 'ui\vendor\chart.umd.min.js' }
    if (-not $chartSrc -or -not (Test-Path -LiteralPath $chartSrc)) {
        $chartSrc = Join-Path $PSScriptRoot '..\ui\vendor\chart.umd.min.js'
    }
    if (Test-Path -LiteralPath $chartSrc) {
        $vendorDir = Join-Path $LogsDir 'vendor'
        if (-not (Test-Path -LiteralPath $vendorDir)) {
            New-Item -ItemType Directory -Path $vendorDir -Force | Out-Null
        }
        Copy-Item -LiteralPath $chartSrc -Destination (Join-Path $vendorDir 'chart.umd.min.js') -Force
    }

    [pscustomobject]@{ Json = $jsonPath; Txt = $txtPath; Html = $htmlPath }
}

function Build-AuditHtmlReport {
    param($Result)
    $json = ($Result | ConvertTo-Json -Depth 10 -Compress) -replace '</', '<\/'
    $candidates = @()
    if ($script:AuditRoot) { $candidates += (Join-Path $script:AuditRoot 'ui\report-template.html') }
    if ($Global:WinAuditRoot) { $candidates += (Join-Path $Global:WinAuditRoot 'ui\report-template.html') }
    $candidates += (Join-Path $PSScriptRoot '..\ui\report-template.html')
    $templatePath = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($templatePath) {
        $tpl = Get-Content -LiteralPath $templatePath -Raw -Encoding UTF8
        return ($tpl.Replace('/*__WINAUDIT_DATA__*/', $json))
    }
    return "<html><body><h1>WinAudit</h1><p>Template manquant. Score=$($Result.Score.Score)</p></body></html>"
}

