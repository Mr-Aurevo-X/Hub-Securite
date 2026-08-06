#Requires -Version 5.1
# Audit.Hash.ps1 - SHA256 des binaires suspects

$script:AuditHashCache = @{}

function Get-AuditFileSha256 {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $clean = $Path.Trim().Trim('"')
    if ($clean -match '([A-Za-z]:\\[^"<>|]+\.(?:exe|dll|sys|scr|com))') {
        $clean = $Matches[1]
    }
    $clean = [Environment]::ExpandEnvironmentVariables($clean)
    if ($script:AuditHashCache.ContainsKey($clean)) {
        return $script:AuditHashCache[$clean]
    }
    if (-not (Test-Path -LiteralPath $clean -PathType Leaf)) {
        $script:AuditHashCache[$clean] = ''
        return ''
    }
    try {
        $h = Get-FileHash -LiteralPath $clean -Algorithm SHA256 -ErrorAction Stop
        $script:AuditHashCache[$clean] = [string]$h.Hash
        return [string]$h.Hash
    }
    catch {
        $script:AuditHashCache[$clean] = ''
        return ''
    }
}

function Add-AuditSha256ToFindings {
    param([object[]]$Findings)
    $script:AuditHashCache = @{}
    $n = 0
    foreach ($f in @($Findings)) {
        if ($f.Severity -notin @('High','Critical')) { continue }
        $p = [string]$f.Path
        if (-not $p) { continue }
        if ($p -notmatch '(?i)\.(exe|dll|sys|scr|com)(\s|"|$)') { continue }
        $hash = Get-AuditFileSha256 -Path $p
        if (-not $hash) { continue }
        $n++
        if (-not $f.Meta) { $f | Add-Member -NotePropertyName Meta -NotePropertyValue @{} -Force }
        # Meta may be PSCustomObject from earlier - use hashtable-like add
        try {
            if ($f.Meta -is [hashtable]) {
                $f.Meta['Sha256'] = $hash
            }
            else {
                $f.Meta | Add-Member -NotePropertyName Sha256 -NotePropertyValue $hash -Force
            }
        }
        catch {
            $f | Add-Member -NotePropertyName Sha256 -NotePropertyValue $hash -Force
        }
        if ($f.Evidence -and $f.Evidence -notmatch $hash) {
            $f.Evidence = ("{0} | SHA256={1}" -f $f.Evidence, $hash)
        }
        elseif (-not $f.Evidence) {
            $f.Evidence = ("SHA256={0}" -f $hash)
        }
        if ($n -ge 40) { break }  # budget
    }
    return $Findings
}

function Add-AuditSha256ToConnections {
    param([object[]]$Connections)
    $n = 0
    foreach ($c in @($Connections)) {
        if ($c.Risk -notin @('Medium','High','Critical')) { continue }
        $p = [string]$c.Path
        if (-not $p -or $p -notmatch '(?i)\.(exe|dll)$') { continue }
        $hash = Get-AuditFileSha256 -Path $p
        if (-not $hash) { continue }
        $c | Add-Member -NotePropertyName Sha256 -NotePropertyValue $hash -Force
        $n++
        if ($n -ge 30) { break }
    }
    return $Connections
}
