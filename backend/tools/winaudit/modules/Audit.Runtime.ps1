#Requires -Version 5.1
# Audit.Runtime.ps1 - Processus, typosquat, modules, users

function Get-AuditSystemProcessNames {
    @('svchost','csrss','lsass','services','winlogon','smss','wininit','dwm','explorer','RuntimeBroker','dllhost','conhost','sihost','taskhostw','SearchIndexer','MsMpEng','SecurityHealthService','fontdrvhost','ctfmon','WmiPrvSE','spoolsv','smartscreen')
}

function Test-AuditTyposquatName {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    $n = $Name.ToLowerInvariant() -replace '\.exe$',''
    $legit = Get-AuditSystemProcessNames
    foreach ($l in $legit) {
        $ll = $l.ToLowerInvariant()
        if ($n -eq $ll) { return $false }
        if ([Math]::Abs($n.Length - $ll.Length) -le 1 -and $n.Length -ge 4) {
            $same = 0
            $min = [Math]::Min($n.Length, $ll.Length)
            for ($i = 0; $i -lt $min; $i++) { if ($n[$i] -eq $ll[$i]) { $same++ } }
            if ($same -ge ($min - 1) -and $n -ne $ll) { return $true }
        }
    }
    return $false
}

function Invoke-AuditRuntimeScan {
    $findings = New-Object System.Collections.Generic.List[object]
    Write-AuditProgress -Phase 'Runtime' -Percent 10 -Detail 'Processus...'

    $procs = @()
    try {
        $procs = Get-CimInstance Win32_Process -ErrorAction Stop
    }
    catch {
        try { $procs = Get-Process -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{ Name = $_.ProcessName; ProcessId = $_.Id; ExecutablePath = $_.Path; ParentProcessId = $null; CommandLine = '' }
        } } catch { return $findings }
    }

    $byId = @{}
    foreach ($p in $procs) { $byId[[int]$p.ProcessId] = $p }

    $officeParents = @('WINWORD','EXCEL','OUTLOOK','POWERPNT','MSACCESS','ONENOTE')
    $i = 0
    foreach ($p in $procs) {
        $i++
        if ($i % 80 -eq 0) { Write-AuditProgress -Phase 'Runtime' -Percent (10 + [int](50 * $i / [Math]::Max(1,$procs.Count))) -Detail $p.Name }

        $name = [string]$p.Name
        $path = [string]$p.ExecutablePath
        $cmd = if ($p.PSObject.Properties.Name -contains 'CommandLine') { [string]$p.CommandLine } else { '' }
        $procId = [int]$p.ProcessId
        $ppid = if ($p.PSObject.Properties.Name -contains 'ParentProcessId') { [int]$p.ParentProcessId } else { 0 }

        if ([string]::IsNullOrWhiteSpace($path) -and $name -match '(?i)System|Idle|Registry') { continue }

        $baseName = ($name -replace '\.exe$','')
        $isSystemName = (Get-AuditSystemProcessNames) -contains $baseName
        $sig = Get-AuditFileSignature -FilePath $path
        $susPath = Test-AuditSuspiciousPath $path

        # System name outside System32
        if ($isSystemName -and $path -and -not ($path -match '(?i)\\windows\\(system32|syswow64)\\') -and -not ($baseName -eq 'explorer' -and $path -match '(?i)\\windows\\explorer\.exe$')) {
            $findings.Add((New-AuditFinding -Category 'Process' -Severity 'Critical' `
                -Title "Nom systeme hors System32: $name" `
                -Detail $cmd -Path $path -Evidence ("PID $procId") `
                -WhySuspicious 'Processus avec un nom Windows classique mais chemin inhabituel (masquerade).' `
                -Meta @{ ProcessName = $name; Pid = $procId }))
            continue
        }

        if (Test-AuditTyposquatName $name) {
            $findings.Add((New-AuditFinding -Category 'Process' -Severity 'High' `
                -Title "Nom proche d'un binaire systeme: $name" `
                -Detail $cmd -Path $path -Evidence ("PID $procId") `
                -WhySuspicious 'Typosquatting possible de nom de processus.' `
                -Meta @{ ProcessName = $name; Pid = $procId }))
        }

        if ($susPath) {
            if (Test-AuditAllowed -Path $path -ProcessName $name) {
                # still flag unsigned in temp
                if ($sig.Signed) { continue }
            }
            $sev = if ($sig.Signed) { 'Medium' } else { 'High' }
            $findings.Add((New-AuditFinding -Category 'Process' -Severity $sev `
                -Title "Processus depuis emplacement sensible: $name" `
                -Detail $cmd -Path $path -Evidence ("PID $procId") `
                -WhySuspicious 'Executable lance depuis Temp/AppData/Downloads.' `
                -Meta @{ ProcessName = $name; Pid = $procId }))
        }

        if ($cmd -match '(?i)powershell.*(-enc|encodedcommand|bypass|hidden|noprofile)|downloadstring|invoke-expression|iex\(|frombase64string') {
            $findings.Add((New-AuditFinding -Category 'Process' -Severity 'Critical' `
                -Title "PowerShell encode / bypass: $name" `
                -Detail $cmd -Path $path -Evidence ("PID $procId") `
                -WhySuspicious 'Ligne de commande PowerShell typique d''attaque.' `
                -Meta @{ ProcessName = $name; Pid = $procId }))
        }

        # Parent-child: Office -> shell
        if ($ppid -and $byId.ContainsKey($ppid)) {
            $parent = $byId[$ppid]
            $pname = ([string]$parent.Name) -replace '\.exe$',''
            if ($officeParents -contains $pname.ToUpperInvariant()) {
                if ($baseName -match '(?i)^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin|certutil)$') {
                    $findings.Add((New-AuditFinding -Category 'Process' -Severity 'Critical' `
                        -Title "Office a lance $name" `
                        -Detail ("Parent={0} ({1}) Child={2}" -f $pname, $ppid, $cmd) `
                        -Path $path -Evidence ("PID $procId parent $ppid") `
                        -WhySuspicious 'Parent Office inhabituel - macro / exploitation document possible.' `
                        -Meta @{ ProcessName = $name; Pid = $procId; Parent = $pname }))
                }
            }
        }
    }

    Write-AuditProgress -Phase 'Runtime' -Percent 70 -Detail 'Modules (echantillon)...'
    # Sample modules for high-risk processes only (perf)
    $sample = @($findings | Where-Object { $_.Category -eq 'Process' -and $_.Severity -in @('High','Critical') } | Select-Object -First 12)
    foreach ($f in $sample) {
        $spid = 0
        if ($f.Meta -and $f.Meta.Pid) { $spid = [int]$f.Meta.Pid }
        if ($spid -le 0) { continue }
        try {
            $proc = Get-Process -Id $spid -ErrorAction Stop
            foreach ($m in @($proc.Modules | Select-Object -First 40)) {
                $mp = [string]$m.FileName
                if (-not $mp) { continue }
                if ($mp -match '(?i)\\windows\\') { continue }
                $ms = Get-AuditFileSignature -FilePath $mp
                if (-not $ms.Signed -and (Test-AuditSuspiciousPath $mp)) {
                    $findings.Add((New-AuditFinding -Category 'Process' -Severity 'High' `
                        -Title "DLL non signee chargee: $($m.ModuleName)" `
                        -Detail ("Dans PID {0} ({1})" -f $spid, $f.Meta.ProcessName) `
                        -Path $mp -Evidence ("PID $spid") `
                        -WhySuspicious 'Module non signe depuis emplacement sensible.'))
                }
            }
        }
        catch { }
    }

    Write-AuditProgress -Phase 'Runtime' -Percent 85 -Detail 'Comptes locaux...'
    try {
        $admins = Get-LocalGroupMember -Group 'Administrateurs' -ErrorAction SilentlyContinue
        if (-not $admins) { $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue }
        foreach ($a in @($admins)) {
            $an = [string]$a.Name
            if ($an -match '(?i)\\Administrator$' -or $an -match '(?i)\\Domain Admins' -or $an -match '(?i)NT AUTHORITY') { continue }
            # Flag recently created local users that are admin - best effort
            $findings.Add((New-AuditFinding -Category 'Account' -Severity 'Info' `
                -Title "Membre Administrateurs: $an" `
                -Detail ([string]$a.PrincipalSource) -Evidence $an `
                -WhySuspicious 'Inventaire des admins - a valider manuellement.'))
        }
        Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { $_.Enabled } | ForEach-Object {
            if ($_.PasswordRequired -eq $false) {
                $findings.Add((New-AuditFinding -Category 'Account' -Severity 'Medium' `
                    -Title "Compte sans mot de passe: $($_.Name)" `
                    -Evidence $_.Name -WhySuspicious 'Compte local actif sans mot de passe requis.'))
            }
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Runtime' -Percent 95 -Detail 'Runtime OK'
    return $findings
}
