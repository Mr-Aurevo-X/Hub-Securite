# Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X

#Requires -Version 5.1
# Audit.Persistence.ps1 - Run keys, Startup, Tasks, Services, WMI, IFEO, etc.

function Get-AuditRunKeyFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($k in $keys) {
        if (-not (Test-Path -LiteralPath $k)) { continue }
        try {
            $props = Get-ItemProperty -LiteralPath $k -ErrorAction Stop
            foreach ($p in $props.PSObject.Properties) {
                if ($p.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')) { continue }
                $val = [string]$p.Value
                if ([string]::IsNullOrWhiteSpace($val)) { continue }
                $sig = Get-AuditFileSignature -FilePath $val
                $susPath = Test-AuditSuspiciousPath $sig.Path
                if (Test-AuditAllowed -Path $sig.Path) {
                    if ($sig.Signed -and (Test-AuditMicrosoftPublisher $sig.Publisher)) { continue }
                    if ($sig.Signed -and -not $susPath) { continue }
                }
                $sev = 'Low'
                $why = "Entree de demarrage automatique ($k)."
                if ($susPath) { $sev = 'High'; $why = 'Chemin dans Temp/AppData/Downloads - persistence suspecte.' }
                if (-not $sig.Signed) { if ($sev -eq 'Low') { $sev = 'Medium' }; $why += ' Binaire non signe / introuvable.' }
                if ($val -match '(?i)powershell|wscript|cscript|mshta|cmd\.exe|/c |bypass|-enc') {
                    $sev = 'Critical'
                    $why = 'Commande d''interpreteur / encodee au demarrage.'
                }
                $findings.Add((New-AuditFinding -Category 'Startup' -Severity $sev -Title "Run: $($p.Name)" `
                    -Detail $val -Path $sig.Path -Evidence $k -WhySuspicious $why `
                    -Meta @{ Name = $p.Name; Hive = $k }))
            }
        }
        catch { }
    }
    return $findings
}

function Get-AuditStartupFolderFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    $dirs = @(
        [Environment]::GetFolderPath('Startup'),
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue | ForEach-Object {
            $target = $_.FullName
            $args = ''
            if ($_.Extension -eq '.lnk') {
                try {
                    $sh = New-Object -ComObject WScript.Shell
                    $lnk = $sh.CreateShortcut($_.FullName)
                    $target = $lnk.TargetPath
                    $args = [string]$lnk.Arguments
                }
                catch { }
            }
            $sig = Get-AuditFileSignature -FilePath $target
            if (Test-AuditAllowed -Path $sig.Path) {
                if ($sig.Signed) { return }
            }
            $sev = 'Low'
            $why = 'Raccourci / fichier dans le dossier Startup.'
            if (Test-AuditSuspiciousPath $sig.Path) { $sev = 'High'; $why = 'Cible Startup dans un dossier utilisateur sensible.' }
            if (-not $sig.Signed) { $sev = 'Medium' }
            if ($args -match '(?i)powershell|hidden|bypass|-enc|http') { $sev = 'Critical'; $why = 'Arguments Startup suspects.' }
            $findings.Add((New-AuditFinding -Category 'Startup' -Severity $sev -Title "Startup: $($_.Name)" `
                -Detail ("Target={0} Args={1}" -f $target, $args) -Path $sig.Path -Evidence $_.FullName `
                -WhySuspicious $why))
        }
    }
    return $findings
}

function Get-AuditScheduledTaskFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' }
    }
    catch { return $findings }

    $i = 0
    foreach ($t in $tasks) {
        $i++
        if ($i % 40 -eq 0) { Write-AuditProgress -Phase 'Persistence' -Percent 25 -Detail "Taches: $($t.TaskName)" }
        $taskPath = $t.TaskPath + $t.TaskName
        if ($taskPath -match '\\Microsoft\\' -or $taskPath -match '\\Windows\\') {
            # still inspect odd actions
        }
        try {
            $info = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
            foreach ($a in @($t.Actions)) {
                $exe = [string]$a.Execute
                $arg = [string]$a.Arguments
                $full = "$exe $arg".Trim()
                if ([string]::IsNullOrWhiteSpace($exe)) { continue }
                $sig = Get-AuditFileSignature -FilePath $exe
                $sus = Test-AuditSuspiciousPath $sig.Path
                $lol = $full -match '(?i)powershell.*(enc|bypass|hidden|nop)|mshta|wscript|cscript|cmd\.exe\s+/c|bitsadmin|certutil|frombase64|downloadstring|invoke-webrequest|curl\.exe|wget'
                $msTask = ($taskPath -match '\\Microsoft\\') -or ($taskPath -match '\\Windows\\')

                if ($msTask -and -not $sus -and -not $lol -and $sig.Signed) { continue }
                if (-not $sus -and -not $lol -and $sig.Signed -and (Test-AuditAllowed -Path $sig.Path)) { continue }

                $sev = 'Low'
                $why = 'Tache planifiee hors profil Microsoft classique ou chemin inhabituel.'
                if ($sus) { $sev = 'High'; $why = 'Action de tache depuis Temp/AppData/Downloads.' }
                if ($lol) { $sev = 'Critical'; $why = 'Action de tache avec LOLBin / script encode.' }
                if (-not $sig.Signed -and -not $msTask) { if ($sev -eq 'Low') { $sev = 'Medium' } }

                $findings.Add((New-AuditFinding -Category 'ScheduledTask' -Severity $sev `
                    -Title "Tache: $($t.TaskName)" `
                    -Detail $full -Path $sig.Path -Evidence $taskPath `
                    -WhySuspicious $why `
                    -Meta @{ TaskPath = $taskPath; LastRun = [string]$info.LastRunTime }))
            }
        }
        catch { }
    }
    return $findings
}

function Get-AuditServiceFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction Stop
    }
    catch { return $findings }

    foreach ($s in $svcs) {
        $path = [string]$s.PathName
        if ([string]::IsNullOrWhiteSpace($path)) { continue }
        $sig = Get-AuditFileSignature -FilePath $path
        $sus = Test-AuditSuspiciousPath $sig.Path
        $sys = $sig.Path -match '(?i)\\windows\\(system32|syswow64)\\'
        if ($sys -and $sig.Signed -and -not $sus) { continue }
        if ((Test-AuditAllowed -Path $sig.Path) -and $sig.Signed -and -not $sus) { continue }

        $sev = 'Low'
        $why = 'Service hors emplacements systeme classiques ou signature douteuse.'
        if ($sus) { $sev = 'High'; $why = 'Binaire de service dans un dossier utilisateur / temp.' }
        if (-not $sig.Signed) { if ($sev -eq 'Low') { $sev = 'Medium' }; $why += ' Non signe.' }
        if ($s.StartMode -eq 'Auto' -and $sus) { $sev = 'Critical' }

        $findings.Add((New-AuditFinding -Category 'Service' -Severity $sev `
            -Title "Service: $($s.Name)" `
            -Detail ("State={0} Start={1} Path={2}" -f $s.State, $s.StartMode, $path) `
            -Path $sig.Path -Evidence $s.Name -WhySuspicious $why `
            -Meta @{ ServiceName = $s.Name; DisplayName = $s.DisplayName }))
    }
    return $findings
}

function Get-AuditWmiPersistenceFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    try {
        $filters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue
        $consumers = @()
        $consumers += @(Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue)
        $consumers += @(Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue)
        $bindings = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue

        foreach ($c in $consumers) {
            $cmd = ''
            if ($c.PSObject.Properties.Name -contains 'CommandLineTemplate') { $cmd = [string]$c.CommandLineTemplate }
            if ($c.PSObject.Properties.Name -contains 'ScriptText') { $cmd = [string]$c.ScriptText }
            if ($c.PSObject.Properties.Name -contains 'ScriptFileName') { $cmd = [string]$c.ScriptFileName }
            $name = [string]$c.Name
            if ($name -match '(?i)BVTConsumer|SCM Event') { continue }
            $sev = 'High'
            if ($cmd -match '(?i)powershell|cmd|http|temp|appdata|download') { $sev = 'Critical' }
            $findings.Add((New-AuditFinding -Category 'WMI' -Severity $sev `
                -Title "WMI Consumer: $name" `
                -Detail $cmd -Path $cmd -Evidence 'root\subscription' `
                -WhySuspicious 'Abonnement WMI - persistence furtive possible.'))
        }
        foreach ($b in @($bindings)) {
            $findings.Add((New-AuditFinding -Category 'WMI' -Severity 'Medium' `
                -Title 'WMI Filter-Consumer Binding' `
                -Detail ([string]$b.Filter + ' -> ' + [string]$b.Consumer) `
                -Evidence 'root\subscription' `
                -WhySuspicious 'Liaison WMI active (verifier legitimite).'))
        }
        foreach ($f in @($filters)) {
            if ([string]$f.Name -match '(?i)BVTFilter|SCM Event') { continue }
            $findings.Add((New-AuditFinding -Category 'WMI' -Severity 'Low' `
                -Title "WMI Filter: $($f.Name)" `
                -Detail ([string]$f.Query) -Evidence 'root\subscription' `
                -WhySuspicious 'Filtre d''evenement WMI present.'))
        }
    }
    catch { }
    return $findings
}

function Get-AuditIfeoFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (-not (Test-Path -LiteralPath $base)) { return $findings }
    Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $dbg = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).Debugger
            if ($dbg) {
                $findings.Add((New-AuditFinding -Category 'IFEO' -Severity 'Critical' `
                    -Title "IFEO Debugger: $($_.PSChildName)" `
                    -Detail ([string]$dbg) -Path ([string]$dbg) -Evidence $_.PSPath `
                    -WhySuspicious 'Debugger IFEO - technique classique de hijack de processus.'))
            }
        }
        catch { }
    }
    return $findings
}

function Get-AuditAppInitFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
    )
    foreach ($p in $paths) {
        if (-not (Test-Path -LiteralPath $p)) { continue }
        try {
            $item = Get-ItemProperty -LiteralPath $p -ErrorAction Stop
            $dlls = [string]$item.AppInit_DLLs
            if ($dlls -and $dlls.Trim()) {
                $findings.Add((New-AuditFinding -Category 'IFEO' -Severity 'Critical' `
                    -Title 'AppInit_DLLs non vide' `
                    -Detail $dlls -Path $dlls -Evidence $p `
                    -WhySuspicious 'Injection DLL globale via AppInit_DLLs.'))
            }
        }
        catch { }
    }
    return $findings
}

function Get-AuditWinlogonFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    $p = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    if (-not (Test-Path -LiteralPath $p)) { return $findings }
    try {
        $w = Get-ItemProperty -LiteralPath $p
        $shell = [string]$w.Shell
        $userinit = [string]$w.Userinit
        if ($shell -and $shell -notmatch '(?i)^explorer\.exe\s*$') {
            $findings.Add((New-AuditFinding -Category 'Winlogon' -Severity 'Critical' `
                -Title 'Winlogon Shell modifie' -Detail $shell -Path $shell -Evidence $p `
                -WhySuspicious 'Le shell de session n''est pas explorer.exe.'))
        }
        if ($userinit -and $userinit -notmatch '(?i)userinit\.exe') {
            $findings.Add((New-AuditFinding -Category 'Winlogon' -Severity 'Critical' `
                -Title 'Winlogon Userinit inhabituel' -Detail $userinit -Path $userinit -Evidence $p `
                -WhySuspicious 'Userinit ne pointe pas vers userinit.exe standard.'))
        }
        elseif ($userinit -match ',') {
            $findings.Add((New-AuditFinding -Category 'Winlogon' -Severity 'High' `
                -Title 'Winlogon Userinit multi-valeurs' -Detail $userinit -Evidence $p `
                -WhySuspicious 'Userinit contient plusieurs entrees (souvent persistence).'))
        }
    }
    catch { }
    return $findings
}

function Get-AuditBitsFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    try {
        $jobs = Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue
        foreach ($j in @($jobs)) {
            $sev = 'Medium'
            $remote = [string]$j.RemoteName
            $local = [string]$j.LocalName
            if ($remote -match '(?i)http' -or (Test-AuditSuspiciousPath $local)) { $sev = 'High' }
            $findings.Add((New-AuditFinding -Category 'BITS' -Severity $sev `
                -Title "BITS job: $($j.DisplayName)" `
                -Detail ("Remote={0} Local={1} State={2}" -f $remote, $local, $j.JobState) `
                -Path $local -Evidence ([string]$j.JobId) `
                -WhySuspicious 'Job BITS persistant - parfois utilise pour telecharger / executer du code.'))
        }
    }
    catch { }
    return $findings
}

function Get-AuditLsaFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    $p = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    if (-not (Test-Path -LiteralPath $p)) { return $findings }
    try {
        $lsa = Get-ItemProperty -LiteralPath $p
        foreach ($name in @('Authentication Packages','Security Packages','Notification Packages')) {
            $val = $lsa.$name
            if (-not $val) { continue }
            $text = if ($val -is [array]) { $val -join ', ' } else { [string]$val }
            # Flag non-default-looking paths
            if ($text -match '(?i)\\|temp|appdata|\.dll') {
                $findings.Add((New-AuditFinding -Category 'LSA' -Severity 'High' `
                    -Title "LSA: $name" -Detail $text -Evidence $p `
                    -WhySuspicious 'Package LSA personnalise - verifier legitimite (auth/security).'))
            }
        }
    }
    catch { }
    return $findings
}

function Get-AuditComFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    $roots = @(
        'HKLM:\SOFTWARE\Classes\CLSID',
        'HKCU:\SOFTWARE\Classes\CLSID'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        try {
            # Sample CLSID keys (full enumerate is huge) - focus on ones with Inproc/LocalServer
            $keys = @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue | Select-Object -First 400)
            foreach ($k in $keys) {
                foreach ($sub in @('InprocServer32','LocalServer32')) {
                    $p = Join-Path $k.PSPath $sub
                    if (-not (Test-Path -LiteralPath $p)) { continue }
                    try {
                        $def = (Get-ItemProperty -LiteralPath $p -ErrorAction SilentlyContinue).'(default)'
                        if (-not $def) { continue }
                        $path = [string]$def.Trim('"')
                        if ($path -notmatch '(?i)\.(dll|exe|ocx)$' -and $path -notmatch '(?i)^[a-z]:\\') { continue }
                        if (-not (Test-AuditSuspiciousPath $path)) { continue }
                        if (Test-AuditAllowed -Path $path) { continue }
                        $sev = if ($path -match '(?i)\\temp\\|\\downloads\\') { 'High' } else { 'Medium' }
                        $findings.Add((New-AuditFinding -Category 'COM' -Severity $sev `
                            -Title ("COM $sub -> zone sensible") `
                            -Detail $path -Path $path -Evidence $k.PSChildName `
                            -WhySuspicious 'Serveur COM pointant vers Temp/AppData/Downloads - technique de hijack COM classique.' `
                            -Meta @{ Clsid = $k.PSChildName; Server = $sub }))
                    }
                    catch { }
                }
            }
        }
        catch { }
    }
    return $findings
}

function Get-AuditShellFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers',
        'Registry::HKEY_CLASSES_ROOT\*\shellex\ContextMenuHandlers',
        'Registry::HKEY_CLASSES_ROOT\Directory\shellex\ContextMenuHandlers',
        'Registry::HKEY_CLASSES_ROOT\Directory\Background\shellex\ContextMenuHandlers',
        'Registry::HKEY_CLASSES_ROOT\exefile\shellex\ContextMenuHandlers'
    )
    foreach ($base in $paths) {
        if (-not (Test-Path -LiteralPath $base)) { continue }
        try {
            Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
                $name = [string]$_.PSChildName
                if ($name -match '(?i)^(Sharing|Offline Files|Dropbox|OneDrive|GoogleDrive|iCloud|Box|Sync|Adobe|Microsoft|Windows|EnhancedStorage)') { return }
                $clsid = ''
                try {
                    $clsid = [string](Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).'(default)'
                } catch { }
                $findings.Add((New-AuditFinding -Category 'Shell' -Severity 'Low' `
                    -Title ("Shell extension: $name") `
                    -Detail $clsid -Evidence $_.PSPath `
                    -WhySuspicious 'Extension shell / overlay hors editeurs courants - verifier legitimite.' `
                    -Meta @{ Name = $name; Clsid = $clsid }))
            }
        }
        catch { }
    }
    return $findings
}

function Invoke-AuditPersistenceScan {
    Write-AuditProgress -Phase 'Persistence' -Percent 5 -Detail 'Run keys...'
    $all = New-Object System.Collections.Generic.List[object]
    foreach ($f in @(Get-AuditRunKeyFindings)) { $all.Add($f) }
    Write-AuditProgress -Phase 'Persistence' -Percent 12 -Detail 'Startup folders...'
    foreach ($f in @(Get-AuditStartupFolderFindings)) { $all.Add($f) }
    Write-AuditProgress -Phase 'Persistence' -Percent 20 -Detail 'Scheduled tasks...'
    foreach ($f in @(Get-AuditScheduledTaskFindings)) { $all.Add($f) }
    Write-AuditProgress -Phase 'Persistence' -Percent 40 -Detail 'Services...'
    foreach ($f in @(Get-AuditServiceFindings)) { $all.Add($f) }
    Write-AuditProgress -Phase 'Persistence' -Percent 52 -Detail 'WMI...'
    foreach ($f in @(Get-AuditWmiPersistenceFindings)) { $all.Add($f) }
    Write-AuditProgress -Phase 'Persistence' -Percent 60 -Detail 'IFEO / AppInit...'
    foreach ($f in @(Get-AuditIfeoFindings)) { $all.Add($f) }
    foreach ($f in @(Get-AuditAppInitFindings)) { $all.Add($f) }
    Write-AuditProgress -Phase 'Persistence' -Percent 70 -Detail 'Winlogon / LSA / BITS...'
    foreach ($f in @(Get-AuditWinlogonFindings)) { $all.Add($f) }
    foreach ($f in @(Get-AuditLsaFindings)) { $all.Add($f) }
    foreach ($f in @(Get-AuditBitsFindings)) { $all.Add($f) }
    Write-AuditProgress -Phase 'Persistence' -Percent 82 -Detail 'COM / Shell...'
    foreach ($f in @(Get-AuditComFindings)) { $all.Add($f) }
    foreach ($f in @(Get-AuditShellFindings)) { $all.Add($f) }
    Write-AuditProgress -Phase 'Persistence' -Percent 90 -Detail 'Persistence OK'
    return $all
}
