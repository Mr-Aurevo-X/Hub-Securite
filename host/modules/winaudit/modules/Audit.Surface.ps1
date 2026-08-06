#Requires -Version 5.1
# Audit.Surface.ps1 - Defender, certs, software, browsers, shadow, events, disk

function Invoke-AuditSurfaceScan {
    $findings = New-Object System.Collections.Generic.List[object]

    Write-AuditProgress -Phase 'Surface' -Percent 8 -Detail 'Windows Defender...'
    try {
        $mp = Get-MpPreference -ErrorAction SilentlyContinue
        $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($status -and $status.RealTimeProtectionEnabled -eq $false) {
            $findings.Add((New-AuditFinding -Category 'Defender' -Severity 'Critical' `
                -Title 'Protection en temps reel desactivee' `
                -Evidence 'RealTimeProtectionEnabled=False' `
                -WhySuspicious 'Defender realtime off - machine moins protegee.'))
        }
        if ($status -and $status.AntivirusEnabled -eq $false) {
            $findings.Add((New-AuditFinding -Category 'Defender' -Severity 'Critical' `
                -Title 'Antivirus desactive' `
                -Evidence 'AntivirusEnabled=False' `
                -WhySuspicious 'Moteur antivirus inactif.'))
        }
        if ($mp) {
            foreach ($x in @($mp.ExclusionPath)) {
                if (-not $x) { continue }
                $sev = if (Test-AuditSuspiciousPath $x) { 'Critical' } else { 'Medium' }
                $findings.Add((New-AuditFinding -Category 'Defender' -Severity $sev `
                    -Title "Exclusion Defender (chemin): $x" `
                    -Path $x -Evidence 'ExclusionPath' `
                    -WhySuspicious 'Dossier exclus du scan - utile aux malware s''ils controlent les exclusions.'))
            }
            foreach ($x in @($mp.ExclusionProcess)) {
                if (-not $x) { continue }
                $findings.Add((New-AuditFinding -Category 'Defender' -Severity 'High' `
                    -Title "Exclusion Defender (process): $x" `
                    -Detail $x -Evidence 'ExclusionProcess' `
                    -WhySuspicious 'Processus exclus de Defender.'))
            }
            foreach ($x in @($mp.ExclusionExtension)) {
                if (-not $x) { continue }
                if ($x -match '(?i)exe|dll|ps1|js|vbs|bat|cmd|scr') {
                    $findings.Add((New-AuditFinding -Category 'Defender' -Severity 'Critical' `
                        -Title "Exclusion Defender (ext): $x" `
                        -Evidence 'ExclusionExtension' `
                        -WhySuspicious 'Extension dangereuse exclue du scan.'))
                }
            }
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Surface' -Percent 25 -Detail 'Certificats racine (echantillon)...'
    try {
        $roots = Get-ChildItem Cert:\LocalMachine\Root -ErrorAction SilentlyContinue
        $infoCount = 0
        foreach ($c in @($roots)) {
            $subj = [string]$c.Subject
            $simple = try { $c.GetNameInfo('SimpleName', $false) } catch { $subj }
            if ($c.NotAfter -lt (Get-Date)) {
                $findings.Add((New-AuditFinding -Category 'Certificate' -Severity 'Medium' `
                    -Title "Certificat racine expire: $simple" `
                    -Detail $subj -Evidence $c.Thumbprint `
                    -WhySuspicious 'Certificat racine expire encore present.'))
                continue
            }
            if ($subj -match '(?i)Microsoft|VeriSign|DigiCert|GlobalSign|Google|Amazon|USERTrust|ISRG|Comodo|Sectigo|Baltimore|GTE|Thawte|Entrust|IdenTrust|Starfield|Go Daddy|Apple|Certum|Symantec|GeoTrust|AffirmTrust|Cybertrust|SecureTrust') { continue }
            if ($infoCount -ge 12) { continue }
            $infoCount++
            $findings.Add((New-AuditFinding -Category 'Certificate' -Severity 'Info' `
                -Title "Certificat racine tiers: $simple" `
                -Detail $subj -Evidence $c.Thumbprint `
                -WhySuspicious 'Inventaire - verifier si editeur attendu.'))
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Surface' -Percent 40 -Detail 'Logiciels recents...'
    try {
        $uninstall = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
        $cutoff = (Get-Date).AddDays(-14)
        foreach ($pattern in $uninstall) {
            Get-ItemProperty $pattern -ErrorAction SilentlyContinue | ForEach-Object {
                $name = [string]$_.DisplayName
                if (-not $name) { return }
                $dateRaw = [string]$_.InstallDate
                $dt = $null
                if ($dateRaw -match '^\d{8}$') {
                    try { $dt = [datetime]::ParseExact($dateRaw, 'yyyyMMdd', $null) } catch { }
                }
                $loc = [string]$_.InstallLocation
                if ($dt -and $dt -gt $cutoff) {
                    $sev = 'Info'
                    if (Test-AuditSuspiciousPath $loc) { $sev = 'Medium' }
                    $findings.Add((New-AuditFinding -Category 'Software' -Severity $sev `
                        -Title "Install recent: $name" `
                        -Detail ("InstallDate={0} Publisher={1}" -f $dateRaw, $_.Publisher) `
                        -Path $loc -Evidence $name `
                        -WhySuspicious 'Logiciel installe dans les 14 derniers jours.'))
                }
            }
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Surface' -Percent 55 -Detail 'Extensions navigateur...'
    $browserExtRoots = @(
        @{ Name = 'Chrome'; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions" },
        @{ Name = 'Edge'; Path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions" },
        @{ Name = 'Firefox'; Path = "$env:APPDATA\Mozilla\Firefox\Profiles" }
    )
    foreach ($b in $browserExtRoots) {
        if (-not (Test-Path -LiteralPath $b.Path)) { continue }
        if ($b.Name -eq 'Firefox') {
            Get-ChildItem -LiteralPath $b.Path -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $extDir = Join-Path $_.FullName 'extensions'
                if (Test-Path -LiteralPath $extDir) {
                    $count = @(Get-ChildItem -LiteralPath $extDir -ErrorAction SilentlyContinue).Count
                    if ($count -gt 0) {
                        $findings.Add((New-AuditFinding -Category 'Browser' -Severity 'Info' `
                            -Title "Firefox extensions ($count) - $($_.Name)" `
                            -Path $extDir -Evidence $b.Name `
                            -WhySuspicious 'Inventaire extensions - verifier manuellement les add-ons inconnus.'))
                    }
                }
            }
            continue
        }
        Get-ChildItem -LiteralPath $b.Path -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $id = $_.Name
            # Chromium extension IDs are 32 chars
            $sev = 'Info'
            $manifest = Get-ChildItem -LiteralPath $_.FullName -Filter manifest.json -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
            $detail = $id
            if ($manifest) {
                try {
                    $json = Get-Content -LiteralPath $manifest.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
                    $detail = [string]$json.name
                    if ($json.permissions -match 'webRequest|tabs|<all_urls>|cookies') { $sev = 'Low' }
                }
                catch { }
            }
            $findings.Add((New-AuditFinding -Category 'Browser' -Severity $sev `
                -Title "$($b.Name) extension: $detail" `
                -Detail $id -Path $_.FullName -Evidence $b.Name `
                -WhySuspicious 'Extension navigateur presente - controler la legitimite.'))
        }
    }

    Write-AuditProgress -Phase 'Surface' -Percent 70 -Detail 'Shadow copies...'
    try {
        $shadows = @(Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue)
        if ($shadows.Count -eq 0) {
            $findings.Add((New-AuditFinding -Category 'Hygiene' -Severity 'Medium' `
                -Title 'Aucune copie d''ombre (VSS) detectee' `
                -Evidence 'Win32_ShadowCopy' `
                -WhySuspicious 'Pas de shadow copy - restauration / forensics limites (peut etre normal).'))
        }
    }
    catch {
        $findings.Add((New-AuditFinding -Category 'Hygiene' -Severity 'Info' `
            -Title 'Impossible de lister les shadow copies' `
            -WhySuspicious 'Acces VSS refuse ou indisponible.'))
    }

    Write-AuditProgress -Phase 'Surface' -Percent 80 -Detail 'Event logs (echantillon)...'
    $since = (Get-Date).AddDays(-3)
    try {
        # New service installs
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $since } -MaxEvents 25 -ErrorAction SilentlyContinue |
            ForEach-Object {
                $msg = $_.Message
                $findings.Add((New-AuditFinding -Category 'EventLog' -Severity 'Medium' `
                    -Title 'Nouveau service installe (7045)' `
                    -Detail ($msg.Substring(0, [Math]::Min(300, $msg.Length))) `
                    -Evidence $_.TimeCreated.ToString('o') `
                    -WhySuspicious 'Installation de service recente - verifier le binaire.'))
            }
    }
    catch { }
    try {
        Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $since } -MaxEvents 15 -ErrorAction SilentlyContinue |
            ForEach-Object {
                $msg = $_.Message
                if ($msg -match '(?i)bypass|frombase64|downloadstring|invoke-expression|-enc|encodedcommand|hidden') {
                    $findings.Add((New-AuditFinding -Category 'EventLog' -Severity 'High' `
                        -Title 'ScriptBlock PowerShell suspect (4104)' `
                        -Detail ($msg.Substring(0, [Math]::Min(400, $msg.Length))) `
                        -Evidence $_.TimeCreated.ToString('o') `
                        -WhySuspicious 'Journal PowerShell avec motifs d''attaque.'))
                }
            }
    }
    catch { }

    Write-AuditProgress -Phase 'Surface' -Percent 88 -Detail 'Hotspots disque...'
    $roots = @(
        $env:TEMP,
        "$env:LOCALAPPDATA\Temp",
        "$env:USERPROFILE\Downloads",
        "$env:APPDATA",
        "$env:LOCALAPPDATA",
        "$env:ProgramData"
    ) | Select-Object -Unique
    $exts = @('*.exe','*.dll','*.ps1','*.vbs','*.js','*.bat','*.cmd','*.scr','*.hta')
    $cutoffFile = (Get-Date).AddDays(-7)
    $deadline = (Get-Date).AddSeconds(35)
    foreach ($root in $roots) {
        if ((Get-Date) -gt $deadline) { break }
        if (-not (Test-Path -LiteralPath $root)) { continue }
        # limit depth via -Depth where available (PS5.1 has -Depth on Get-ChildItem in newer builds)
        foreach ($ext in $exts) {
            if ((Get-Date) -gt $deadline) { break }
            try {
                Get-ChildItem -LiteralPath $root -Filter $ext -File -Recurse -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -gt $cutoffFile } |
                    Select-Object -First 25 |
                    ForEach-Object {
                        if (Test-AuditAllowed -Path $_.FullName) {
                            $sig = Get-AuditFileSignature $_.FullName
                            if ($sig.Signed) { return }
                        }
                        $sev = 'Low'
                        if ($_.Extension -match '(?i)\.(exe|scr|dll)$' -and (Test-AuditSuspiciousPath $_.FullName)) { $sev = 'Medium' }
                        if ($_.DirectoryName -match '(?i)\\Temp\\') { $sev = 'Medium' }
                        $findings.Add((New-AuditFinding -Category 'Disk' -Severity $sev `
                            -Title "Fichier recent: $($_.Name)" `
                            -Detail ("Size={0} Modified={1}" -f $_.Length, $_.LastWriteTime) `
                            -Path $_.FullName -Evidence $_.FullName `
                            -WhySuspicious 'Artefact executable/script recent dans zone a risque.'))
                    }
            }
            catch { }
        }
    }

    Write-AuditProgress -Phase 'Surface' -Percent 95 -Detail 'Spot-check binaires critiques...'
    $criticalBins = @(
        "$env:SystemRoot\System32\cmd.exe",
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
        "$env:SystemRoot\explorer.exe",
        "$env:SystemRoot\System32\lsass.exe",
        "$env:SystemRoot\System32\services.exe",
        "$env:SystemRoot\System32\csrss.exe",
        "$env:SystemRoot\System32\svchost.exe"
    )
    foreach ($b in $criticalBins) {
        $sig = Get-AuditFileSignature -FilePath $b
        if (-not (Test-Path -LiteralPath $b)) {
            $findings.Add((New-AuditFinding -Category 'Hygiene' -Severity 'Critical' `
                -Title "Binaire systeme manquant: $(Split-Path $b -Leaf)" `
                -Path $b -WhySuspicious 'Fichier systeme attendu introuvable.'))
            continue
        }
        if (-not $sig.Signed) {
            $findings.Add((New-AuditFinding -Category 'Hygiene' -Severity 'Critical' `
                -Title "Binaire systeme non signe: $(Split-Path $b -Leaf)" `
                -Path $b -Detail $sig.Status `
                -WhySuspicious 'Signature Authenticode absente/invalide sur binaire critique.'))
        }
        elseif (-not (Test-AuditMicrosoftPublisher $sig.Publisher)) {
            $findings.Add((New-AuditFinding -Category 'Hygiene' -Severity 'Critical' `
                -Title "Binaire systeme editeur inattendu: $(Split-Path $b -Leaf)" `
                -Path $b -Detail $sig.Publisher `
                -WhySuspicious 'Editeur non Microsoft sur fichier systeme.'))
        }
    }

    Write-AuditProgress -Phase 'Surface' -Percent 98 -Detail 'Surface OK'
    return $findings
}
