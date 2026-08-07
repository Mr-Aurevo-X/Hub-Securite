#Requires -Version 5.1
# Audit.Deduce.ps1 - Corrélation findings -> chaînes + narratives

function New-AuditChain {
    param(
        [string]$Title,
        [ValidateSet('Info','Low','Medium','High','Critical')]$Severity,
        [int]$Confidence,
        [string]$Narrative,
        [string[]]$FindingIds,
        [string[]]$InvestigateHints = @()
    )
    [pscustomobject]@{
        Id               = [guid]::NewGuid().ToString('N').Substring(0, 8)
        Title            = $Title
        Severity         = $Severity
        Confidence       = [Math]::Max(0, [Math]::Min(100, $Confidence))
        Narrative        = $Narrative
        FindingIds       = @($FindingIds)
        InvestigateHints = @($InvestigateHints)
    }
}

function Get-AuditNormalizedPathKey {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $p = $Path.Trim().Trim('"').ToLowerInvariant()
    if ($p -match '([a-z]:\\[^"<>|]+\.(?:exe|dll|sys|scr|com|ps1|vbs|js|bat|cmd|msi))') {
        return $Matches[1]
    }
    return $p
}

function Invoke-AuditDeduce {
    param([object[]]$Findings)
    $chains = New-Object System.Collections.Generic.List[object]
    $list = @($Findings)
    if ($list.Count -eq 0) { return @() }

    # Index by path key
    $byPath = @{}
    foreach ($f in $list) {
        $key = Get-AuditNormalizedPathKey $f.Path
        if (-not $key) { continue }
        if (-not $byPath.ContainsKey($key)) { $byPath[$key] = @() }
        $byPath[$key] += $f
    }

    # Multi-persistence same binary
    foreach ($key in @($byPath.Keys)) {
        $group = @($byPath[$key])
        $persistCats = @($group | Where-Object { $_.Category -in @('Startup','ScheduledTask','Service','WMI','BITS','COM','Shell','IFEO','Winlogon') })
        if ($persistCats.Count -ge 2) {
            $ids = @($persistCats | ForEach-Object { $_.Id })
            $cats = (@($persistCats | ForEach-Object { $_.Category }) | Select-Object -Unique) -join ', '
            $sev = if ($persistCats | Where-Object { $_.Severity -eq 'Critical' }) { 'Critical' }
                elseif ($persistCats | Where-Object { $_.Severity -eq 'High' }) { 'High' }
                else { 'Medium' }
            $chains.Add((New-AuditChain `
                -Title "Persistence multi-vecteur" `
                -Severity $sev `
                -Confidence 82 `
                -Narrative "Le meme binaire apparait dans plusieurs mecanismes de demarrage ($cats). C'est un schema classique de malware qui veut survivre a un nettoyage partiel." `
                -FindingIds $ids `
                -InvestigateHints @(
                    "Verifier le fichier: $key"
                    "Inspecter les entrees Run / Taches / Services liees a ce chemin"
                    "Ne pas supprimer sans backup / point de restauration"
                )))
        }
    }

    # Suspicious path process + network
    $net = @($list | Where-Object { $_.Category -eq 'Network' })
    $proc = @($list | Where-Object { $_.Category -eq 'Process' -and (Test-AuditSuspiciousPath $_.Path) })
    foreach ($p in $proc) {
        $pkey = Get-AuditNormalizedPathKey $p.Path
        $relatedNet = @($net | Where-Object {
            $nkey = Get-AuditNormalizedPathKey $_.Path
            ($nkey -and $pkey -and $nkey -eq $pkey) -or ($_.Detail -like "*$($p.Meta.ProcessName)*") -or ($_.Evidence -like "*$pkey*")
        })
        if ($relatedNet.Count -gt 0) {
            $ids = @($p.Id) + @($relatedNet | ForEach-Object { $_.Id })
            $chains.Add((New-AuditChain `
                -Title "Implant potentiel actif" `
                -Severity 'Critical' `
                -Confidence 88 `
                -Narrative "Un executable depuis un emplacement inhabituel ($($p.Path)) etablit des connexions reseau. Combine processus suspect + trafic sortant = priorite haute d'investigation." `
                -FindingIds $ids `
                -InvestigateHints @(
                    "Identifier la destination IP/domaine dans le finding reseau"
                    "Couper la connexion (airplane / firewall) puis analyser le fichier"
                    "Scanner ce fichier avec Windows Defender / un AV a jour"
                )))
        }
    }

    # LOLBins / encoded powershell
    $lol = @($list | Where-Object {
        $_.Evidence -match '(?i)powershell.*(enc|encoded|bypass|hidden)|cmd\.exe\s+/c|mshta|rundll32|regsvr32|bitsadmin|certutil\s+-urlcache|wscript|cscript' `
        -or $_.Detail -match '(?i)-enc |encodedcommand|bypass|downloadstring|invoke-expression|iex\('
    })
    if ($lol.Count -ge 1) {
        $ids = @($lol | ForEach-Object { $_.Id } | Select-Object -Unique)
        $sev = if ($lol.Count -ge 2) { 'Critical' } else { 'High' }
        $chains.Add((New-AuditChain `
            -Title "Living-off-the-land (LOLBin)" `
            -Severity $sev `
            -Confidence 78 `
            -Narrative "Des outils Windows legitimes (PowerShell, cmd, mshta, rundll32...) sont utilises avec des arguments typiques d'attaque. Cela permet d'executer du code sans deposer un gros malware." `
            -FindingIds $ids `
            -InvestigateHints @(
                "Lire la ligne de commande complete dans les findings"
                "Verifier le parent process (Office, navigateur, explorer)"
                "Consulter l'historique PowerShell / ScriptBlock logging si active"
            )))
    }

    # Defender exclusion + exe in same area
    $excl = @($list | Where-Object { $_.Category -eq 'Defender' -and $_.Title -match 'exclusion' })
    $hot = @($list | Where-Object { $_.Category -in @('Disk','Process','Startup') -and (Test-AuditSuspiciousPath $_.Path) })
    foreach ($e in $excl) {
        $exPath = [string]$e.Path
        if (-not $exPath) { continue }
        $hits = @($hot | Where-Object { $_.Path -and ($_.Path.ToLowerInvariant().StartsWith($exPath.ToLowerInvariant().TrimEnd('\') + '\') -or $_.Path -like "$exPath*") })
        if ($hits.Count -gt 0) {
            $ids = @($e.Id) + @($hits | ForEach-Object { $_.Id })
            $chains.Add((New-AuditChain `
                -Title "Exclusion Defender + activite dans la zone" `
                -Severity 'Critical' `
                -Confidence 90 `
                -Narrative "Une exclusion Windows Defender couvre un dossier ou des executables / artefacts suspects ont ete trouves. C'est un signal fort de contournement antivirus." `
                -FindingIds $ids `
                -InvestigateHints @(
                    "Ouvrir Securite Windows -> Protection contre les virus -> Exclusions (lecture)"
                    "Noter pourquoi cette exclusion existe (legitime vs. forcee)"
                    "Analyser les fichiers listes hors exclusion (cle USB / autre PC)"
                )))
        }
    }

    # Hosts / proxy traffic diversion
    $divert = @($list | Where-Object { $_.Category -in @('Hosts','Proxy') })
    if ($divert.Count -ge 1) {
        $ids = @($divert | ForEach-Object { $_.Id })
        $chains.Add((New-AuditChain `
            -Title "Detournement DNS / proxy" `
            -Severity $(if ($divert | Where-Object Severity -eq 'Critical') { 'Critical' } else { 'High' }) `
            -Confidence 75 `
            -Narrative "La resolution DNS (hosts) ou le proxy systeme a ete modifie. Le trafic web peut etre redirige vers des serveurs malveillants (phishing, vol de sessions)." `
            -FindingIds $ids `
            -InvestigateHints @(
                "Comparer C:\Windows\System32\drivers\etc\hosts aux entrees attendues"
                "Verifier Parametres -> Reseau -> Proxy"
                "Tester la navigation apres correction manuelle"
            )))
    }

    # Unsigned service + listening / network
    $svc = @($list | Where-Object { $_.Category -eq 'Service' })
    $listen = @($list | Where-Object { $_.Category -eq 'Network' -and ($_.Title -match 'ecoute|listen|port') })
    foreach ($s in $svc) {
        $skey = Get-AuditNormalizedPathKey $s.Path
        $rel = @($listen | Where-Object { (Get-AuditNormalizedPathKey $_.Path) -eq $skey -or $_.Detail -like "*$($s.Meta.ServiceName)*" })
        if ($rel.Count -gt 0) {
            $ids = @($s.Id) + @($rel | ForEach-Object { $_.Id })
            $chains.Add((New-AuditChain `
                -Title "Service suspect + port reseau" `
                -Severity 'High' `
                -Confidence 80 `
                -Narrative "Un service marque suspect expose ou utilise le reseau. Pattern compatible avec un backdoor persistant." `
                -FindingIds $ids `
                -InvestigateHints @(
                    "services.msc -> proprietes du service (chemin, compte)"
                    "netstat / Get-NetTCPConnection pour confirmer le port"
                )))
        }
    }

    # WMI persistence alone is already strong - amplify if scripts
    $wmi = @($list | Where-Object { $_.Category -eq 'WMI' })
    if ($wmi.Count -ge 1) {
        $ids = @($wmi | ForEach-Object { $_.Id })
        $chains.Add((New-AuditChain `
            -Title "Persistence WMI" `
            -Severity 'High' `
            -Confidence 85 `
            -Narrative "Des abonnements WMI (Filter/Consumer) peuvent relancer du code a chaque evenement systeme, souvent invisibles dans les dossiers Startup classiques." `
            -FindingIds $ids `
            -InvestigateHints @(
                "Inspecter root\subscription (Filter, Consumer, Binding) en lecture"
                "Noter le chemin du script/commande consumer"
            )))
    }

    # Anti-forensics: shadow copies missing + recent installs / services
    $shadow = @($list | Where-Object { $_.Category -eq 'Hygiene' -and $_.Title -match 'ombre|shadow|restauration' })
    $recent = @($list | Where-Object { $_.Category -in @('Software','Service','EventLog') })
    if ($shadow.Count -ge 1 -and $recent.Count -ge 2) {
        $ids = @($shadow | ForEach-Object { $_.Id }) + @($recent | Select-Object -First 5 | ForEach-Object { $_.Id })
        $chains.Add((New-AuditChain `
            -Title "Possible anti-forensics" `
            -Severity 'Medium' `
            -Confidence 60 `
            -Narrative "Les copies d'ombre / restauration semblent absentes ou purgees, alors que d'autres changements recents sont visibles. Peut etre legitime (disque plein) ou tentative d'effacer des traces." `
            -FindingIds $ids `
            -InvestigateHints @(
                "Verifier l'espace disque et l'historique Protection du systeme"
                "Croiser avec les installs recentes dans les findings Software"
            )))
    }

    # Parent-child lol: Office spawning shells
    $parent = @($list | Where-Object { $_.Category -eq 'Process' -and $_.WhySuspicious -match '(?i)parent|office|winword|excel|outlook' })
    if ($parent.Count -ge 1) {
        $ids = @($parent | ForEach-Object { $_.Id })
        $chains.Add((New-AuditChain `
            -Title "Chaine parent inhabituelle" `
            -Severity 'High' `
            -Confidence 72 `
            -Narrative "Un processus sensible (souvent Office ou navigateur) a lance un interpreteur / outil systeme. Schema frequent d'infection par document ou page web." `
            -FindingIds $ids `
            -InvestigateHints @(
                "Identifier le document / onglet ouvert au moment du scan"
                "Desactiver les macros Office si non necessaires"
            )))
    }

    # Remote access / possible espionnage
    $surv = @($list | Where-Object { $_.Category -eq 'Surveillance' })
    if ($surv.Count -ge 1) {
        $ids = @($surv | ForEach-Object { $_.Id })
        $sev = if ($surv | Where-Object Severity -eq 'Critical') { 'Critical' }
            elseif ($surv | Where-Object Severity -eq 'High') { 'High' }
            else { 'Medium' }
        $chains.Add((New-AuditChain `
            -Title "Possible canal de surveillance a distance" `
            -Severity $sev `
            -Confidence 84 `
            -Narrative "Des outils ou ports d'acces distant / surveillance ont ete detectes (AnyDesk, TeamViewer, RDP, ecoute inhabituelle...). Cela peut etre legitime (vous aidez quelqu'un) ou indiquer qu'un tiers controle le PC." `
            -FindingIds $ids `
            -InvestigateHints @(
                "Verifier si vous avez installe ces outils volontairement"
                "Onglet Reseau: filtrer Suspectes / Ecoute"
                "Desactiver RDP si inutile (Parametres -> Systeme -> Bureau a distance) - manuellement"
                "Couper le reseau et relancer un scan pour voir ce qui insiste a se connecter"
            )))
    }

    # Surveillance + outbound from same process path
    $survHigh = @($surv | Where-Object { $_.Severity -in @('High','Critical') })
    $netOut = @($list | Where-Object { $_.Category -eq 'Network' -and $_.Title -match 'Sortante' })
    foreach ($s in $survHigh) {
        $sp = Get-AuditNormalizedPathKey $s.Path
        $hits = @($netOut | Where-Object {
            (Get-AuditNormalizedPathKey $_.Path) -eq $sp -or $_.Detail -like "*$($s.Meta.ProcessName)*"
        })
        if ($hits.Count -gt 0) {
            $ids = @($s.Id) + @($hits | Select-Object -First 5 | ForEach-Object { $_.Id })
            $chains.Add((New-AuditChain `
                -Title "Acces distant + trafic sortant actif" `
                -Severity 'Critical' `
                -Confidence 90 `
                -Narrative "Un outil marque surveillance/acces distant etablit aussi des connexions sortantes. Priorite: confirmer l'operateur legitime derriere cette session." `
                -FindingIds $ids `
                -InvestigateHints @(
                    "Noter l'IP distante dans les findings Network"
                    "Fermer la session remote-access si ce n'est pas vous"
                )))
        }
    }

    # USB + account activity
    $usb = @($list | Where-Object { $_.Category -eq 'USB' -and $_.Severity -in @('Low','Medium','High') })
    $accRecent = @($list | Where-Object { $_.Category -eq 'Account' -and $_.Title -match '(?i)recent|Administrateurs|Echecs' })
    if ($usb.Count -ge 2 -and $accRecent.Count -ge 1) {
        $ids = @($usb | Select-Object -First 5 | ForEach-Object { $_.Id }) + @($accRecent | Select-Object -First 3 | ForEach-Object { $_.Id })
        $chains.Add((New-AuditChain `
            -Title "USB + activite comptes" `
            -Severity 'Medium' `
            -Confidence 62 `
            -Narrative "Plusieurs peripheriques USB notables coexistent avec des signaux comptes (recent, admin, echecs). Scenario possible: cle USB + creation de compte local." `
            -FindingIds $ids `
            -InvestigateHints @(
                "Comparer les USBSTOR a vos cles connues"
                "Verifier les membres du groupe Administrateurs"
            )))
    }

    # Wi-Fi / DNS
    $wifiDns = @($list | Where-Object { $_.Category -in @('Wifi','Dns') -and $_.Severity -in @('Low','Medium','High') })
    if ($wifiDns.Count -ge 1) {
        $ids = @($wifiDns | ForEach-Object { $_.Id })
        $chains.Add((New-AuditChain `
            -Title "Surface Wi-Fi / DNS" `
            -Severity $(if ($wifiDns | Where-Object Severity -eq 'Medium') { 'Medium' } else { 'Low' }) `
            -Confidence 68 `
            -Narrative "Profils Wi-Fi nombreux ou DNS non standard detectes. Un hotspot malveillant ou un DNS pirate peut detourner le trafic." `
            -FindingIds $ids `
            -InvestigateHints @(
                "Parametres -> Reseau -> Wi-Fi -> reseaux connus"
                "ipconfig /all pour confirmer les serveurs DNS"
            )))
    }

    # COM / Shell
    $comShell = @($list | Where-Object { $_.Category -in @('COM','Shell') -and $_.Severity -in @('Medium','High','Critical') })
    if ($comShell.Count -ge 1) {
        $ids = @($comShell | ForEach-Object { $_.Id })
        $chains.Add((New-AuditChain `
            -Title "Hijack COM / extension shell" `
            -Severity $(if ($comShell | Where-Object Severity -eq 'High') { 'High' } else { 'Medium' }) `
            -Confidence 76 `
            -Narrative "Des serveurs COM ou extensions shell pointent vers des zones sensibles ou des editeurs inhabituels. Technique de persistence discrete." `
            -FindingIds $ids `
            -InvestigateHints @(
                "Noter le CLSID et le chemin InprocServer32/LocalServer32"
                "Verifier la signature du DLL/EXE cible"
            )))
    }

    return @($chains | Sort-Object @{
        Expression = {
            switch ($_.Severity) { 'Critical' { 0 } 'High' { 1 } 'Medium' { 2 } 'Low' { 3 } default { 4 } }
        }
    }, @{ Expression = { -$_.Confidence } })
}
