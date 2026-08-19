# Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X

#Requires -Version 5.1
# Audit.Network.ps1 - Inventaire connexions, estimation, surveillance, hosts/proxy/firewall

$script:AuditDnsCache = @{}

function Test-AuditPrivateIp {
    param([string]$Ip)
    if ([string]::IsNullOrWhiteSpace($Ip)) { return $true }
    if ($Ip -in @('127.0.0.1','::1','0.0.0.0','::','::','*')) { return $true }
    if ($Ip -eq '::' -or $Ip -match '^::$') { return $true }
    if ($Ip -match '^10\.') { return $true }
    if ($Ip -match '^192\.168\.') { return $true }
    if ($Ip -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') { return $true }
    if ($Ip -match '^fe80:') { return $true }
    if ($Ip -match '^fc') { return $true }
    if ($Ip -match '^169\.254\.') { return $true }
    return $false
}

function Get-AuditPortEstimate {
    param([int]$Port, [string]$Direction = 'Out')
    $map = @{
        20 = 'FTP data'; 21 = 'FTP'; 22 = 'SSH'
        23 = 'Telnet'; 25 = 'SMTP'; 53 = 'DNS'
        80 = 'HTTP'; 110 = 'POP3'; 135 = 'RPC/EPMap'
        139 = 'NetBIOS'; 143 = 'IMAP'; 443 = 'HTTPS'
        445 = 'SMB'; 465 = 'SMTPS'; 587 = 'SMTP submission'
        993 = 'IMAPS'; 995 = 'POP3S'; 1433 = 'MSSQL'
        1521 = 'Oracle'; 3306 = 'MySQL'; 3389 = 'RDP'
        5432 = 'PostgreSQL'; 5900 = 'VNC'; 5901 = 'VNC'
        5938 = 'TeamViewer'; 7070 = 'AnyDesk?'
        8080 = 'HTTP-alt'; 8443 = 'HTTPS-alt'
        27017 = 'MongoDB'
        4444 = 'RAT/Metasploit?'; 5555 = 'ADB/RAT?'
        6666 = 'IRC/RAT?'; 1337 = 'Elite/RAT?'
        31337 = 'Back Orifice?'
        5357 = 'WSDAPI'; 7680 = 'Delivery Optimization'
        1900 = 'SSDP'; 5353 = 'mDNS'
        8530 = 'WSUS'; 8531 = 'WSUS SSL'
        5228 = 'Google services'; 5223 = 'Apple push?'
        3478 = 'STUN/WebRTC'; 1935 = 'RTMP'
        5060 = 'SIP'; 6881 = 'BitTorrent'
        9418 = 'Git'
    }
    if ($map.ContainsKey($Port)) { return $map[$Port] }
    if ($Port -ge 49152) { return 'Port ephemere / dynamique' }
    if ($Direction -eq 'Listen' -and $Port -lt 1024) { return 'Service systeme (port privilegie)' }
    return 'Service inconnu / custom'
}

function Get-AuditReverseDns {
    param([string]$Ip)
    if ([string]::IsNullOrWhiteSpace($Ip)) { return '' }
    if (Test-AuditPrivateIp $Ip) { return '' }
    if ($script:AuditDnsCache.ContainsKey($Ip)) { return $script:AuditDnsCache[$Ip] }
    $name = ''
    try {
        $r = Resolve-DnsName -Name $Ip -Type PTR -DnsOnly -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($r -and $r.NameHost) { $name = [string]$r.NameHost }
    }
    catch { }
    $script:AuditDnsCache[$Ip] = $name
    return $name
}

function Test-AuditRemoteAccessProcess {
    param([string]$Name, [string]$Path)
    $blob = ("{0} {1}" -f $Name, $Path).ToLowerInvariant()
    $tools = @(
        'anydesk','teamviewer','rustdesk','vnc','tvnserver','winvnc','ultravnc',
        'chrome_remote_desktop','remotedesktop','remotepc','splashtop','logmein',
        'gotomypc','ammyy','radmin','supremo','dwagent','meshagent','screenconnect',
        'connectwise','bomgar','beyondtrust','parsec','moonlight','nomachine','nxd',
        'tightvnc','realvnc','phontom','quasar','njrat','asyncrat'
    )
    foreach ($t in $tools) {
        if ($blob.Contains($t)) { return $t }
    }
    return $null
}

function Get-AuditConnectionRisk {
    param(
        [string]$Direction,
        [string]$ProcessName,
        [string]$Path,
        [string]$LocalAddress,
        [int]$LocalPort,
        [string]$RemoteAddress,
        [int]$RemotePort,
        [string]$Estimate
    )
    $risk = 'Info'
    $reasons = New-Object System.Collections.Generic.List[string]
    $remoteTool = Test-AuditRemoteAccessProcess $ProcessName $Path
    if ($remoteTool) {
        $risk = 'High'
        $reasons.Add("Outil d'acces distant detecte: $remoteTool")
    }
    if (Test-AuditSuspiciousPath $Path) {
        $risk = 'High'
        $reasons.Add('Executable en zone sensible (Temp/AppData/Downloads)')
    }
    if ($Direction -eq 'Listen') {
        if ($LocalAddress -in @('0.0.0.0','::','*') -or $LocalAddress -match '^0\.0\.0\.0') {
            if ($risk -eq 'Info') { $risk = 'Medium' }
            $reasons.Add('Ecoute sur toutes les interfaces')
        }
        if ($LocalPort -in @(4444,5555,6666,1337,31337,5900,5901,3389)) {
            $risk = 'High'
            $reasons.Add("Port d'ecoute sensible: $LocalPort ($Estimate)")
        }
    }
    else {
        if (-not (Test-AuditPrivateIp $RemoteAddress)) {
            if ($RemotePort -in @(4444,5555,6666,1337,31337)) {
                $risk = 'Critical'
                $reasons.Add("Port distant typique RAT: $RemotePort")
            }
            elseif ($Estimate -match '\?' -and $risk -eq 'Info') {
                $risk = 'Low'
                $reasons.Add('Port / service peu courant')
            }
        }
    }
    if ($Path -and -not (Test-AuditAllowed -Path $Path -ProcessName $ProcessName)) {
        $sig = Get-AuditFileSignature -FilePath $Path
        if (-not $sig.Signed -and $Direction -ne 'Listen') {
            if ($risk -in @('Info','Low')) { $risk = 'Medium' }
            $reasons.Add('Binaire non signe')
        }
    }
    return @{
        Risk    = $risk
        Reasons = (@($reasons) -join '; ')
    }
}

function Get-AuditConnectionInventory {
    param([switch]$SkipReverseDns)
    $connections = New-Object System.Collections.Generic.List[object]
    if (-not $SkipReverseDns) { $script:AuditDnsCache = @{} }

    $procMap = @{}
    try {
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $procMap[$_.Id] = @{ Name = $_.ProcessName; Path = $_.Path }
        }
    }
    catch { }

    try {
        foreach ($c in @(Get-NetTCPConnection -State Established,Listen -ErrorAction Stop)) {
            $owning = [int]$c.OwningProcess
            $info = $procMap[$owning]
            $pname = if ($info) { [string]$info.Name } else { "PID$owning" }
            $ppath = if ($info) { [string]$info.Path } else { '' }
            $remote = [string]$c.RemoteAddress
            $rport = [int]$c.RemotePort
            $local = [string]$c.LocalAddress
            $lport = [int]$c.LocalPort
            $state = [string]$c.State
            $direction = if ($state -eq 'Listen') { 'Listen' } else { 'Outbound' }
            $estPort = if ($direction -eq 'Listen') { $lport } else { $rport }
            $estimate = Get-AuditPortEstimate -Port $estPort -Direction $direction
            $rdns = ''
            if (-not $SkipReverseDns -and $direction -eq 'Outbound' -and -not (Test-AuditPrivateIp $remote)) {
                if ($script:AuditDnsCache.Count -lt 40) {
                    $rdns = Get-AuditReverseDns $remote
                    if ($rdns) { $estimate = "$estimate | $rdns" }
                }
            }
            $riskInfo = Get-AuditConnectionRisk -Direction $direction -ProcessName $pname -Path $ppath `
                -LocalAddress $local -LocalPort $lport -RemoteAddress $remote -RemotePort $rport -Estimate $estimate
            $connections.Add([pscustomobject]@{
                Direction     = $direction
                State         = $state
                Protocol      = 'TCP'
                ProcessName   = $pname
                Pid           = $owning
                Path          = $ppath
                LocalAddress  = $local
                LocalPort     = $lport
                RemoteAddress = $(if ($direction -eq 'Listen') { '-' } else { $remote })
                RemotePort    = $(if ($direction -eq 'Listen') { 0 } else { $rport })
                Estimate      = $estimate
                ReverseDns    = $rdns
                Risk          = $riskInfo.Risk
                RiskReason    = $riskInfo.Reasons
                IsPrivate     = $(if ($direction -eq 'Listen') { $true } else { Test-AuditPrivateIp $remote })
            })
        }
    }
    catch { }

    try {
        foreach ($u in @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Select-Object -First 100)) {
            $owning = [int]$u.OwningProcess
            $info = $procMap[$owning]
            $pname = if ($info) { [string]$info.Name } else { "PID$owning" }
            $ppath = if ($info) { [string]$info.Path } else { '' }
            $local = [string]$u.LocalAddress
            $lport = [int]$u.LocalPort
            $estimate = Get-AuditPortEstimate -Port $lport -Direction 'Listen'
            $riskInfo = Get-AuditConnectionRisk -Direction 'Listen' -ProcessName $pname -Path $ppath `
                -LocalAddress $local -LocalPort $lport -RemoteAddress '' -RemotePort 0 -Estimate $estimate
            $connections.Add([pscustomobject]@{
                Direction     = 'Listen'
                State         = 'UDP'
                Protocol      = 'UDP'
                ProcessName   = $pname
                Pid           = $owning
                Path          = $ppath
                LocalAddress  = $local
                LocalPort     = $lport
                RemoteAddress = '-'
                RemotePort    = 0
                Estimate      = $estimate
                ReverseDns    = ''
                Risk          = $riskInfo.Risk
                RiskReason    = $riskInfo.Reasons
                IsPrivate     = $true
            })
        }
    }
    catch { }

    return @($connections.ToArray())
}

function Get-AuditWifiDnsFindings {
    $findings = New-Object System.Collections.Generic.List[object]
    try {
        $lines = & netsh.exe wlan show profiles 2>$null
        $profiles = New-Object System.Collections.Generic.List[string]
        foreach ($line in @($lines)) {
            if ($line -match '(?i)(?:All User Profile|User Profile|Profil de tous les utilisateurs|Profil utilisateur)\s*:\s*(.+)$') {
                $name = $Matches[1].Trim()
                if ($name) { [void]$profiles.Add($name) }
            }
        }
        $profiles = @($profiles | Select-Object -Unique)
        foreach ($p in $profiles) {
            $findings.Add((New-AuditFinding -Category 'Wifi' -Severity 'Info' `
                -Title "Profil Wi-Fi: $p" `
                -Evidence $p `
                -WhySuspicious 'Inventaire des reseaux Wi-Fi enregistres - verifier les inconnus.'))
        }
        if ($profiles.Count -gt 15) {
            $findings.Add((New-AuditFinding -Category 'Wifi' -Severity 'Low' `
                -Title ("Beaucoup de profils Wi-Fi ({0})" -f $profiles.Count) `
                -WhySuspicious 'Nombre eleve de reseaux memorises - possible hotspot malveillant parmi eux.'))
        }
    }
    catch { }

    try {
        Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 } |
            ForEach-Object {
                $iface = [string]$_.InterfaceAlias
                foreach ($dns in @($_.ServerAddresses)) {
                    $d = [string]$dns
                    if ($d -in @('127.0.0.1','::1')) { continue }
                    if (Test-AuditPrivateIp $d) {
                        $findings.Add((New-AuditFinding -Category 'Dns' -Severity 'Low' `
                            -Title "DNS local: $d ($iface)" `
                            -Detail $d -Evidence $iface `
                            -WhySuspicious 'DNS sur IP privee - router ou filtre local, verifier legitimite.'))
                    }
                    elseif ($d -notmatch '^(8\.8\.|8\.9\.|1\.1\.1\.|1\.0\.0\.|9\.9\.9\.|208\.67\.|75\.75\.|64\.6\.|94\.140\.)') {
                        $findings.Add((New-AuditFinding -Category 'Dns' -Severity 'Medium' `
                            -Title "DNS public non standard: $d ($iface)" `
                            -Detail $d -Evidence $iface `
                            -WhySuspicious 'Serveur DNS inhabituel - risque de detournement de resolution.'))
                    }
                }
            }
    }
    catch { }
    return $findings
}

function Invoke-AuditNetworkScan {
    $findings = New-Object System.Collections.Generic.List[object]
    $script:AuditDnsCache = @{}

    Write-AuditProgress -Phase 'Reseau' -Percent 10 -Detail 'Inventaire TCP/UDP...'
    $connections = @(Get-AuditConnectionInventory)

    $browser = @('chrome','msedge','firefox','opera','brave','iexplore','ApplicationFrameHost','SearchApp','Discord','Slack','Teams','OUTLOOK','Spotify','steam','EpicGamesLauncher','Cursor','Code')
    $seenRemoteTools = @{}

    Write-AuditProgress -Phase 'Reseau' -Percent 35 -Detail 'Analyse connexions...'
    foreach ($c in $connections) {
        if ($c.Protocol -ne 'TCP') { continue }
        $pname = [string]$c.ProcessName
        $ppath = [string]$c.Path
        $owning = [int]$c.Pid
        $direction = [string]$c.Direction
        $local = [string]$c.LocalAddress
        $lport = [int]$c.LocalPort
        $remote = [string]$c.RemoteAddress
        $rport = [int]$c.RemotePort
        $estimate = [string]$c.Estimate
        $rdns = [string]$c.ReverseDns
        $risk = [string]$c.Risk
        $riskReason = [string]$c.RiskReason

        $remoteTool = Test-AuditRemoteAccessProcess $pname $ppath
        if ($remoteTool -and -not $seenRemoteTools.ContainsKey($remoteTool)) {
            $seenRemoteTools[$remoteTool] = $true
            $findings.Add((New-AuditFinding -Category 'Surveillance' -Severity 'High' `
                -Title "Acces distant actif: $remoteTool ($pname)" `
                -Detail ("PID={0} Path={1}" -f $owning, $ppath) `
                -Path $ppath -Evidence $remoteTool `
                -WhySuspicious 'Logiciel de prise de controle a distance en cours - verifier si vous l''avez installe.' `
                -Meta @{ ProcessName = $pname; Pid = $owning; Tool = $remoteTool }))
        }

        if ($direction -eq 'Listen') {
            if ($ppath -and (Test-AuditSuspiciousPath $ppath) -and -not (Test-AuditAllowed -Path $ppath -ProcessName $pname)) {
                $findings.Add((New-AuditFinding -Category 'Network' -Severity 'High' `
                    -Title "Port en ecoute depuis emplacement sensible: $pname" `
                    -Detail ("Local={0}:{1} Path={2}" -f $local, $lport, $ppath) `
                    -Path $ppath -Evidence ("PID $owning") `
                    -WhySuspicious 'Service/processus en ecoute depuis Temp/AppData - possible backdoor.' `
                    -Meta @{ ProcessName = $pname; Pid = $owning; Port = $lport }))
            }
            elseif (($local -in @('0.0.0.0','::') -or $local -match '^0\.0\.0\.0') -and
                    $lport -notin @(135,139,445,5357,7680,2869,5353,1900,3389) -and
                    -not (Test-AuditAllowed -Path $ppath -ProcessName $pname) -and
                    $ppath -and -not ($ppath -match '(?i)\\windows\\')) {
                $findings.Add((New-AuditFinding -Category 'Surveillance' -Severity 'Medium' `
                    -Title "Ecoute toutes interfaces: $pname :$lport" `
                    -Detail ("Estimate={0} Path={1}" -f $estimate, $ppath) `
                    -WhySuspicious 'Port ouvert sur le reseau local/internet - surface d''attaque.' `
                    -Meta @{ ProcessName = $pname; Pid = $owning; Port = $lport }))
            }
            continue
        }

        if ($c.IsPrivate) { continue }
        if ($browser -contains $pname) { continue }
        if ($ppath -match '(?i)\\windows\\' -and (Get-AuditFileSignature $ppath).Signed) { continue }
        if ((Test-AuditAllowed -Path $ppath -ProcessName $pname) -and $risk -in @('Info','Low')) { continue }

        $sev = $risk
        if ($sev -eq 'Info') { $sev = 'Low' }
        $why = if ($riskReason) { $riskReason } else { 'Connexion sortante vers IP publique.' }
        $findings.Add((New-AuditFinding -Category 'Network' -Severity $sev `
            -Title ("Sortante: {0} -> {1}:{2} ({3})" -f $pname, $remote, $rport, $estimate) `
            -Detail ("PID={0} Path={1} DNS={2}" -f $owning, $ppath, $rdns) `
            -Path $ppath -Evidence ("{0}:{1}" -f $remote, $rport) `
            -WhySuspicious $why `
            -Meta @{ ProcessName = $pname; Pid = $owning; Remote = $remote; Port = $rport; Estimate = $estimate }))
    }

    Write-AuditProgress -Phase 'Reseau' -Percent 50 -Detail 'Processus...'
    $procMap = @{}
    try {
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $procMap[$_.Id] = @{ Name = $_.ProcessName; Path = $_.Path }
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Reseau' -Percent 55 -Detail 'Surveillance process...'
    foreach ($kv in @($procMap.GetEnumerator())) {
        $pname = [string]$kv.Value.Name
        $ppath = [string]$kv.Value.Path
        $tool = Test-AuditRemoteAccessProcess $pname $ppath
        if ($tool -and -not $seenRemoteTools.ContainsKey($tool)) {
            $seenRemoteTools[$tool] = $true
            $findings.Add((New-AuditFinding -Category 'Surveillance' -Severity 'Medium' `
                -Title "Outil remote-access present: $tool ($pname)" `
                -Detail ("PID={0} Path={1}" -f $kv.Key, $ppath) `
                -Path $ppath -Evidence $tool `
                -WhySuspicious 'Processus d''acces distant sans connexion TCP listee - verifier legitimite.' `
                -Meta @{ ProcessName = $pname; Pid = [int]$kv.Key; Tool = $tool }))
        }
        # Recording / spy-ish process names (info only)
        if ($pname -match '(?i)^(obs64|obs32|bandicam|camtasia|nvidia share|gamebarftserver|skype|zoom)$') {
            # skip common benign
        }
        elseif ($pname -match '(?i)keylog|screen.?capture|web.?cam.?spy|hidden.?cam|mic.?spy|hid.?tee') {
            $findings.Add((New-AuditFinding -Category 'Surveillance' -Severity 'Critical' `
                -Title "Processus nomme comme spyware: $pname" `
                -Path $ppath -Evidence ("PID $($kv.Key)") `
                -WhySuspicious 'Nom de processus typique d''outil d''espionnage.' `
                -Meta @{ ProcessName = $pname; Pid = [int]$kv.Key }))
        }
    }

    Write-AuditProgress -Phase 'Reseau' -Percent 65 -Detail 'Hosts...'
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path -LiteralPath $hostsPath) {
        Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue | ForEach-Object {
            $line = $_.Trim()
            if (-not $line -or $line.StartsWith('#')) { return }
            if ($line -match '^(127\.0\.0\.1|::1)\s+(localhost|broadcasthost)') { return }
            if ($line -match '^[\d\.:a-fA-F]+\s+(\S+)') {
                $hostName = $Matches[1]
                $sev = 'Medium'
                if ($hostName -match '(?i)microsoft|windows|defender|google|facebook|login|bank|paypal|office') { $sev = 'High' }
                $findings.Add((New-AuditFinding -Category 'Hosts' -Severity $sev `
                    -Title "Entree hosts non standard: $hostName" `
                    -Detail $line -Path $hostsPath -Evidence $line `
                    -WhySuspicious 'Redirection DNS locale - peut detourner un site legible.'))
            }
        }
    }

    Write-AuditProgress -Phase 'Reseau' -Percent 72 -Detail 'Proxy...'
    try {
        $proxyKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $ie = Get-ItemProperty -LiteralPath $proxyKey -ErrorAction SilentlyContinue
        if ($ie.ProxyEnable -eq 1 -and $ie.ProxyServer) {
            $findings.Add((New-AuditFinding -Category 'Proxy' -Severity 'Medium' `
                -Title 'Proxy systeme active' `
                -Detail ([string]$ie.ProxyServer) -Evidence $proxyKey `
                -WhySuspicious 'Proxy utilisateur active - verifier qu''il est intentionnel.'))
        }
        if ($ie.AutoConfigURL) {
            $findings.Add((New-AuditFinding -Category 'Proxy' -Severity 'High' `
                -Title 'PAC proxy distant' `
                -Detail ([string]$ie.AutoConfigURL) -Evidence $proxyKey `
                -WhySuspicious 'Fichier PAC distant peut rediriger tout le trafic web.'))
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Reseau' -Percent 80 -Detail 'DNS cache...'
    try {
        $dns = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -First 200
        foreach ($d in @($dns)) {
            $name = [string]$d.Entry
            if ($name.Length -lt 8) { continue }
            $label = ($name -split '\.')[0]
            if ($label.Length -ge 16 -and $label -match '^[a-z0-9]+$' -and $label -notmatch '(cdn|static|google|microsoft|amazon|cloud|akamai|facebook)') {
                $vowels = ([regex]::Matches($label, '[aeiou]')).Count
                if ($vowels -le 2) {
                    $findings.Add((New-AuditFinding -Category 'Network' -Severity 'Low' `
                        -Title "DNS cache aspect DGA: $name" `
                        -Detail ([string]$d.Data) -Evidence $name `
                        -WhySuspicious 'Nom de domaine inhabituel dans le cache DNS (faux positifs possibles).'))
                }
            }
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Reseau' -Percent 88 -Detail 'Firewall / RDP...'
    try {
        $rules = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
            Select-Object -First 80
        foreach ($r in @($rules)) {
            try {
                $app = (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue).Program
                if ($app -and (Test-AuditSuspiciousPath $app)) {
                    $findings.Add((New-AuditFinding -Category 'Network' -Severity 'High' `
                        -Title "Firewall allow: $($r.DisplayName)" `
                        -Detail $app -Path $app -Evidence $r.Name `
                        -WhySuspicious 'Regle firewall entrante vers un executable en zone sensible.'))
                }
            }
            catch { }
        }
    }
    catch { }

    try {
        $rdp = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
        if ($rdp -eq 0) {
            $rdpConns = @($connections | Where-Object { $_.LocalPort -eq 3389 -or $_.RemotePort -eq 3389 })
            $sev = if ($rdpConns.Count -gt 0) { 'High' } else { 'Info' }
            $findings.Add((New-AuditFinding -Category 'Surveillance' -Severity $sev `
                -Title 'Bureau a distance (RDP) active' `
                -Detail ("Connexions RDP actives: {0}" -f $rdpConns.Count) `
                -Evidence 'fDenyTSConnections=0' `
                -WhySuspicious 'RDP ouvert - canal classique d''acces distant. Verifier si intentionnel.'))
        }
    }
    catch { }

    try {
        Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('ADMIN$','C$','IPC$') } | ForEach-Object {
            $findings.Add((New-AuditFinding -Category 'Network' -Severity 'Low' `
                -Title "Partage SMB: $($_.Name)" `
                -Detail $_.Path -Path $_.Path -Evidence $_.Name `
                -WhySuspicious 'Partage reseau non administratif - verifier les permissions.'))
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Reseau' -Percent 92 -Detail 'Wi-Fi / DNS...'
    foreach ($f in @(Get-AuditWifiDnsFindings)) { $findings.Add($f) }

    Write-AuditProgress -Phase 'Reseau' -Percent 95 -Detail 'Reseau OK'
    [pscustomobject]@{
        Findings    = @($findings.ToArray())
        Connections = @($connections)
    }
}
