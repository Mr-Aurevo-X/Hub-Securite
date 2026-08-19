# Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X

#Requires -Version 5.1
# Audit.Accounts.ps1 - Comptes locaux + echantillon logons 4624/4625

function Invoke-AuditAccountsScan {
    $findings = New-Object System.Collections.Generic.List[object]
    Write-AuditProgress -Phase 'Accounts' -Percent 10 -Detail 'Comptes locaux...'

    $cutoff = (Get-Date).AddDays(-30)
    try {
        Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object {
            $u = $_
            $name = [string]$u.Name
            $created = $null
            try { $created = [datetime]$u.PasswordLastSet } catch { }
            try {
                if ($u.PSObject.Properties.Name -contains 'AccountExpires') { }
                # Approximate "recent" via SID creation time is hard; use PasswordLastSet + Enabled as signals
            } catch { }

            if ($u.Enabled -and $u.PasswordNeverExpires) {
                $findings.Add((New-AuditFinding -Category 'Account' -Severity 'Low' `
                    -Title "Mot de passe n'expire jamais: $name" `
                    -Evidence $name `
                    -WhySuspicious 'Compte local sans expiration de mot de passe - politique faible.' `
                    -Meta @{ User = $name }))
            }

            if ($u.Enabled -and $created -and $created -gt $cutoff) {
                $findings.Add((New-AuditFinding -Category 'Account' -Severity 'Medium' `
                    -Title "Compte recent (mdp < 30j): $name" `
                    -Detail ("PasswordLastSet={0}" -f $created.ToString('s')) `
                    -Evidence $name `
                    -WhySuspicious 'Compte local avec mot de passe change/cree recemment - verifier legitimite.' `
                    -Meta @{ User = $name; When = $created.ToString('o') }))
            }
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Accounts' -Percent 35 -Detail 'Administrateurs...'
    try {
        $admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue)
        foreach ($a in $admins) {
            $n = [string]$a.Name
            if ($n -match '(?i)\\Administrator$' -or $n -match '(?i)^Administrateur$') { continue }
            $findings.Add((New-AuditFinding -Category 'Account' -Severity 'Medium' `
                -Title "Membre Administrateurs: $n" `
                -Detail ([string]$a.ObjectClass) `
                -Evidence $n `
                -WhySuspicious 'Compte avec privileges eleves - verifier si attendu.' `
                -Meta @{ User = $n }))
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Accounts' -Percent 55 -Detail 'Logons Security 4624/4625...'
    $since = (Get-Date).AddDays(-7)
    try {
        $ok = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624; StartTime = $since } -MaxEvents 80 -ErrorAction SilentlyContinue)
        $netLogons = 0
        $remoteUsers = @{}
        foreach ($e in $ok) {
            try {
                $xml = [xml]$e.ToXml()
                $data = @{}
                foreach ($d in $xml.Event.EventData.Data) {
                    $data[$d.Name] = [string]$d.'#text'
                }
                $logonType = [string]$data['LogonType']
                $user = [string]$data['TargetUserName']
                $ip = [string]$data['IpAddress']
                # 3=Network, 10=RemoteInteractive
                if ($logonType -in @('3','10') -and $user -and $user -notmatch '(?i)^(ANONYMOUS|DWM-|UMFD-|LOCAL SERVICE|NETWORK SERVICE|SYSTEM)') {
                    $netLogons++
                    if ($ip -and $ip -notin @('-','127.0.0.1','::1')) {
                        $remoteUsers["$user@$ip"] = $true
                    }
                }
            }
            catch { }
        }
        if ($netLogons -gt 0) {
            $sev = if ($remoteUsers.Count -gt 3) { 'High' } elseif ($remoteUsers.Count -gt 0) { 'Medium' } else { 'Low' }
            $sample = (@($remoteUsers.Keys) | Select-Object -First 8) -join ', '
            $findings.Add((New-AuditFinding -Category 'Account' -Severity $sev `
                -Title ("Logons reseau/RDP 7j: {0}" -f $netLogons) `
                -Detail $sample `
                -Evidence 'Event 4624' `
                -WhySuspicious 'Connexions reseau ou interactives a distance recentes - verifier origines.' `
                -Meta @{ Count = $netLogons }))
        }
    }
    catch { }

    try {
        $fail = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4625; StartTime = $since } -MaxEvents 60 -ErrorAction SilentlyContinue)
        if ($fail.Count -ge 5) {
            $sev = if ($fail.Count -ge 20) { 'High' } else { 'Medium' }
            $findings.Add((New-AuditFinding -Category 'Account' -Severity $sev `
                -Title ("Echecs de logon 7j: {0}" -f $fail.Count) `
                -Evidence 'Event 4625' `
                -WhySuspicious 'Nombreux echecs d''authentification - possible brute-force ou mauvais identifiants.' `
                -Meta @{ Count = $fail.Count }))
        }
        elseif ($fail.Count -gt 0) {
            $findings.Add((New-AuditFinding -Category 'Account' -Severity 'Info' `
                -Title ("Echecs de logon 7j: {0}" -f $fail.Count) `
                -Evidence 'Event 4625' `
                -WhySuspicious 'Quelques echecs de logon - souvent benignes.'))
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Accounts' -Percent 95 -Detail 'Accounts OK'
    return $findings
}
