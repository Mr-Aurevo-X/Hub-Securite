# Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X

#Requires -Version 5.1
# Audit.Checklist.ps1 - Checklist anti-espionnage (lecture seule)

function New-AuditCheckItem {
    param(
        [string]$Id,
        [string]$Question,
        [ValidateSet('OK','Attention','Critique')]$Status,
        [string]$Detail = ''
    )
    [pscustomobject]@{
        Id       = $Id
        Question = $Question
        Status   = $Status
        Detail   = $Detail
    }
}

function Invoke-AuditSpyChecklist {
    param(
        [object[]]$Findings,
        [object[]]$Connections = @(),
        [object[]]$Chains = @()
    )
    $list = @($Findings)
    $conns = @($Connections)
    $items = New-Object System.Collections.Generic.List[object]

    # 1 Remote access
    $ra = @($list | Where-Object { $_.Category -eq 'Surveillance' -and $_.Title -match '(?i)acces distant|remote-access|AnyDesk|TeamViewer|VNC|RustDesk' })
    if ($ra.Count -eq 0) {
        $items.Add((New-AuditCheckItem -Id 'remote' -Question 'Outils de prise de controle a distance ?' -Status 'OK' -Detail 'Aucun outil remote-access detecte.'))
    }
    else {
        $names = ($ra | ForEach-Object { $_.Title } | Select-Object -First 3) -join ' | '
        $st = if ($ra | Where-Object Severity -in @('High','Critical')) { 'Critique' } else { 'Attention' }
        $items.Add((New-AuditCheckItem -Id 'remote' -Question 'Outils de prise de controle a distance ?' -Status $st -Detail $names))
    }

    # 2 RDP
    $rdp = @($list | Where-Object { $_.Title -match '(?i)RDP|Bureau a distance' })
    if ($rdp.Count -eq 0) {
        $items.Add((New-AuditCheckItem -Id 'rdp' -Question 'Bureau a distance (RDP) ouvert ?' -Status 'OK' -Detail 'RDP non signale comme actif.'))
    }
    else {
        $st = if ($rdp | Where-Object Severity -in @('High','Critical')) { 'Critique' } else { 'Attention' }
        $items.Add((New-AuditCheckItem -Id 'rdp' -Question 'Bureau a distance (RDP) ouvert ?' -Status $st -Detail ($rdp[0].Detail)))
    }

    # 3 Proxy / Hosts
    $divert = @($list | Where-Object { $_.Category -in @('Hosts','Proxy') })
    if ($divert.Count -eq 0) {
        $items.Add((New-AuditCheckItem -Id 'divert' -Question 'Trafic web detourne (hosts / proxy) ?' -Status 'OK' -Detail 'Pas de modification hosts/proxy suspecte.'))
    }
    else {
        $st = if ($divert | Where-Object Severity -in @('High','Critical')) { 'Critique' } else { 'Attention' }
        $items.Add((New-AuditCheckItem -Id 'divert' -Question 'Trafic web detourne (hosts / proxy) ?' -Status $st -Detail ("{0} signal(s)" -f $divert.Count)))
    }

    # 4 Listen all interfaces
    $listen = @($list | Where-Object { $_.Title -match '(?i)Ecoute toutes interfaces|emplacement sensible' -and $_.Category -in @('Surveillance','Network') })
    $listenSus = @($conns | Where-Object { $_.Direction -eq 'Listen' -and $_.Risk -in @('Medium','High','Critical') })
    if ($listen.Count -eq 0 -and $listenSus.Count -eq 0) {
        $items.Add((New-AuditCheckItem -Id 'listen' -Question 'Ports en ecoute inhabituels ?' -Status 'OK' -Detail 'Pas d''ecoute marquee suspecte.'))
    }
    else {
        $items.Add((New-AuditCheckItem -Id 'listen' -Question 'Ports en ecoute inhabituels ?' -Status 'Attention' -Detail ("Findings={0}, connexions risque={1}" -f $listen.Count, $listenSus.Count)))
    }

    # 5 Temp/AppData + network
    $implant = @($Chains | Where-Object { $_.Title -match '(?i)Implant|Temp|AppData' })
    $tempNet = @($list | Where-Object { $_.Category -eq 'Network' -and (Test-AuditSuspiciousPath $_.Path) -and $_.Severity -in @('High','Critical') })
    if ($implant.Count -eq 0 -and $tempNet.Count -eq 0) {
        $items.Add((New-AuditCheckItem -Id 'tempnet' -Question 'Executable sensible + connexion reseau ?' -Status 'OK' -Detail 'Pas de combo Temp/AppData + reseau critique.'))
    }
    else {
        $items.Add((New-AuditCheckItem -Id 'tempnet' -Question 'Executable sensible + connexion reseau ?' -Status 'Critique' -Detail ("Chaines={0}, findings={1}" -f $implant.Count, $tempNet.Count)))
    }

    # 6 Defender exclusions
    $excl = @($list | Where-Object { $_.Category -eq 'Defender' -and $_.Title -match 'exclusion' })
    if ($excl.Count -eq 0) {
        $items.Add((New-AuditCheckItem -Id 'defender' -Question 'Exclusions Windows Defender douteuses ?' -Status 'OK' -Detail 'Aucune exclusion signalee.'))
    }
    else {
        $st = if ($excl | Where-Object Severity -eq 'Critical') { 'Critique' } else { 'Attention' }
        $items.Add((New-AuditCheckItem -Id 'defender' -Question 'Exclusions Windows Defender douteuses ?' -Status $st -Detail ("{0} exclusion(s)" -f $excl.Count)))
    }

    # 7 WMI
    $wmi = @($list | Where-Object { $_.Category -eq 'WMI' })
    if ($wmi.Count -eq 0) {
        $items.Add((New-AuditCheckItem -Id 'wmi' -Question 'Persistence WMI furtive ?' -Status 'OK' -Detail 'Pas d''abonnement WMI suspect.'))
    }
    else {
        $st = if ($wmi | Where-Object Severity -in @('High','Critical')) { 'Critique' } else { 'Attention' }
        $items.Add((New-AuditCheckItem -Id 'wmi' -Question 'Persistence WMI furtive ?' -Status $st -Detail ("{0} finding(s) WMI" -f $wmi.Count)))
    }

    # 8 IFEO / AppInit
    $ifeo = @($list | Where-Object { $_.Category -eq 'IFEO' })
    if ($ifeo.Count -eq 0) {
        $items.Add((New-AuditCheckItem -Id 'ifeo' -Question 'Hijack IFEO / AppInit_DLLs ?' -Status 'OK' -Detail 'Pas de debugger IFEO / AppInit detecte.'))
    }
    else {
        $items.Add((New-AuditCheckItem -Id 'ifeo' -Question 'Hijack IFEO / AppInit_DLLs ?' -Status 'Critique' -Detail ("{0} finding(s)" -f $ifeo.Count)))
    }

    $ok = [int](@($items | Where-Object { $_.Status -eq 'OK' }).Count)
    $att = [int](@($items | Where-Object { $_.Status -eq 'Attention' }).Count)
    $cri = [int](@($items | Where-Object { $_.Status -eq 'Critique' }).Count)
    $verdict = if ($cri -gt 0) { 'Risque eleve - investiguer les points Critiques.' }
        elseif ($att -gt 0) { 'Points d''attention - verifier les elements marques.' }
        else { 'Aucun signal fort d''espionnage sur les checks automatiques.' }

    # Note: @($Generic.List) inside [pscustomobject] throws ArgumentException on PS 5.1
    [pscustomobject]@{
        Items     = $items.ToArray()
        Ok        = $ok
        Attention = $att
        Critique  = $cri
        Verdict   = $verdict
    }
}
