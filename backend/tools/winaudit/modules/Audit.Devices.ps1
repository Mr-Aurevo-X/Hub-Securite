# Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X

#Requires -Version 5.1
# Audit.Devices.ps1 - USB / PnP (lecture seule)

function Invoke-AuditDevicesScan {
    $findings = New-Object System.Collections.Generic.List[object]
    Write-AuditProgress -Phase 'Devices' -Percent 10 -Detail 'PnP USB...'

    try {
        $usb = @(Get-PnpDevice -Class USB -ErrorAction SilentlyContinue | Select-Object -First 120)
        foreach ($d in $usb) {
            $name = [string]$d.FriendlyName
            $status = [string]$d.Status
            $id = [string]$d.InstanceId
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $sev = 'Info'
            $why = 'Peripherique USB inventorie.'
            if ($status -eq 'Error' -or $status -eq 'Unknown') {
                $sev = 'Low'
                $why = 'Peripherique USB en etat inhabituel.'
            }
            if ($name -match '(?i)unknown|generic|composite|hid.?compliant' -and $status -eq 'OK') {
                $sev = 'Low'
                $why = 'Nom generique - verifier si peripherique attendu (HID/clavier/souris).'
            }
            $findings.Add((New-AuditFinding -Category 'USB' -Severity $sev `
                -Title ("USB: {0}" -f $name) `
                -Detail ("Status={0}" -f $status) `
                -Evidence $id `
                -WhySuspicious $why `
                -Meta @{ Status = $status; Class = 'USB' }))
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Devices' -Percent 45 -Detail 'USBSTOR historique...'
    try {
        $usbstor = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
        if (Test-Path -LiteralPath $usbstor) {
            Get-ChildItem -LiteralPath $usbstor -ErrorAction SilentlyContinue | ForEach-Object {
                $prod = $_.PSChildName
                Get-ChildItem -LiteralPath $_.PSPath -ErrorAction SilentlyContinue | Select-Object -First 3 | ForEach-Object {
                    $inst = $_.PSChildName
                    $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue
                    $friendly = if ($props.FriendlyName) { [string]$props.FriendlyName } else { $prod }
                    $findings.Add((New-AuditFinding -Category 'USB' -Severity 'Info' `
                        -Title ("USBSTOR: {0}" -f $friendly) `
                        -Detail ("Instance={0}" -f $inst) `
                        -Evidence $prod `
                        -WhySuspicious 'Stockage de masse USB deja branche sur cette machine (historique registre).' `
                        -Meta @{ Product = $prod; Instance = $inst }))
                }
            }
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Devices' -Percent 75 -Detail 'Peripheriques problematiques...'
    try {
        Get-PnpDevice -Status Error -ErrorAction SilentlyContinue | Select-Object -First 40 | ForEach-Object {
            $findings.Add((New-AuditFinding -Category 'USB' -Severity 'Low' `
                -Title ("PnP Error: {0}" -f $_.FriendlyName) `
                -Detail ([string]$_.Class) `
                -Evidence ([string]$_.InstanceId) `
                -WhySuspicious 'Peripherique en erreur - peut indiquer driver manquant ou materiel deconnecte.'))
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Devices' -Percent 95 -Detail 'Devices OK'
    return $findings
}
