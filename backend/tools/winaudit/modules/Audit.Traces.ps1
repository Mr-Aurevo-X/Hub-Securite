# Copyright (c) 2026 Mr-Aurevo-X. All rights reserved.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Author: Mr-Aurevo-X | https://github.com/Mr-Aurevo-X

#Requires -Version 5.1
# Audit.Traces.ps1 - RunMRU / Recent / UserAssist (leger, lecture seule)

function ConvertFrom-AuditRot13 {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $sb = New-Object System.Text.StringBuilder
    foreach ($ch in $Text.ToCharArray()) {
        $c = [int][char]$ch
        if ($c -ge 65 -and $c -le 90) {
            [void]$sb.Append([char](65 + (($c - 65 + 13) % 26)))
        }
        elseif ($c -ge 97 -and $c -le 122) {
            [void]$sb.Append([char](97 + (($c - 97 + 13) % 26)))
        }
        else {
            [void]$sb.Append($ch)
        }
    }
    return $sb.ToString()
}

function Invoke-AuditTracesScan {
    $findings = New-Object System.Collections.Generic.List[object]
    Write-AuditProgress -Phase 'Traces' -Percent 15 -Detail 'RunMRU...'

    try {
        $runMru = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
        if (Test-Path -LiteralPath $runMru) {
            $props = Get-ItemProperty -LiteralPath $runMru -ErrorAction SilentlyContinue
            foreach ($p in @($props.PSObject.Properties)) {
                if ($p.Name -in @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider','MRUList')) { continue }
                $val = [string]$p.Value
                if ([string]::IsNullOrWhiteSpace($val)) { continue }
                $clean = $val.TrimEnd('\1').Trim()
                $sev = 'Info'
                $why = 'Commande recente via Win+R.'
                if ($clean -match '(?i)\\temp\\|\\downloads\\|powershell|cmd\.exe|mshta|rundll32|regsvr32|bitsadmin|certutil') {
                    $sev = 'Low'
                    $why = 'Commande RunMRU vers zone sensible ou outil living-off-the-land.'
                }
                if ($clean -match '(?i)\\temp\\|\\downloads\\') {
                    $sev = 'Medium'
                    $why = 'Execution recente depuis Temp/Downloads via Run.'
                }
                $findings.Add((New-AuditFinding -Category 'Trace' -Severity $sev `
                    -Title ("RunMRU: {0}" -f ($(if ($clean.Length -gt 80) { $clean.Substring(0, 80) + '...' } else { $clean }))) `
                    -Detail $clean -Evidence $p.Name `
                    -WhySuspicious $why `
                    -Path $(if ($clean -match '^[a-zA-Z]:\\') { ($clean -split '\s+')[0].Trim('"') } else { '' })))
            }
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Traces' -Percent 45 -Detail 'Recent...'
    try {
        $recent = [Environment]::GetFolderPath('Recent')
        if ($recent -and (Test-Path -LiteralPath $recent)) {
            $items = @(Get-ChildItem -LiteralPath $recent -ErrorAction SilentlyContinue)
            $findings.Add((New-AuditFinding -Category 'Trace' -Severity 'Info' `
                -Title ("Fichiers Recent: {0}" -f $items.Count) `
                -Detail $recent -Evidence $recent `
                -WhySuspicious 'Compte des raccourcis Recent - trace d''activite locale.'))
            $suspect = @($items | Where-Object {
                $_.Name -match '(?i)\.(exe|scr|bat|cmd|ps1|vbs|js)\.lnk$' -or
                $_.Name -match '(?i)temp|download'
            } | Select-Object -First 15)
            foreach ($s in $suspect) {
                $findings.Add((New-AuditFinding -Category 'Trace' -Severity 'Low' `
                    -Title ("Recent suspect: {0}" -f $s.Name) `
                    -Path $s.FullName -Evidence $s.Name `
                    -WhySuspicious 'Raccourci Recent vers executable ou zone sensible.'))
            }
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Traces' -Percent 70 -Detail 'UserAssist...'
    try {
        $uaRoot = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
        if (Test-Path -LiteralPath $uaRoot) {
            $count = 0
            Get-ChildItem -LiteralPath $uaRoot -ErrorAction SilentlyContinue | ForEach-Object {
                $countPath = Join-Path $_.PSPath 'Count'
                if (-not (Test-Path -LiteralPath $countPath)) { return }
                Get-Item -LiteralPath $countPath -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty Property -ErrorAction SilentlyContinue |
                    Select-Object -First 40 | ForEach-Object {
                        $enc = [string]$_
                        $dec = ConvertFrom-AuditRot13 $enc
                        if ($dec -match '(?i)\\temp\\|\\downloads\\|appdata\\local\\temp') {
                            $findings.Add((New-AuditFinding -Category 'Trace' -Severity 'Medium' `
                                -Title ("UserAssist Temp/Downloads: {0}" -f ($(if ($dec.Length -gt 90) { $dec.Substring(0, 90) + '...' } else { $dec }))) `
                                -Detail $dec -Evidence $enc `
                                -WhySuspicious 'Execution tracee depuis Temp/Downloads (UserAssist).' `
                                -Path $(if ($dec -match '([a-zA-Z]:\\[^\\]+(?:\\[^\\]+)*\.(?:exe|dll|scr|bat|cmd|ps1))') { $Matches[1] } else { '' })))
                            $count++
                        }
                        elseif ($count -lt 8 -and $dec -match '(?i)\.(exe|scr|bat|cmd|ps1)$') {
                            $findings.Add((New-AuditFinding -Category 'Trace' -Severity 'Info' `
                                -Title ("UserAssist: {0}" -f ([IO.Path]::GetFileName($dec))) `
                                -Detail $dec -Evidence 'UserAssist' `
                                -WhySuspicious 'Programme execute recemment (inventaire UserAssist).'))
                            $count++
                        }
                    }
            }
        }
    }
    catch { }

    Write-AuditProgress -Phase 'Traces' -Percent 95 -Detail 'Traces OK'
    return $findings
}
