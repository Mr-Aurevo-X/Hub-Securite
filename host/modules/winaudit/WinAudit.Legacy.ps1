#Requires -Version 5.1
<#
.SYNOPSIS
    WinAudit Pro - Scan d'anomalies Windows (lecture seule)
#>
[CmdletBinding()]
param([switch]$NoElevate)

$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

$Global:WinAuditRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Global:WinAuditRoot) { $Global:WinAuditRoot = $PSScriptRoot }

$modDir = Join-Path $Global:WinAuditRoot 'modules'
    @(
    'Elevate.ps1'
    'Audit.Core.ps1'
    'Audit.Hash.ps1'
    'Audit.Baseline.ps1'
    'Audit.Checklist.ps1'
    'Audit.Deduce.ps1'
    'Audit.Persistence.ps1'
    'Audit.Runtime.ps1'
    'Audit.Network.ps1'
    'Audit.Devices.ps1'
    'Audit.Accounts.ps1'
    'Audit.Traces.ps1'
    'Audit.Surface.ps1'
    'Audit.Orchestrator.ps1'
) | ForEach-Object { . (Join-Path $modDir $_) }

if (-not $NoElevate) {
    if (-not (Test-WinAuditAdmin)) {
        $null = Request-WinAuditAdmin -ScriptPath $MyInvocation.MyCommand.Path
        exit
    }
}

$logsDir = Join-Path $Global:WinAuditRoot 'logs'
if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir -Force | Out-Null }

# Palette alignee sur WinCleaner (ui/styles.css)
$theme = @{
    Bg         = [Drawing.Color]::FromArgb(12, 15, 20)      # --bg0
    Surface    = [Drawing.Color]::FromArgb(18, 23, 31)      # --bg1
    Surface2   = [Drawing.Color]::FromArgb(24, 30, 41)      # --bg2
    Surface3   = [Drawing.Color]::FromArgb(28, 36, 48)
    ChartBg    = [Drawing.Color]::FromArgb(18, 23, 31)
    Border     = [Drawing.Color]::FromArgb(48, 56, 70)
    Fg         = [Drawing.Color]::FromArgb(232, 237, 245)   # --text
    Muted      = [Drawing.Color]::FromArgb(139, 151, 168)   # --muted
    Accent     = [Drawing.Color]::FromArgb(224, 53, 69)     # --accent #e03545
    AccentDim  = [Drawing.Color]::FromArgb(16, 48, 46)      # accent-dim solid
    AccentSoft = [Drawing.Color]::FromArgb(22, 40, 42)
    Danger     = [Drawing.Color]::FromArgb(240, 113, 120)   # --danger
    Warn       = [Drawing.Color]::FromArgb(240, 180, 41)    # --warn
    High       = [Drawing.Color]::FromArgb(251, 146, 60)
    Ok         = [Drawing.Color]::FromArgb(74, 222, 128)
    Sidebar    = [Drawing.Color]::FromArgb(10, 12, 16)
    NavActive  = [Drawing.Color]::FromArgb(16, 48, 46)
}

$script:LastResult = $null
$script:LastExport = $null
$script:ScanRunning = $false
$script:HasScan = $false
$script:ScoreValue = -1
$script:ScoreLabel = 'En attente'
$script:SevCounts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
$script:CatStats = @()

function New-UiFont {
    param([float]$Size = 9, [string]$Style = 'Regular')
    $fs = [Drawing.FontStyle]::Regular
    if ($Style -eq 'Bold') { $fs = [Drawing.FontStyle]::Bold }
    return New-Object Drawing.Font('Segoe UI', $Size, $fs)
}

function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        'Critical' { $theme.Danger }
        'High'     { $theme.High }
        'Medium'   { $theme.Warn }
        'Low'      { $theme.Accent }
        default    { $theme.Muted }
    }
}

function New-DarkButton {
    param([string]$Text, [int]$Width = 140, [int]$Height = 40, [string]$Variant = 'Default')
    $b = New-Object Windows.Forms.Button
    $b.Text = $Text
    $b.Size = New-Object Drawing.Size($Width, $Height)
    $b.FlatStyle = 'Flat'
    $b.Cursor = [Windows.Forms.Cursors]::Hand
    $b.Font = New-UiFont 9
    $b.FlatAppearance.BorderSize = 1
    $b.FlatAppearance.MouseOverBackColor = $theme.Surface3
    switch ($Variant) {
        'Accent' {
            $b.BackColor = $theme.AccentDim
            $b.ForeColor = $theme.Accent
            $b.FlatAppearance.BorderColor = $theme.Accent
            $b.Font = New-UiFont 9.5 'Bold'
            $b.FlatAppearance.MouseOverBackColor = [Drawing.Color]::FromArgb(24, 90, 74)
        }
        'Ghost' {
            $b.BackColor = $theme.Surface
            $b.ForeColor = $theme.Muted
            $b.FlatAppearance.BorderColor = $theme.Border
            $b.FlatAppearance.MouseOverBackColor = $theme.AccentSoft
        }
        default {
            $b.BackColor = $theme.Surface2
            $b.ForeColor = $theme.Fg
            $b.FlatAppearance.BorderColor = $theme.Border
        }
    }
    return $b
}

function New-OutlinedPanel {
    param([Drawing.Color]$Back = $theme.Surface)
    $p = New-Object Windows.Forms.Panel
    $p.BackColor = $Back
    $p.Margin = New-Object Windows.Forms.Padding(0)
    $p.Add_Paint({
        param($sender, $e)
        $pen = New-Object Drawing.Pen $theme.Border, 1
        $e.Graphics.DrawRectangle($pen, 0, 0, $sender.ClientSize.Width - 1, $sender.ClientSize.Height - 1)
        $pen.Dispose()
    })
    return $p
}

# ===================== FORM =====================
$form = New-Object Windows.Forms.Form
$form.Text = 'WinAudit Pro'
$form.Size = New-Object Drawing.Size(1340, 880)
$form.MinimumSize = New-Object Drawing.Size(1100, 700)
$form.StartPosition = 'CenterScreen'
$form.BackColor = $theme.Bg
$form.Font = New-UiFont 9

# ---------- Sidebar ----------
$sidebar = New-Object Windows.Forms.Panel
$sidebar.Dock = 'Left'
$sidebar.Width = 232
$sidebar.BackColor = $theme.Sidebar
$form.Controls.Add($sidebar)

$picBrand = New-Object Windows.Forms.PictureBox
$picBrand.Size = New-Object Drawing.Size(40, 40)
$picBrand.Location = New-Object Drawing.Point(18, 18)
$picBrand.SizeMode = 'Zoom'
$picBrand.BackColor = $theme.Sidebar
$brandIconPath = Join-Path $Global:WinAuditRoot 'ui\brand-icon.png'
if (Test-Path -LiteralPath $brandIconPath) {
    try { $picBrand.Image = [Drawing.Image]::FromFile($brandIconPath) } catch { }
}
$sidebar.Controls.Add($picBrand)

$lblBrand = New-Object Windows.Forms.Label
$lblBrand.Text = 'WinAudit'
$lblBrand.ForeColor = $theme.Accent
$lblBrand.Font = New-UiFont 16 'Bold'
$lblBrand.Location = New-Object Drawing.Point(66, 16)
$lblBrand.Size = New-Object Drawing.Size(150, 28)
$lblBrand.AutoSize = $false
$lblBrand.BackColor = $theme.Sidebar
$sidebar.Controls.Add($lblBrand)

$lblPro = New-Object Windows.Forms.Label
$lblPro.Text = 'Scan only | lecture seule'
$lblPro.ForeColor = $theme.Muted
$lblPro.Font = New-UiFont 8
$lblPro.Location = New-Object Drawing.Point(66, 42)
$lblPro.Size = New-Object Drawing.Size(150, 18)
$lblPro.AutoSize = $false
$lblPro.BackColor = $theme.Sidebar
$lblPro.UseCompatibleTextRendering = $true
$lblPro.TextAlign = 'MiddleLeft'
$sidebar.Controls.Add($lblPro)

$badgeAdmin = New-Object Windows.Forms.Label
$badgeAdmin.Text = 'ADMIN'
$badgeAdmin.Font = New-UiFont 7.5 'Bold'
$badgeAdmin.AutoSize = $false
$badgeAdmin.Size = New-Object Drawing.Size(72, 22)
$badgeAdmin.Location = New-Object Drawing.Point(18, 68)
$badgeAdmin.TextAlign = 'MiddleCenter'
$badgeAdmin.BackColor = $theme.AccentDim
$badgeAdmin.ForeColor = $theme.Accent
$sidebar.Controls.Add($badgeAdmin)

$navButtons = @{}
$navMeta = @(
    @{ Key = 'Overview'; Label = 'Overview' }
    @{ Key = 'Findings'; Label = 'Findings' }
    @{ Key = 'Reseau';   Label = 'Reseau' }
    @{ Key = 'Chains';   Label = 'Chaines' }
    @{ Key = 'Timeline'; Label = 'Timeline' }
)
$ny = 104
foreach ($item in $navMeta) {
    $nb = New-Object Windows.Forms.Button
    $nb.Text = '  ' + $item.Label
    $nb.Tag = $item.Key
    $nb.Size = New-Object Drawing.Size(200, 40)
    $nb.Location = New-Object Drawing.Point(16, $ny)
    $nb.FlatStyle = 'Flat'
    $nb.FlatAppearance.BorderSize = 0
    $nb.FlatAppearance.MouseOverBackColor = $theme.AccentSoft
    $nb.TextAlign = 'MiddleLeft'
    $nb.Font = New-UiFont 9.5
    $nb.BackColor = $theme.Sidebar
    $nb.ForeColor = $theme.Muted
    $nb.Cursor = [Windows.Forms.Cursors]::Hand
    $sidebar.Controls.Add($nb)
    $navButtons[$item.Key] = $nb
    $ny += 46
}

$btnScan = New-DarkButton -Text 'Lancer le scan' -Width 200 -Height 40 -Variant 'Accent'
$btnScan.Location = New-Object Drawing.Point(16, 350)
$sidebar.Controls.Add($btnScan)

$btnExport = New-DarkButton -Text 'Exporter rapport' -Width 200 -Height 32 -Variant 'Ghost'
$btnExport.Location = New-Object Drawing.Point(16, 400)
$btnExport.Enabled = $false
$sidebar.Controls.Add($btnExport)

$btnOpenHtml = New-DarkButton -Text 'Ouvrir dashboard HTML' -Width 200 -Height 32 -Variant 'Ghost'
$btnOpenHtml.Location = New-Object Drawing.Point(16, 438)
$btnOpenHtml.Enabled = $false
$sidebar.Controls.Add($btnOpenHtml)

$btnPrintA4 = New-DarkButton -Text 'Rapport A4' -Width 200 -Height 32 -Variant 'Ghost'
$btnPrintA4.Location = New-Object Drawing.Point(16, 476)
$btnPrintA4.Enabled = $false
$sidebar.Controls.Add($btnPrintA4)

$btnWhitelist = New-DarkButton -Text 'Whitelist' -Width 200 -Height 32 -Variant 'Ghost'
$btnWhitelist.Location = New-Object Drawing.Point(16, 514)
$sidebar.Controls.Add($btnWhitelist)

$lblSideHint = New-Object Windows.Forms.Label
$lblSideHint.Text = "Lecture seule`nAucune suppression`nHeuristique locale"
$lblSideHint.ForeColor = $theme.Muted
$lblSideHint.Font = New-UiFont 7.5
$lblSideHint.Size = New-Object Drawing.Size(200, 48)
$lblSideHint.Anchor = 'Bottom,Left'
$lblSideHint.Location = New-Object Drawing.Point(16, 740)
$sidebar.Controls.Add($lblSideHint)

$lblCopyright = New-Object Windows.Forms.Label
$lblCopyright.Text = [char]0x00A9 + ' 2026 Mr-Aurevo-X'
$lblCopyright.ForeColor = $theme.Muted
$lblCopyright.Font = New-UiFont 7.5
$lblCopyright.Size = New-Object Drawing.Size(200, 22)
$lblCopyright.Anchor = 'Bottom,Left'
$lblCopyright.Location = New-Object Drawing.Point(16, 800)
$lblCopyright.TextAlign = 'MiddleLeft'
$sidebar.Controls.Add($lblCopyright)

# ---------- Main column (TableLayout) ----------
$mainLayout = New-Object Windows.Forms.TableLayoutPanel
$mainLayout.Dock = 'Fill'
$mainLayout.BackColor = $theme.Bg
$mainLayout.ColumnCount = 1
$mainLayout.RowCount = 3
$mainLayout.Padding = New-Object Windows.Forms.Padding(0)
[void]$mainLayout.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 100)))
[void]$mainLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 86)))
[void]$mainLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 5)))
[void]$mainLayout.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100)))
$form.Controls.Add($mainLayout)
$mainLayout.BringToFront()

# Header
$header = New-Object Windows.Forms.Panel
$header.Dock = 'Fill'
$header.BackColor = $theme.Bg
$mainLayout.Controls.Add($header, 0, 0)

$lblTitle = New-Object Windows.Forms.Label
$lblTitle.Text = 'Overview'
$lblTitle.ForeColor = $theme.Fg
$lblTitle.Font = New-UiFont 18 'Bold'
$lblTitle.Location = New-Object Drawing.Point(28, 16)
$lblTitle.AutoSize = $true
$header.Controls.Add($lblTitle)

$lblStatus = New-Object Windows.Forms.Label
$lblStatus.Text = 'Pret - lancez un scan pour cartographier les anomalies du PC.'
$lblStatus.ForeColor = $theme.Muted
$lblStatus.Font = New-UiFont 9
$lblStatus.Location = New-Object Drawing.Point(30, 50)
$lblStatus.AutoSize = $true
$header.Controls.Add($lblStatus)

# Progress
$progressHost = New-Object Windows.Forms.Panel
$progressHost.Dock = 'Fill'
$progressHost.BackColor = $theme.Surface3
$progressHost.Visible = $true
$mainLayout.Controls.Add($progressHost, 0, 1)

$progress = New-Object Windows.Forms.ProgressBar
$progress.Dock = 'Fill'
$progress.Style = 'Continuous'
$progress.Minimum = 0
$progress.Maximum = 100
$progress.Value = 0
$progressHost.Controls.Add($progress)
$progressHost.Visible = $false

# Content host
$content = New-Object Windows.Forms.Panel
$content.Dock = 'Fill'
$content.BackColor = $theme.Bg
$content.Padding = New-Object Windows.Forms.Padding(20, 8, 20, 16)
$mainLayout.Controls.Add($content, 0, 2)

# ================= OVERVIEW =================
$panelOverview = New-Object Windows.Forms.TableLayoutPanel
$panelOverview.Dock = 'Fill'
$panelOverview.BackColor = $theme.Bg
$panelOverview.ColumnCount = 1
$panelOverview.RowCount = 3
$panelOverview.Padding = New-Object Windows.Forms.Padding(4)
[void]$panelOverview.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 100)))
[void]$panelOverview.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 78)))
[void]$panelOverview.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 270)))
[void]$panelOverview.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100)))
$content.Controls.Add($panelOverview)

# --- Stats row ---
$statRow = New-Object Windows.Forms.TableLayoutPanel
$statRow.Dock = 'Fill'
$statRow.ColumnCount = 4
$statRow.RowCount = 1
$statRow.BackColor = $theme.Bg
1..4 | ForEach-Object {
    [void]$statRow.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 25)))
}
[void]$statRow.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100)))
$panelOverview.Controls.Add($statRow, 0, 0)

function New-StatPill {
    param([string]$Caption)
    $wrap = New-OutlinedPanel
    $wrap.Dock = 'Fill'
    $wrap.Margin = New-Object Windows.Forms.Padding(0, 0, 10, 0)

    $cap = New-Object Windows.Forms.Label
    $cap.Text = $Caption.ToUpperInvariant()
    $cap.ForeColor = $theme.Muted
    $cap.Font = New-UiFont 7 'Bold'
    $cap.Location = New-Object Drawing.Point(16, 12)
    $cap.AutoSize = $true
    $wrap.Controls.Add($cap)

    $val = New-Object Windows.Forms.Label
    $val.Name = 'Value'
    $val.Text = '--'
    $val.ForeColor = $theme.Fg
    $val.Font = New-UiFont 18 'Bold'
    $val.Location = New-Object Drawing.Point(16, 32)
    $val.AutoSize = $true
    $wrap.Controls.Add($val)
    return $wrap
}

$pillScore = New-StatPill 'Score'
$pillFindings = New-StatPill 'Findings'
$pillChains = New-StatPill 'Chaines'
$pillTime = New-StatPill 'Duree'
$statRow.Controls.Add($pillScore, 0, 0)
$statRow.Controls.Add($pillFindings, 1, 0)
$statRow.Controls.Add($pillChains, 2, 0)
$statRow.Controls.Add($pillTime, 3, 0)
$pillTime.Margin = New-Object Windows.Forms.Padding(0)

# --- Charts row ---
$chartRow = New-Object Windows.Forms.TableLayoutPanel
$chartRow.Dock = 'Fill'
$chartRow.ColumnCount = 3
$chartRow.RowCount = 1
$chartRow.BackColor = $theme.Bg
$chartRow.Margin = New-Object Windows.Forms.Padding(0, 10, 0, 0)
[void]$chartRow.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 28)))
[void]$chartRow.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 36)))
[void]$chartRow.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 36)))
[void]$chartRow.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100)))
$panelOverview.Controls.Add($chartRow, 0, 1)

function Add-CardTitle {
    param($Panel, [string]$Text)
    $t = New-Object Windows.Forms.Label
    $t.Text = $Text
    $t.ForeColor = $theme.Muted
    $t.Font = New-UiFont 8 'Bold'
    $t.Location = New-Object Drawing.Point(16, 12)
    $t.AutoSize = $true
    $Panel.Controls.Add($t)
}

$cardScore = New-OutlinedPanel
$cardScore.Dock = 'Fill'
$cardScore.Margin = New-Object Windows.Forms.Padding(0, 0, 10, 0)
Add-CardTitle $cardScore 'SANTE'
$chartRow.Controls.Add($cardScore, 0, 0)

$cardScore.Add_Paint({
    param($s, $e)
    $g = $e.Graphics
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear($theme.Surface)
    # redraw border
    $penB = New-Object Drawing.Pen $theme.Border, 1
    $g.DrawRectangle($penB, 0, 0, $s.Width - 1, $s.Height - 1)
    $penB.Dispose()
    # title
    $tb = New-Object Drawing.SolidBrush $theme.Muted
    $g.DrawString('SANTE', (New-UiFont 8 'Bold'), $tb, 16, 12)
    $tb.Dispose()

    $w = $s.ClientSize.Width
    $h = $s.ClientSize.Height
    $size = [Math]::Min($w - 40, $h - 60)
    if ($size -lt 80) { return }
    $cx = [int]($w / 2)
    $cy = [int](($h + 20) / 2)
    $r = [int]($size / 2)
    $rect = New-Object Drawing.Rectangle(($cx - $r), ($cy - $r), ($r * 2), ($r * 2))

    $penBg = New-Object Drawing.Pen $theme.Surface3, 12
    $g.DrawArc($penBg, $rect, 135, 270)
    $penBg.Dispose()

    $sf = New-Object Drawing.StringFormat
    $sf.Alignment = 'Center'
    $sf.LineAlignment = 'Center'
    $rectF = New-Object Drawing.RectangleF([float]$rect.X, [float]$rect.Y, [float]$rect.Width, [float]$rect.Height)

    if ($script:ScoreValue -lt 0) {
        $m = New-Object Drawing.SolidBrush $theme.Muted
        $g.DrawString('--', (New-UiFont 28 'Bold'), $m, $rectF, $sf)
        $g.DrawString('En attente', (New-UiFont 9), $m, [float]($cx - 40), [float]($cy + 28))
        $m.Dispose(); $sf.Dispose()
        return
    }

    $pct = [Math]::Max(0, [Math]::Min(100, $script:ScoreValue))
    $col = if ($pct -ge 85) { $theme.Ok } elseif ($pct -ge 65) { $theme.Accent } elseif ($pct -ge 40) { $theme.Warn } else { $theme.Danger }
    $pen = New-Object Drawing.Pen $col, 12
    $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
    $g.DrawArc($pen, $rect, 135, [int](270 * $pct / 100.0))
    $pen.Dispose()
    $br = New-Object Drawing.SolidBrush $theme.Fg
    $g.DrawString("$pct", (New-UiFont 32 'Bold'), $br, $rectF, $sf)
    $br.Dispose()
    $m = New-Object Drawing.SolidBrush $theme.Muted
    $g.DrawString($script:ScoreLabel, (New-UiFont 9), $m, [float]($cx - 50), [float]($cy + 30))
    $m.Dispose(); $sf.Dispose()
})

$cardSev = New-OutlinedPanel
$cardSev.Dock = 'Fill'
$cardSev.Margin = New-Object Windows.Forms.Padding(0, 0, 10, 0)
$chartRow.Controls.Add($cardSev, 1, 0)

$cardSev.Add_Paint({
    param($s, $e)
    $g = $e.Graphics
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear($theme.Surface)
    $penB = New-Object Drawing.Pen $theme.Border, 1
    $g.DrawRectangle($penB, 0, 0, $s.Width - 1, $s.Height - 1)
    $penB.Dispose()
    $tb = New-Object Drawing.SolidBrush $theme.Muted
    $g.DrawString('SEVERITE', (New-UiFont 8 'Bold'), $tb, 16, 12)
    $tb.Dispose()

    $keys = @('Critical','High','Medium','Low','Info')
    $total = 0
    foreach ($k in $keys) { $total += [int]$script:SevCounts[$k] }
    if ($total -eq 0 -and -not $script:HasScan) {
        $m = New-Object Drawing.SolidBrush $theme.Muted
        $g.DrawString('Les comptes apparaitront apres le scan.', (New-UiFont 9), $m, 16, 120)
        $m.Dispose()
        return
    }

    $y = 48
    $barMax = [Math]::Max(80, $s.Width - 140)
    foreach ($k in $keys) {
        $c = [int]$script:SevCounts[$k]
        $wbar = if ($total -gt 0) { [Math]::Max(0, [int]($barMax * $c / $total)) } else { 0 }
        if ($c -gt 0 -and $wbar -lt 4) { $wbar = 4 }

        $lb = New-Object Drawing.SolidBrush $theme.Muted
        $g.DrawString($k, (New-UiFont 8), $lb, 16, $y)
        $lb.Dispose()

        $track = New-Object Drawing.SolidBrush $theme.Surface3
        $g.FillRectangle($track, 90, ($y + 3), $barMax, 11)
        $track.Dispose()
        if ($wbar -gt 0) {
            $br = New-Object Drawing.SolidBrush (Get-SeverityColor $k)
            $g.FillRectangle($br, 90, ($y + 3), $wbar, 11)
            $br.Dispose()
        }
        $vb = New-Object Drawing.SolidBrush $theme.Fg
        $g.DrawString("$c", (New-UiFont 8 'Bold'), $vb, (96 + $barMax), $y)
        $vb.Dispose()
        $y += 38
    }
})

$cardCat = New-OutlinedPanel
$cardCat.Dock = 'Fill'
$cardCat.Margin = New-Object Windows.Forms.Padding(0)
$chartRow.Controls.Add($cardCat, 2, 0)

$cardCat.Add_Paint({
    param($s, $e)
    $g = $e.Graphics
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear($theme.Surface)
    $penB = New-Object Drawing.Pen $theme.Border, 1
    $g.DrawRectangle($penB, 0, 0, $s.Width - 1, $s.Height - 1)
    $penB.Dispose()
    $tb = New-Object Drawing.SolidBrush $theme.Muted
    $g.DrawString('CATEGORIES', (New-UiFont 8 'Bold'), $tb, 16, 12)
    $tb.Dispose()

    $stats = @($script:CatStats | Select-Object -First 6)
    if ($stats.Count -eq 0) {
        $m = New-Object Drawing.SolidBrush $theme.Muted
        $msg = if ($script:HasScan) { 'Aucune categorie.' } else { 'Repartition par domaine apres le scan.' }
        $g.DrawString($msg, (New-UiFont 9), $m, 16, 120)
        $m.Dispose()
        return
    }

    $max = ($stats | Measure-Object Count -Maximum).Maximum
    if ($max -lt 1) { $max = 1 }
    $n = $stats.Count
    $gap = 8
    $avail = $s.Width - 36
    $barW = [Math]::Max(16, [int](($avail - $gap * ($n - 1)) / $n))
    $x = 18
    $baseY = $s.Height - 36
    $maxH = $s.Height - 80
    foreach ($st in $stats) {
        $bh = [Math]::Max(4, [int]($maxH * ([int]$st.Count) / $max))
        $y = $baseY - $bh
        $br = New-Object Drawing.SolidBrush $theme.Accent
        $g.FillRectangle($br, $x, $y, $barW, $bh)
        $br.Dispose()
        $vb = New-Object Drawing.SolidBrush $theme.Fg
        $g.DrawString("$($st.Count)", (New-UiFont 7 'Bold'), $vb, $x, ($y - 14))
        $vb.Dispose()
        $name = [string]$st.Category
        if ($name.Length -gt 8) { $name = $name.Substring(0, 7) + '.' }
        $mb = New-Object Drawing.SolidBrush $theme.Muted
        $g.DrawString($name, (New-UiFont 7), $mb, $x, ($baseY + 4))
        $mb.Dispose()
        $x += $barW + $gap
    }
})

# --- Bottom: diff + checklist + priorities ---
$cardPrio = New-OutlinedPanel
$cardPrio.Dock = 'Fill'
$cardPrio.Margin = New-Object Windows.Forms.Padding(0, 12, 0, 0)
$panelOverview.Controls.Add($cardPrio, 0, 2)

$bottomSplit = New-Object Windows.Forms.TableLayoutPanel
$bottomSplit.Dock = 'Fill'
$bottomSplit.ColumnCount = 2
$bottomSplit.RowCount = 2
$bottomSplit.Padding = New-Object Windows.Forms.Padding(8, 4, 8, 8)
[void]$bottomSplit.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 48)))
[void]$bottomSplit.ColumnStyles.Add((New-Object Windows.Forms.ColumnStyle([Windows.Forms.SizeType]::Percent, 52)))
[void]$bottomSplit.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute, 28)))
[void]$bottomSplit.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent, 100)))
$cardPrio.Controls.Add($bottomSplit)

$lblDiff = New-Object Windows.Forms.Label
$lblDiff.Text = 'DEPUIS LE DERNIER SCAN: lancez un scan'
$lblDiff.ForeColor = $theme.Accent
$lblDiff.Font = New-UiFont 8 'Bold'
$lblDiff.Dock = 'Fill'
$lblDiff.TextAlign = 'MiddleLeft'
$bottomSplit.Controls.Add($lblDiff, 0, 0)
$bottomSplit.SetColumnSpan($lblDiff, 2)

$lblCheckTitle = New-Object Windows.Forms.Label
$lblCheckTitle.Text = 'CHECKLIST ESPIONNAGE'
$lblCheckTitle.ForeColor = $theme.Muted
$lblCheckTitle.Font = New-UiFont 8 'Bold'
$lblCheckTitle.Dock = 'Top'
$lblCheckTitle.Height = 22

$listChecklist = New-Object Windows.Forms.ListBox
$listChecklist.Dock = 'Fill'
$listChecklist.BackColor = $theme.ChartBg
$listChecklist.ForeColor = $theme.Fg
$listChecklist.BorderStyle = 'None'
$listChecklist.Font = New-UiFont 9
$listChecklist.IntegralHeight = $false
$listChecklist.ItemHeight = 26
[void]$listChecklist.Items.Add('  Lancez un scan pour remplir la checklist.')

$checkHost = New-Object Windows.Forms.Panel
$checkHost.Dock = 'Fill'
$checkHost.Margin = New-Object Windows.Forms.Padding(0, 0, 8, 0)
$checkHost.Controls.Add($listChecklist)
$checkHost.Controls.Add($lblCheckTitle)
$listChecklist.BringToFront()
$bottomSplit.Controls.Add($checkHost, 0, 1)

$lblPrio = New-Object Windows.Forms.Label
$lblPrio.Text = 'PRIORITES DEDUITES'
$lblPrio.ForeColor = $theme.Muted
$lblPrio.Font = New-UiFont 8 'Bold'
$lblPrio.Dock = 'Top'
$lblPrio.Height = 22

$listPriorities = New-Object Windows.Forms.ListBox
$listPriorities.Dock = 'Fill'
$listPriorities.BackColor = $theme.ChartBg
$listPriorities.ForeColor = $theme.Fg
$listPriorities.BorderStyle = 'None'
$listPriorities.Font = New-UiFont 9
$listPriorities.IntegralHeight = $false
$listPriorities.ItemHeight = 26
[void]$listPriorities.Items.Add('  Cliquez sur "Lancer le scan" pour analyser le PC.')

$prioHost = New-Object Windows.Forms.Panel
$prioHost.Dock = 'Fill'
$prioHost.Controls.Add($listPriorities)
$prioHost.Controls.Add($lblPrio)
$listPriorities.BringToFront()
$bottomSplit.Controls.Add($prioHost, 1, 1)

# ================= FINDINGS =================
$panelFindings = New-Object Windows.Forms.Panel
$panelFindings.Dock = 'Fill'
$panelFindings.Visible = $false
$panelFindings.BackColor = $theme.Bg
$content.Controls.Add($panelFindings)

$findBar = New-Object Windows.Forms.Panel
$findBar.Dock = 'Top'
$findBar.Height = 48
$findBar.BackColor = $theme.Bg
$panelFindings.Controls.Add($findBar)

$txtFilter = New-Object Windows.Forms.TextBox
$txtFilter.Location = New-Object Drawing.Point(4, 10)
$txtFilter.Size = New-Object Drawing.Size(300, 28)
$txtFilter.BackColor = $theme.Surface2
$txtFilter.ForeColor = $theme.Fg
$txtFilter.BorderStyle = 'FixedSingle'
$findBar.Controls.Add($txtFilter)

$cmbSev = New-Object Windows.Forms.ComboBox
$cmbSev.Location = New-Object Drawing.Point(316, 10)
$cmbSev.Width = 140
$cmbSev.DropDownStyle = 'DropDownList'
$cmbSev.BackColor = $theme.Surface2
$cmbSev.ForeColor = $theme.Fg
$cmbSev.FlatStyle = 'Flat'
@('Toutes','Critical','High','Medium','Low','Info') | ForEach-Object { [void]$cmbSev.Items.Add($_) }
$cmbSev.SelectedIndex = 0
$findBar.Controls.Add($cmbSev)

$lblFindCount = New-Object Windows.Forms.Label
$lblFindCount.Location = New-Object Drawing.Point(470, 14)
$lblFindCount.AutoSize = $true
$lblFindCount.ForeColor = $theme.Muted
$findBar.Controls.Add($lblFindCount)

$grid = New-Object Windows.Forms.DataGridView
$grid.Dock = 'Fill'
$grid.BackgroundColor = $theme.ChartBg
$grid.BorderStyle = 'None'
$grid.RowHeadersVisible = $false
$grid.AllowUserToAddRows = $false
$grid.ReadOnly = $true
$grid.SelectionMode = 'FullRowSelect'
$grid.AutoSizeColumnsMode = 'Fill'
$grid.RowTemplate.Height = 34
$grid.ColumnHeadersHeight = 38
$grid.DefaultCellStyle.BackColor = $theme.ChartBg
$grid.DefaultCellStyle.ForeColor = $theme.Fg
$grid.DefaultCellStyle.SelectionBackColor = $theme.AccentDim
$grid.DefaultCellStyle.SelectionForeColor = $theme.Accent
$grid.AlternatingRowsDefaultCellStyle.BackColor = $theme.Surface2
$grid.AlternatingRowsDefaultCellStyle.ForeColor = $theme.Fg
$grid.AlternatingRowsDefaultCellStyle.SelectionBackColor = $theme.AccentDim
$grid.AlternatingRowsDefaultCellStyle.SelectionForeColor = $theme.Accent
$grid.ColumnHeadersDefaultCellStyle.BackColor = $theme.Surface2
$grid.ColumnHeadersDefaultCellStyle.ForeColor = $theme.Muted
$grid.EnableHeadersVisualStyles = $false
$grid.GridColor = $theme.Border
$grid.CellBorderStyle = 'SingleHorizontal'
[void]$grid.Columns.Add('Severity', 'Severite')
[void]$grid.Columns.Add('Category', 'Cat.')
[void]$grid.Columns.Add('Title', 'Titre')
[void]$grid.Columns.Add('Path', 'Chemin')
[void]$grid.Columns.Add('Hash', 'SHA256')
[void]$grid.Columns.Add('Why', 'Pourquoi')
$grid.Columns[0].FillWeight = 9
$grid.Columns[1].FillWeight = 10
$grid.Columns[2].FillWeight = 18
$grid.Columns[3].FillWeight = 22
$grid.Columns[4].FillWeight = 18
$grid.Columns[5].FillWeight = 23
$panelFindings.Controls.Add($grid)
$grid.BringToFront()

# ================= RESEAU =================
$panelReseau = New-Object Windows.Forms.Panel
$panelReseau.Dock = 'Fill'
$panelReseau.Visible = $false
$panelReseau.BackColor = $theme.Bg
$content.Controls.Add($panelReseau)

$netBar = New-Object Windows.Forms.Panel
$netBar.Dock = 'Top'
$netBar.Height = 78
$netBar.BackColor = $theme.Bg
$panelReseau.Controls.Add($netBar)

$lblNetStats = New-Object Windows.Forms.Label
$lblNetStats.Text = 'Aucune donnee - lancez un scan.'
$lblNetStats.ForeColor = $theme.Muted
$lblNetStats.Font = New-UiFont 9
$lblNetStats.Location = New-Object Drawing.Point(4, 8)
$lblNetStats.AutoSize = $true
$netBar.Controls.Add($lblNetStats)

$cmbNetFilter = New-Object Windows.Forms.ComboBox
$cmbNetFilter.Location = New-Object Drawing.Point(4, 40)
$cmbNetFilter.Width = 160
$cmbNetFilter.DropDownStyle = 'DropDownList'
$cmbNetFilter.BackColor = $theme.Surface2
$cmbNetFilter.ForeColor = $theme.Fg
$cmbNetFilter.FlatStyle = 'Flat'
@('Toutes','Sortantes','Ecoute','Suspectes') | ForEach-Object { [void]$cmbNetFilter.Items.Add($_) }
$cmbNetFilter.SelectedIndex = 0
$netBar.Controls.Add($cmbNetFilter)

$btnRefreshNet = New-DarkButton -Text 'Actualiser connexions' -Width 170 -Height 28 -Variant 'Ghost'
$btnRefreshNet.Location = New-Object Drawing.Point(470, 38)
$netBar.Controls.Add($btnRefreshNet)

$txtNetFilter = New-Object Windows.Forms.TextBox
$txtNetFilter.Location = New-Object Drawing.Point(176, 40)
$txtNetFilter.Size = New-Object Drawing.Size(280, 28)
$txtNetFilter.BackColor = $theme.Surface2
$txtNetFilter.ForeColor = $theme.Fg
$txtNetFilter.BorderStyle = 'FixedSingle'
$netBar.Controls.Add($txtNetFilter)

$lblNetHint = New-Object Windows.Forms.Label
$lblNetHint.Text = 'Filtrer processus / IP / estimation...'
$lblNetHint.ForeColor = $theme.Muted
$lblNetHint.Location = New-Object Drawing.Point(180, 44)
$lblNetHint.AutoSize = $true
$lblNetHint.BackColor = $theme.Surface2
$netBar.Controls.Add($lblNetHint)
$lblNetHint.BringToFront()

$gridNet = New-Object Windows.Forms.DataGridView
$gridNet.Dock = 'Fill'
$gridNet.BackgroundColor = $theme.ChartBg
$gridNet.BorderStyle = 'None'
$gridNet.RowHeadersVisible = $false
$gridNet.AllowUserToAddRows = $false
$gridNet.ReadOnly = $true
$gridNet.SelectionMode = 'FullRowSelect'
$gridNet.AutoSizeColumnsMode = 'Fill'
$gridNet.RowTemplate.Height = 32
$gridNet.ColumnHeadersHeight = 36
$gridNet.DefaultCellStyle.BackColor = $theme.ChartBg
$gridNet.DefaultCellStyle.ForeColor = $theme.Fg
$gridNet.DefaultCellStyle.SelectionBackColor = $theme.AccentDim
$gridNet.DefaultCellStyle.SelectionForeColor = $theme.Accent
$gridNet.AlternatingRowsDefaultCellStyle.BackColor = $theme.Surface2
$gridNet.AlternatingRowsDefaultCellStyle.ForeColor = $theme.Fg
$gridNet.AlternatingRowsDefaultCellStyle.SelectionBackColor = $theme.AccentDim
$gridNet.AlternatingRowsDefaultCellStyle.SelectionForeColor = $theme.Accent
$gridNet.ColumnHeadersDefaultCellStyle.BackColor = $theme.Surface2
$gridNet.ColumnHeadersDefaultCellStyle.ForeColor = $theme.Muted
$gridNet.EnableHeadersVisualStyles = $false
$gridNet.GridColor = $theme.Border
$gridNet.CellBorderStyle = 'SingleHorizontal'
[void]$gridNet.Columns.Add('Direction', 'Dir.')
[void]$gridNet.Columns.Add('Process', 'Processus')
[void]$gridNet.Columns.Add('Local', 'Local')
[void]$gridNet.Columns.Add('Remote', 'Distant')
[void]$gridNet.Columns.Add('Estimate', 'Estimation')
[void]$gridNet.Columns.Add('Risk', 'Risque')
[void]$gridNet.Columns.Add('Path', 'Chemin')
$gridNet.Columns[0].FillWeight = 8
$gridNet.Columns[1].FillWeight = 12
$gridNet.Columns[2].FillWeight = 14
$gridNet.Columns[3].FillWeight = 14
$gridNet.Columns[4].FillWeight = 16
$gridNet.Columns[5].FillWeight = 8
$gridNet.Columns[6].FillWeight = 28
$panelReseau.Controls.Add($gridNet)
$gridNet.BringToFront()

$txtNetFilter.Add_TextChanged({
    $lblNetHint.Visible = [string]::IsNullOrWhiteSpace($txtNetFilter.Text)
    Update-NetworkGrid
})
$txtNetFilter.Add_Enter({ $lblNetHint.Visible = $false })
$txtNetFilter.Add_Leave({
    if ([string]::IsNullOrWhiteSpace($txtNetFilter.Text)) { $lblNetHint.Visible = $true }
})
$cmbNetFilter.Add_SelectedIndexChanged({ Update-NetworkGrid })

# ================= CHAINS / TIMELINE =================
$panelChains = New-Object Windows.Forms.Panel
$panelChains.Dock = 'Fill'
$panelChains.Visible = $false
$panelChains.BackColor = $theme.Bg
$content.Controls.Add($panelChains)

$txtChains = New-Object Windows.Forms.RichTextBox
$txtChains.Dock = 'Fill'
$txtChains.BackColor = $theme.ChartBg
$txtChains.ForeColor = $theme.Fg
$txtChains.BorderStyle = 'None'
$txtChains.Font = New-UiFont 10
$txtChains.ReadOnly = $true
$panelChains.Controls.Add($txtChains)

$panelTimeline = New-Object Windows.Forms.Panel
$panelTimeline.Dock = 'Fill'
$panelTimeline.Visible = $false
$panelTimeline.BackColor = $theme.Bg
$content.Controls.Add($panelTimeline)

$txtTimeline = New-Object Windows.Forms.RichTextBox
$txtTimeline.Dock = 'Fill'
$txtTimeline.BackColor = $theme.ChartBg
$txtTimeline.ForeColor = $theme.Fg
$txtTimeline.BorderStyle = 'None'
$txtTimeline.Font = New-UiFont 10
$txtTimeline.ReadOnly = $true
$panelTimeline.Controls.Add($txtTimeline)

# ================= LOGIC =================
function Set-StatPillValue {
    param($Pill, [string]$Text, $Color = $null)
    foreach ($c in $Pill.Controls) {
        if ($c.Name -eq 'Value') {
            $c.Text = $Text
            $c.ForeColor = $(if ($Color) { $Color } else { $theme.Fg })
        }
    }
}

function Show-View {
    param([string]$Name)
    $titles = @{
        Overview = 'Overview'
        Findings = 'Findings'
        Reseau   = 'Reseau - connexions'
        Chains   = 'Chaines deduites'
        Timeline = 'Timeline'
    }
    $lblTitle.Text = $titles[$Name]
    $panelOverview.Visible = ($Name -eq 'Overview')
    $panelFindings.Visible = ($Name -eq 'Findings')
    $panelReseau.Visible   = ($Name -eq 'Reseau')
    $panelChains.Visible   = ($Name -eq 'Chains')
    $panelTimeline.Visible = ($Name -eq 'Timeline')
    if ($Name -eq 'Overview') { $panelOverview.BringToFront() }
    elseif ($Name -eq 'Findings') { $panelFindings.BringToFront() }
    elseif ($Name -eq 'Reseau') { $panelReseau.BringToFront() }
    elseif ($Name -eq 'Chains') { $panelChains.BringToFront() }
    else { $panelTimeline.BringToFront() }

    foreach ($k in $navButtons.Keys) {
        if ($k -eq $Name) {
            $navButtons[$k].BackColor = $theme.NavActive
            $navButtons[$k].ForeColor = $theme.Accent
            $navButtons[$k].Font = New-UiFont 9.5 'Bold'
            $navButtons[$k].FlatAppearance.BorderSize = 0
        }
        else {
            $navButtons[$k].BackColor = $theme.Sidebar
            $navButtons[$k].ForeColor = $theme.Muted
            $navButtons[$k].Font = New-UiFont 9.5
            $navButtons[$k].FlatAppearance.BorderSize = 0
        }
    }
}

foreach ($k in @($navButtons.Keys)) {
    $navButtons[$k].Add_Click({
        param($sender, $e)
        Show-View ([string]$sender.Tag)
    })
}

function Update-FindingsGrid {
    $grid.Rows.Clear()
    if (-not $script:LastResult) { $lblFindCount.Text = ''; return }
    $sevFilter = [string]$cmbSev.SelectedItem
    $q = $txtFilter.Text.Trim()
    $sorted = @($script:LastResult.Findings) | Sort-Object @{
        Expression = { switch ($_.Severity) { 'Critical'{0}'High'{1}'Medium'{2}'Low'{3}default{4} } }
    }
    $n = 0
    foreach ($f in $sorted) {
        if ($sevFilter -ne 'Toutes' -and $f.Severity -ne $sevFilter) { continue }
        if ($q) {
            $blob = "$($f.Title) $($f.Path) $($f.Detail) $($f.WhySuspicious) $($f.Category)"
            if ($blob -notlike "*$q*") { continue }
        }
        $hash = ''
        try {
            if ($f.Meta -and $f.Meta.Sha256) { $hash = [string]$f.Meta.Sha256 }
            elseif ($f.Sha256) { $hash = [string]$f.Sha256 }
            elseif ($f.Evidence -match 'SHA256=([A-F0-9]{64})') { $hash = $Matches[1] }
        } catch { }
        if ($hash.Length -gt 16) { $hash = $hash.Substring(0, 16) + '...' }
        [void]$grid.Rows.Add($f.Severity, $f.Category, $f.Title, $f.Path, $hash, $f.WhySuspicious)
        $n++
    }
    $lblFindCount.Text = "$n resultat(s)"
}

function Update-NetworkGrid {
    $gridNet.Rows.Clear()
    if (-not $script:LastResult -or -not $script:LastResult.Connections) {
        $lblNetStats.Text = 'Aucune donnee - lancez un scan.'
        return
    }
    $all = @($script:LastResult.Connections)
    $mode = [string]$cmbNetFilter.SelectedItem
    $q = $txtNetFilter.Text.Trim()
    $outPub = @($all | Where-Object { $_.Direction -eq 'Outbound' -and -not $_.IsPrivate }).Count
    $listen = @($all | Where-Object { $_.Direction -eq 'Listen' }).Count
    $sus = @($all | Where-Object { $_.Risk -in @('Medium','High','Critical') }).Count
    $lblNetStats.Text = ("Total {0} | Sortantes publiques {1} | Ecoute {2} | Suspectes {3}" -f $all.Count, $outPub, $listen, $sus)

    $n = 0
    $ordered = $all | Sort-Object @{
        Expression = { switch ($_.Risk) { 'Critical'{0}'High'{1}'Medium'{2}'Low'{3}default{4} } }
    }, Direction
    foreach ($c in $ordered) {
        if ($mode -eq 'Sortantes' -and $c.Direction -ne 'Outbound') { continue }
        if ($mode -eq 'Ecoute' -and $c.Direction -ne 'Listen') { continue }
        if ($mode -eq 'Suspectes' -and $c.Risk -notin @('Medium','High','Critical')) { continue }
        if ($q) {
            $blob = "$($c.ProcessName) $($c.Path) $($c.LocalAddress) $($c.RemoteAddress) $($c.Estimate) $($c.RiskReason)"
            if ($blob -notlike "*$q*") { continue }
        }
        $local = "{0}:{1}" -f $c.LocalAddress, $c.LocalPort
        $remote = if ($c.Direction -eq 'Listen') { '-' } else { "{0}:{1}" -f $c.RemoteAddress, $c.RemotePort }
        $dir = if ($c.Protocol -eq 'UDP') { 'UDP' } else { $c.Direction }
        [void]$gridNet.Rows.Add($dir, $c.ProcessName, $local, $remote, $c.Estimate, $c.Risk, $c.Path)
        $n++
    }
}

$cmbSev.Add_SelectedIndexChanged({ Update-FindingsGrid })
$txtFilter.Add_TextChanged({ Update-FindingsGrid })

function Update-UiFromResult {
    param($Result)
    $script:LastResult = $Result
    $script:HasScan = $true
    $script:ScoreValue = [int]$Result.Score.Score
    $script:ScoreLabel = [string]$Result.Score.Label
    foreach ($k in @('Critical','High','Medium','Low','Info')) {
        $v = 0
        try { $v = [int]$Result.Score.BySeverity.$k } catch { }
        $script:SevCounts[$k] = $v
    }
    $script:CatStats = @($Result.CategoryStats)

    $scoreCol = if ($script:ScoreValue -ge 85) { $theme.Ok }
        elseif ($script:ScoreValue -ge 65) { $theme.Accent }
        elseif ($script:ScoreValue -ge 40) { $theme.Warn }
        else { $theme.Danger }
    Set-StatPillValue $pillScore "$($script:ScoreValue)" $scoreCol
    Set-StatPillValue $pillFindings ("{0}" -f @($Result.Findings).Count)
    Set-StatPillValue $pillChains ("{0}" -f @($Result.Chains).Count)
    Set-StatPillValue $pillTime ("{0}s" -f $Result.DurationSec)

    $cardScore.Invalidate()
    $cardSev.Invalidate()
    $cardCat.Invalidate()

    $listPriorities.Items.Clear()
    $listChecklist.Items.Clear()

    # Diff
    if ($Result.Diff) {
        $lblDiff.Text = ('DEPUIS LE DERNIER SCAN: {0}' -f $Result.Diff.Summary)
        if ($Result.Diff.HasPrevious -and ($Result.Diff.NewFindingCount -gt 0 -or $Result.Diff.NewConnectionCount -gt 0)) {
            $lblDiff.ForeColor = $theme.Warn
            foreach ($nf in @($Result.Diff.NewFindings | Select-Object -First 5)) {
                [void]$listPriorities.Items.Add(("  [NOUVEAU] [{0}] {1}" -f $nf.Severity, $nf.Title))
            }
        }
        else {
            $lblDiff.ForeColor = $theme.Accent
        }
    }
    else {
        $lblDiff.Text = 'DEPUIS LE DERNIER SCAN: n/a'
        $lblDiff.ForeColor = $theme.Muted
    }

    # Checklist
    if ($Result.Checklist) {
        [void]$listChecklist.Items.Add(('  => {0}' -f $Result.Checklist.Verdict))
        [void]$listChecklist.Items.Add(('  OK={0}  Attention={1}  Critique={2}' -f $Result.Checklist.Ok, $Result.Checklist.Attention, $Result.Checklist.Critique))
        [void]$listChecklist.Items.Add('  ---')
        foreach ($it in @($Result.Checklist.Items)) {
            $mark = switch ($it.Status) { 'OK' { '[OK]' } 'Attention' { '[!!]' } 'Critique' { '[XX]' } default { '[?]' } }
            [void]$listChecklist.Items.Add(("  {0} {1}" -f $mark, $it.Question))
            if ($it.Detail) { [void]$listChecklist.Items.Add(("      {0}" -f $it.Detail)) }
        }
    }
    else {
        [void]$listChecklist.Items.Add('  Checklist indisponible.')
    }

    $top = @($Result.Chains | Select-Object -First 8)
    if ($top.Count -eq 0 -and $listPriorities.Items.Count -eq 0) {
        [void]$listPriorities.Items.Add('  Aucune chaine critique - voir Findings pour les alertes.')
    }
    else {
        foreach ($c in $top) {
            [void]$listPriorities.Items.Add(("  [{0}]  {1}   -  confiance {2}%" -f $c.Severity, $c.Title, $c.Confidence))
        }
    }

    Update-FindingsGrid
    Update-NetworkGrid

    $txtChains.Clear()
    if (@($Result.Chains).Count -eq 0) {
        $txtChains.SelectionColor = $theme.Muted
        $txtChains.AppendText("`r`n  Aucune chaine de correlation.`r`n")
    }
    else {
        foreach ($c in @($Result.Chains)) {
            $txtChains.SelectionColor = (Get-SeverityColor $c.Severity)
            $txtChains.SelectionFont = New-UiFont 12 'Bold'
            $txtChains.AppendText("`r`n  [$($c.Severity)] $($c.Title)`r`n")
            $txtChains.SelectionFont = New-UiFont 9
            $txtChains.SelectionColor = $theme.Muted
            $txtChains.AppendText("  Confiance $($c.Confidence)%`r`n`r`n")
            $txtChains.SelectionColor = $theme.Fg
            $txtChains.AppendText("  $($c.Narrative)`r`n`r`n")
            $txtChains.SelectionColor = $theme.Accent
            foreach ($h in @($c.InvestigateHints)) { $txtChains.AppendText("    -> $h`r`n") }
            $txtChains.SelectionColor = $theme.Muted
            $txtChains.AppendText(("`r`n  Findings: {0}`r`n  --------------------`r`n" -f ($c.FindingIds -join ', ')))
        }
    }

    $txtTimeline.Clear()
    $timed = @($Result.Findings) | Where-Object {
        $_.Category -in @('EventLog','Software','Disk','Service','BITS')
    } | Sort-Object Timestamp -Descending | Select-Object -First 80
    if ($timed.Count -eq 0) {
        $txtTimeline.SelectionColor = $theme.Muted
        $txtTimeline.AppendText("`r`n  Peu d'evenements horodates - voir Findings.`r`n")
    }
    else {
        foreach ($f in $timed) {
            $txtTimeline.SelectionColor = (Get-SeverityColor $f.Severity)
            $txtTimeline.AppendText("  [$($f.Severity)] ")
            $txtTimeline.SelectionColor = $theme.Muted
            $ts = $f.Timestamp
            if ($f.Evidence -match '^\d{4}-') { $ts = $f.Evidence }
            $txtTimeline.AppendText("$ts  ")
            $txtTimeline.SelectionColor = $theme.Fg
            $txtTimeline.AppendText("$($f.Category) - $($f.Title)`r`n")
            if ($f.Path) {
                $txtTimeline.SelectionColor = $theme.Muted
                $txtTimeline.AppendText("      $($f.Path)`r`n")
            }
        }
    }

    $lblStatus.Text = ("Score {0}/100 ({1})  -  {2} findings  -  {3} chaines  -  {4}s" -f `
        $Result.Score.Score, $Result.Score.Label, @($Result.Findings).Count, @($Result.Chains).Count, $Result.DurationSec)
    if ($Result.Diff -and $Result.Diff.HasPrevious) {
        $lblStatus.Text += ("  |  nouveaux: +{0}F +{1}C" -f $Result.Diff.NewFindingCount, $Result.Diff.NewConnectionCount)
    }
    $btnExport.Enabled = $true
    $btnOpenHtml.Enabled = $true
    $btnPrintA4.Enabled = $true
}

$Global:AuditProgressCallback = {
    param($Phase, $Percent, $Detail)
    $phaseWeight = @{
        Persistence = 0; Runtime = 14; Reseau = 28; Devices = 42
        Accounts = 52; Traces = 60; Surface = 70; Deduction = 88; Termine = 100
    }
    $base = 0
    if ($phaseWeight.ContainsKey($Phase)) { $base = [int]$phaseWeight[$Phase] }
    $v = [Math]::Min(99, $base + [Math]::Min(21, [int]($Percent * 0.21)))
    if ($Phase -eq 'Termine') { $v = 100 }
    if ($progress -and -not $progress.IsDisposed) {
        $progressHost.Visible = $true
        $progress.Value = $v
        $lblStatus.Text = ("{0}  -  {1}" -f $Phase, $Detail)
        [Windows.Forms.Application]::DoEvents()
    }
}

$btnScan.Add_Click({
    if ($script:ScanRunning) { return }
    $script:ScanRunning = $true
    $btnScan.Enabled = $false
    $btnExport.Enabled = $false
    $btnOpenHtml.Enabled = $false
    $btnPrintA4.Enabled = $false
    $progressHost.Visible = $true
    $progress.Value = 0
    $lblStatus.Text = 'Scan en cours (lecture seule)...'
    $listPriorities.Items.Clear()
    [void]$listPriorities.Items.Add('  Analyse en cours...')
    Show-View 'Overview'
    [Windows.Forms.Application]::DoEvents()

    $result = $null; $err = $null
    try { $result = Invoke-WinAuditFullScan -Root $Global:WinAuditRoot -LogsDir $logsDir }
    catch { $err = $_ }

    $progress.Value = 100
    if ($err) {
        [Windows.Forms.MessageBox]::Show(("Erreur:`n{0}" -f $err.Exception.Message), 'WinAudit', 'OK', 'Error') | Out-Null
        $lblStatus.Text = 'Echec du scan.'
    }
    elseif ($result) {
        $script:LastExport = Export-AuditReport -LogsDir $logsDir -Result $result
        Update-UiFromResult $result
        $lblStatus.Text = ("Termine  -  {0}" -f (Split-Path $script:LastExport.Html -Leaf))
    }
    $progressHost.Visible = $false
    $btnScan.Enabled = $true
    $script:ScanRunning = $false
})

$btnExport.Add_Click({
    if (-not $script:LastResult) { return }
    $paths = Export-AuditReport -LogsDir $logsDir -Result $script:LastResult
    $script:LastExport = $paths
    [Windows.Forms.MessageBox]::Show(("Rapports:`n`n{0}`n{1}`n{2}" -f $paths.Json, $paths.Txt, $paths.Html), 'Export', 'OK', 'Information') | Out-Null
})

$btnOpenHtml.Add_Click({
    if ($script:LastExport -and (Test-Path -LiteralPath $script:LastExport.Html)) {
        Start-Process $script:LastExport.Html
    }
    elseif ($script:LastResult) {
        $script:LastExport = Export-AuditReport -LogsDir $logsDir -Result $script:LastResult
        Start-Process $script:LastExport.Html
    }
})

$btnPrintA4.Add_Click({
    if (-not $script:LastResult) { return }
    $path = Export-AuditPrintReport -LogsDir $logsDir -Result $script:LastResult
    Start-Process $path
})

$btnRefreshNet.Add_Click({
    if ($script:ScanRunning) { return }
    $btnRefreshNet.Enabled = $false
    $lblStatus.Text = 'Actualisation connexions...'
    [Windows.Forms.Application]::DoEvents()
    try {
        Initialize-AuditCore -Root $Global:WinAuditRoot
        $conns = @(Get-AuditConnectionInventory -SkipReverseDns)
        if ($script:LastResult) {
            $script:LastResult.Connections = $conns
        }
        else {
            $script:LastResult = [pscustomobject]@{
                Connections = $conns
                Findings    = @()
                Chains      = @()
                Score       = @{ Score = 0; Label = 'N/A' }
                Diff        = $null
                Checklist   = $null
                DurationSec = 0
            }
        }
        Update-NetworkGrid
        $lblStatus.Text = ("Connexions actualisees: {0}" -f $conns.Count)
        Show-View 'Reseau'
    }
    catch {
        [Windows.Forms.MessageBox]::Show(("Erreur refresh:`n{0}" -f $_.Exception.Message), 'WinAudit', 'OK', 'Error') | Out-Null
        $lblStatus.Text = 'Echec actualisation reseau.'
    }
    finally {
        $btnRefreshNet.Enabled = $true
    }
})

function Show-AuditWhitelistDialog {
    $dlg = New-Object Windows.Forms.Form
    $dlg.Text = 'Whitelist WinAudit'
    $dlg.Size = New-Object Drawing.Size(520, 420)
    $dlg.StartPosition = 'CenterParent'
    $dlg.BackColor = $theme.Bg
    $dlg.ForeColor = $theme.Fg
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false

    $lbl = New-Object Windows.Forms.Label
    $lbl.Text = 'Motifs ignores au prochain scan (un par ligne). Ex: *\MyApp\*  ou  chrome|*\Chrome\*'
    $lbl.Location = New-Object Drawing.Point(16, 12)
    $lbl.Size = New-Object Drawing.Size(470, 36)
    $lbl.ForeColor = $theme.Muted
    $dlg.Controls.Add($lbl)

    $list = New-Object Windows.Forms.ListBox
    $list.Location = New-Object Drawing.Point(16, 52)
    $list.Size = New-Object Drawing.Size(470, 220)
    $list.BackColor = $theme.Surface2
    $list.ForeColor = $theme.Fg
    $list.BorderStyle = 'FixedSingle'
    foreach ($p in @(Get-AuditAllowListPatterns -Root $Global:WinAuditRoot)) {
        [void]$list.Items.Add($p)
    }
    $dlg.Controls.Add($list)

    $txt = New-Object Windows.Forms.TextBox
    $txt.Location = New-Object Drawing.Point(16, 286)
    $txt.Size = New-Object Drawing.Size(320, 28)
    $txt.BackColor = $theme.Surface2
    $txt.ForeColor = $theme.Fg
    $txt.BorderStyle = 'FixedSingle'
    $dlg.Controls.Add($txt)

    $btnAdd = New-DarkButton -Text 'Ajouter' -Width 70 -Height 28 -Variant 'Ghost'
    $btnAdd.Location = New-Object Drawing.Point(346, 284)
    $dlg.Controls.Add($btnAdd)

    $btnDel = New-DarkButton -Text 'Suppr.' -Width 70 -Height 28 -Variant 'Ghost'
    $btnDel.Location = New-Object Drawing.Point(422, 284)
    $dlg.Controls.Add($btnDel)

    $btnSave = New-DarkButton -Text 'Sauver' -Width 100 -Height 34 -Variant 'Accent'
    $btnSave.Location = New-Object Drawing.Point(286, 330)
    $dlg.Controls.Add($btnSave)

    $btnCancel = New-DarkButton -Text 'Fermer' -Width 100 -Height 34 -Variant 'Ghost'
    $btnCancel.Location = New-Object Drawing.Point(396, 330)
    $dlg.Controls.Add($btnCancel)

    $btnAdd.Add_Click({
        $v = $txt.Text.Trim()
        if ($v) {
            [void]$list.Items.Add($v)
            $txt.Text = ''
        }
    })
    $btnDel.Add_Click({
        if ($list.SelectedIndex -ge 0) { $list.Items.RemoveAt($list.SelectedIndex) }
    })
    $btnSave.Add_Click({
        $patterns = @($list.Items | ForEach-Object { [string]$_ })
        $path = Save-AuditAllowList -Root $Global:WinAuditRoot -Patterns $patterns
        [Windows.Forms.MessageBox]::Show(("Whitelist enregistree:`n{0}`nActive au prochain scan." -f $path), 'Whitelist', 'OK', 'Information') | Out-Null
        $dlg.Close()
    })
    $btnCancel.Add_Click({ $dlg.Close() })
    [void]$dlg.ShowDialog($form)
}

$btnWhitelist.Add_Click({ Show-AuditWhitelistDialog })

$form.Add_Resize({
    $h = $sidebar.ClientSize.Height
    $lblCopyright.Top = [Math]::Max(560, $h - 36)
    $lblSideHint.Top = [Math]::Max(500, $lblCopyright.Top - 56)
})

Show-View 'Overview'
$form.Add_Shown({
    $form.Activate()
    $h = $sidebar.ClientSize.Height
    $lblCopyright.Top = [Math]::Max(560, $h - 36)
    $lblSideHint.Top = [Math]::Max(500, $lblCopyright.Top - 56)
    $cardScore.Invalidate(); $cardSev.Invalidate(); $cardCat.Invalidate()
})

$form.Add_FormClosed({
    if ($picBrand.Image) {
        $img = $picBrand.Image
        $picBrand.Image = $null
        $img.Dispose()
    }
})

[Windows.Forms.Application]::Run($form)
