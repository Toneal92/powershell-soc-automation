# ============================================
# SOC Automation Script — Threat Report Generator
# Author: Takejah O'Neal
# Description: Pulls Windows Event Logs, analyzes
# for suspicious activity, generates HTML report
# ============================================

# --- CONFIGURATION ---
$ReportPath = "C:\Projects\SOC-Automation\ThreatReport.html"
$HoursBack = 24
$StartTime = (Get-Date).AddHours(-$HoursBack)

Write-Host "Starting SOC Threat Report Generation..." -ForegroundColor Cyan
Write-Host "Analyzing events from the last $HoursBack hours..." -ForegroundColor Cyan

# --- COLLECT EVENTS ---

# Failed Logins (Brute Force Detection)
Write-Host "Collecting failed login attempts..." -ForegroundColor Yellow
$FailedLogins = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4625
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

# New User Accounts Created
Write-Host "Collecting new user account events..." -ForegroundColor Yellow
$NewAccounts = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4720
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

# PowerShell Script Block Logging
Write-Host "Collecting PowerShell execution events..." -ForegroundColor Yellow
$PSEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

# Successful Logins
Write-Host "Collecting successful login events..." -ForegroundColor Yellow
$SuccessLogins = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4624
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

# Account Lockouts
Write-Host "Collecting account lockout events..." -ForegroundColor Yellow
$Lockouts = Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4740
    StartTime = $StartTime
} -ErrorAction SilentlyContinue

# --- ANALYSIS ---
$FailedLoginCount = if ($FailedLogins) { $FailedLogins.Count } else { 0 }
$NewAccountCount = if ($NewAccounts) { $NewAccounts.Count } else { 0 }
$PSEventCount = if ($PSEvents) { $PSEvents.Count } else { 0 }
$SuccessLoginCount = if ($SuccessLogins) { $SuccessLogins.Count } else { 0 }
$LockoutCount = if ($Lockouts) { $Lockouts.Count } else { 0 }

# Determine overall risk level
$RiskLevel = "LOW"
$RiskColor = "green"
if ($FailedLoginCount -gt 10 -or $NewAccountCount -gt 0 -or $LockoutCount -gt 0) {
    $RiskLevel = "MEDIUM"
    $RiskColor = "orange"
}
if ($FailedLoginCount -gt 50 -or $PSEventCount -gt 20) {
    $RiskLevel = "HIGH"
    $RiskColor = "red"
}

Write-Host "Analysis complete. Risk Level: $RiskLevel" -ForegroundColor $RiskColor

# --- BUILD FAILED LOGIN TABLE ---
$FailedLoginRows = ""
if ($FailedLogins) {
    foreach ($Event in $FailedLogins | Select-Object -First 10) {
        $XML = [xml]$Event.ToXml()
        $TargetUser = ($XML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
        $SourceIP = ($XML.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
        $FailedLoginRows += "<tr><td>$($Event.TimeCreated)</td><td>$TargetUser</td><td>$SourceIP</td></tr>"
    }
} else {
    $FailedLoginRows = "<tr><td colspan='3'>No failed login events detected</td></tr>"
}

# --- BUILD NEW ACCOUNTS TABLE ---
$NewAccountRows = ""
if ($NewAccounts) {
    foreach ($Event in $NewAccounts | Select-Object -First 10) {
        $XML = [xml]$Event.ToXml()
        $NewUser = ($XML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
        $CreatedBy = ($XML.Event.EventData.Data | Where-Object { $_.Name -eq "SubjectUserName" }).'#text'
        $NewAccountRows += "<tr><td>$($Event.TimeCreated)</td><td>$NewUser</td><td>$CreatedBy</td></tr>"
    }
} else {
    $NewAccountRows = "<tr><td colspan='3'>No new account creation events detected</td></tr>"
}

# --- BUILD POWERSHELL TABLE ---
$PSRows = ""
if ($PSEvents) {
    foreach ($Event in $PSEvents | Select-Object -First 10) {
        $ScriptText = $Event.Message.Substring(0, [Math]::Min(100, $Event.Message.Length))
        $PSRows += "<tr><td>$($Event.TimeCreated)</td><td>$ScriptText...</td></tr>"
    }
} else {
    $PSRows = "<tr><td colspan='2'>No PowerShell script block events detected</td></tr>"
}

# --- GENERATE HTML REPORT ---
Write-Host "Generating HTML report..." -ForegroundColor Yellow

$HTML = @"
<!DOCTYPE html>
<html>
<head>
    <title>SOC Threat Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }
        h1 { color: #00d4ff; border-bottom: 2px solid #00d4ff; padding-bottom: 10px; }
        h2 { color: #00d4ff; margin-top: 30px; }
        .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }
        .metric-card { background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 15px; text-align: center; }
        .metric-number { font-size: 36px; font-weight: bold; color: #00d4ff; }
        .metric-label { font-size: 12px; color: #aaa; margin-top: 5px; }
        .risk-badge { display: inline-block; padding: 8px 20px; border-radius: 20px; font-weight: bold; font-size: 18px; }
        .risk-LOW { background: #1a4731; color: #00ff88; border: 1px solid #00ff88; }
        .risk-MEDIUM { background: #4a3000; color: #ffaa00; border: 1px solid #ffaa00; }
        .risk-HIGH { background: #4a0000; color: #ff4444; border: 1px solid #ff4444; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; background: #16213e; }
        th { background: #0f3460; color: #00d4ff; padding: 10px; text-align: left; }
        td { padding: 8px 10px; border-bottom: 1px solid #0f3460; font-size: 13px; }
        tr:hover { background: #0f3460; }
        .report-meta { color: #aaa; font-size: 13px; margin-bottom: 20px; }
        .section { background: #16213e; border: 1px solid #0f3460; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <h1>SOC Threat Intelligence Report</h1>
    <div class="report-meta">
        Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") | 
        Hostname: $env:COMPUTERNAME | 
        Analysis Window: Last $HoursBack hours | 
        Analyst: Takejah O'Neal
    </div>

    <div class="section">
        <h2>Overall Risk Level</h2>
        <span class="risk-badge risk-$RiskLevel">$RiskLevel</span>
    </div>

    <div class="section">
        <h2>Event Summary</h2>
        <div class="summary-grid">
            <div class="metric-card">
                <div class="metric-number">$FailedLoginCount</div>
                <div class="metric-label">Failed Logins</div>
            </div>
            <div class="metric-card">
                <div class="metric-number">$SuccessLoginCount</div>
                <div class="metric-label">Successful Logins</div>
            </div>
            <div class="metric-card">
                <div class="metric-number">$NewAccountCount</div>
                <div class="metric-label">New Accounts Created</div>
            </div>
            <div class="metric-card">
                <div class="metric-number">$PSEventCount</div>
                <div class="metric-label">PowerShell Events</div>
            </div>
            <div class="metric-card">
                <div class="metric-number">$LockoutCount</div>
                <div class="metric-label">Account Lockouts</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Failed Login Attempts (Top 10) — MITRE T1110</h2>
        <table>
            <tr><th>Timestamp</th><th>Target Account</th><th>Source IP</th></tr>
            $FailedLoginRows
        </table>
    </div>

    <div class="section">
        <h2>New User Accounts Created — MITRE T1136</h2>
        <table>
            <tr><th>Timestamp</th><th>New Account</th><th>Created By</th></tr>
            $NewAccountRows
        </table>
    </div>

    <div class="section">
        <h2>PowerShell Script Block Events (Top 10) — MITRE T1059.001</h2>
        <table>
            <tr><th>Timestamp</th><th>Script Preview</th></tr>
            $PSRows
        </table>
    </div>

</body>
</html>
"@

$HTML | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "Report saved to: $ReportPath" -ForegroundColor Green
Write-Host "Opening report in browser..." -ForegroundColor Green
Start-Process $ReportPath


