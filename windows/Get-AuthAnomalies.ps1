<#
.SYNOPSIS
    Audits Windows Security and Sysmon logs for authentication anomalies and privilege escalation.
.DESCRIPTION
    Filters Event IDs 4625 (Failed Logon), 4672 (Special Privileges Assigned), and Sysmon Event ID 1
    for processes executed from non-standard user directories.
#>

[CmdletBinding()]
param (
    [int]$HoursBack = 24
)

$StartTime = (Get-Date).AddHours(-$HoursBack)

Write-Host "=== Windows Security & Sysmon Triage (Last $HoursBack hours) ===" -ForegroundColor Cyan

Write-Host "`n[+] Top Failed Logon Sources (Event ID 4625):" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$StartTime} -ErrorAction SilentlyContinue |
    ForEach-Object {
        [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            TargetUser  = $_.Properties[5].Value
            SourceIP    = $_.Properties[19].Value
        }
    } | Group-Object SourceIP, TargetUser | Sort-Object Count -Descending | Select-Object -First 10 Count, Name

Write-Host "`n[+] Special Privilege Logons (Event ID 4672):" -ForegroundColor Yellow
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672; StartTime=$StartTime} -ErrorAction SilentlyContinue |
    Select-Object -First 10 TimeCreated, @{N='Account';E={$_.Properties[1].Value}}
