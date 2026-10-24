param(
    [string]$TaskName = "VulnX-NVD-Update",
    [string]$DailyAt = "02:00"
)

$backendDir = $PSScriptRoot
$pythonPath = Join-Path $backendDir ".venv\Scripts\python.exe"
$batchPath = Join-Path $backendDir "run_daily.bat"
if (-not (Test-Path -LiteralPath $pythonPath) -or -not (Test-Path -LiteralPath $batchPath)) {
    throw "Backend virtual environment not found. Create it and install requirements first."
}

$time = [DateTime]::ParseExact($DailyAt, "HH:mm", [Globalization.CultureInfo]::InvariantCulture)
$commandLine = '/c "' + $batchPath + '"'
$action = New-ScheduledTaskAction `
    -Execute "$env:SystemRoot\System32\cmd.exe" `
    -Argument $commandLine `
    -WorkingDirectory $backendDir
$trigger = New-ScheduledTaskTrigger -Daily -At $time
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 3)
$principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType S4U `
    -RunLevel Limited

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "Downloads recent and modified NVD feeds and updates the local VulnX database." `
    -Force | Out-Null

Write-Host "Scheduled '$TaskName' every day at $DailyAt."
Write-Host "Run it now with: Start-ScheduledTask -TaskName '$TaskName'"
