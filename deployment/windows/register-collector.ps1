# Register a scheduled Windows collector task (reviewed example; do not run
# blindly). Creates a task that runs every 5 minutes with a durable cursor and
# logs to a protected directory. It does not change audit policy.
#
# Prerequisites:
#   - fools-gold installed for the service account
#   - registry, evidence database directory and log directory already exist
#   - file SACL/audit policy configured and verified manually (see docs/OPERATIONS.md)
#
# Run from an elevated PowerShell after reviewing every path and identity.

$ErrorActionPreference = "Stop"

$Registry    = "C:\ProgramData\fools-gold\registry.json"
$Database    = "C:\ProgramData\fools-gold\evidence.sqlite"
$StateFile   = "C:\ProgramData\fools-gold\collector-state.json"
$LogFile     = "C:\ProgramData\fools-gold\collector.log"
$TaskName    = "FoolsGoldCollector"
$FoolsGold   = (Get-Command fools-gold).Source

if (-not (Test-Path $Registry))    { throw "registry not found: $Registry" }
if (-not (Test-Path $StateFile))   { New-Item -ItemType File -Path $StateFile | Out-Null }
if (-not (Test-Path $LogFile))     { New-Item -ItemType File -Path $LogFile | Out-Null }

$Arguments = "--registry `"$Registry`" --database `"$Database`" " +
    "collect-windows --log-epoch windows-installation-1 " +
    "--state-file `"$StateFile`""
$Action = New-ScheduledTaskAction -Execute $FoolsGold -Argument $Arguments

$Trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
    -RepetitionInterval (New-TimeSpan -Minutes 5)

$Settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger `
    -Settings $Settings -Description "Fool's Gold decoy collector"

# Logging/recovery: task history plus redirect stdout/stderr with your logging
# wrapper if required. On failure or log clear, the collector prints a coverage
# gap to stderr; investigate and let it restart from the oldest record.
