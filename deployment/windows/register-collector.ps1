# Scheduled Windows collection -> durable spool -> ingestion (reviewed example).
#
# Do NOT run blindly. This script:
#   1. retries any spool files left from a previous failed ingestion,
#   2. collects new Security events into a temp file, then promotes it to a
#      spool file only after the collector exits 0,
#   3. ingests the spool and moves it to processed/ on success, keeping it for
#      retry on failure,
#   4. never creates the collector state file (the collector writes it) and
#      never changes audit policy.
#
# Prerequisites: fools-gold installed for the task identity; registry, database
# directory, spool directory parent and log directory exist; file SACL/audit
# policy configured and verified manually (docs/OPERATIONS.md).

$ErrorActionPreference = "Stop"

$Registry  = "C:\ProgramData\fools-gold\registry.json"
$Database  = "C:\ProgramData\fools-gold\evidence.sqlite"
$StateFile = "C:\ProgramData\fools-gold\collector-state.json"
$SpoolDir  = "C:\ProgramData\fools-gold\spool"
$LogFile   = "C:\ProgramData\fools-gold\collector.log"
$LogEpoch  = "windows-installation-1"
$FoolsGold = (Get-Command fools-gold).Source

if (-not (Test-Path $Registry)) { throw "registry not found: $Registry" }
if (-not (Test-Path (Split-Path $Database))) { throw "database directory missing" }
New-Item -ItemType Directory -Force -Path $SpoolDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $SpoolDir "processed") | Out-Null
if (-not (Test-Path $LogFile)) { New-Item -ItemType File -Path $LogFile | Out-Null }

function Write-Log([string]$Message) {
    Add-Content -Path $LogFile -Value ("{0} {1}" -f (Get-Date).ToUniversalTime().ToString("o"), $Message)
}

function Invoke-Ingest([string]$Spool) {
    & $FoolsGold --registry $Registry --database $Database ingest $Spool 2>> $LogFile | Out-Null
    return $LASTEXITCODE
}

# 1. Restart recovery: ingest pending spools before collecting anything new.
foreach ($pending in Get-ChildItem -Path $SpoolDir -Filter *.jsonl -File) {
    $code = Invoke-Ingest $pending.FullName
    if ($code -eq 0) {
        Move-Item -LiteralPath $pending.FullName -Destination (Join-Path $SpoolDir "processed" $pending.Name) -Force
        Write-Log "recovered pending spool $($pending.Name)"
    }
    else {
        Write-Log "ingestion failed for pending $($pending.Name) (exit $code); kept for retry"
        exit 1
    }
}

# 2. Collect into a temp file; promote only after a successful collection.
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssfffZ")
$spool = Join-Path $SpoolDir ("events-$stamp.jsonl")
$temp = "$spool.tmp"
& $FoolsGold --registry $Registry --database $Database collect-windows `
    --log-epoch $LogEpoch --state-file $StateFile 2>> $LogFile |
    Out-File -FilePath $temp -Encoding utf8
if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $temp -ErrorAction SilentlyContinue
    Write-Log "collection failed (exit $LASTEXITCODE); cursor not advanced by this script"
    exit 1
}
if ((Get-Item -LiteralPath $temp).Length -eq 0) {
    Remove-Item -LiteralPath $temp
    Write-Log "no new events"
    exit 0
}
Move-Item -LiteralPath $temp -Destination $spool -Force

# 3. Ingest the new spool. On failure keep it so the next run retries it.
$code = Invoke-Ingest $spool
if ($code -eq 0) {
    Move-Item -LiteralPath $spool -Destination (Join-Path $SpoolDir "processed" (Split-Path $spool -Leaf)) -Force
    Write-Log "ingested $spool"
    exit 0
}
Write-Log "ingestion failed for $spool (exit $code); kept for retry"
exit 1
