# Scheduled Windows collection -> durable spool -> ingestion (reviewed example).
#
# Do NOT run blindly. This script:
#   1. retries any spool files left from a previous failed ingestion,
#   2. lets the collector publish/fsync each page before advancing its cursor,
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
# If the database is signed, set this to its protected evidence key file.
$EvidenceKeyFile = $null

if (-not (Test-Path $Registry)) { throw "registry not found: $Registry" }
if (-not (Test-Path (Split-Path $Database))) { throw "database directory missing" }
New-Item -ItemType Directory -Force -Path $SpoolDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $SpoolDir "processed") | Out-Null
if (-not (Test-Path $LogFile)) { New-Item -ItemType File -Path $LogFile | Out-Null }
$BaseArguments = @("--registry", $Registry, "--database", $Database)
if ($EvidenceKeyFile) {
    if (-not (Test-Path -LiteralPath $EvidenceKeyFile)) { throw "evidence key file missing" }
    $BaseArguments += @("--evidence-key-file", $EvidenceKeyFile)
}

function Write-Log([string]$Message) {
    Add-Content -Path $LogFile -Value ("{0} {1}" -f (Get-Date).ToUniversalTime().ToString("o"), $Message)
}

function Invoke-FoolsGold([string[]]$Arguments) {
    # Windows PowerShell 5.1 turns native stderr into ErrorRecords even when
    # redirected. Diagnostics must not bypass exit-code/recovery handling.
    $previousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        & $FoolsGold @Arguments 2>> $LogFile | Out-Null
        $nativeExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousPreference
    }
    if ($null -eq $nativeExit) { return 1 }
    return $nativeExit
}

function Invoke-Ingest([string]$Spool) {
    return Invoke-FoolsGold -Arguments ($BaseArguments + @("ingest", $Spool))
}

function Invoke-PendingSpools {
    foreach ($pending in Get-ChildItem -LiteralPath $SpoolDir -Filter *.jsonl -File | Sort-Object Name) {
        $code = Invoke-Ingest $pending.FullName
        if ($code -ne 0) {
            Write-Log "ingestion failed for $($pending.Name) (exit $code); kept for retry"
            return 1
        }
        Move-Item -LiteralPath $pending.FullName -Destination (Join-Path (Join-Path $SpoolDir "processed") $pending.Name)
        Write-Log "ingested pending spool $($pending.Name)"
    }
    return 0
}

# 1. Recover completed pages left by a failed or interrupted previous run.
if ((Invoke-PendingSpools) -ne 0) { exit 1 }

# 2. Each page becomes a complete .jsonl spool BEFORE its cursor is saved.
# A later page failing must never discard already-published pages. Partial
# .tmp files are ignored: their page was not committed and will be recollected.
$collectionExit = Invoke-FoolsGold -Arguments ($BaseArguments + @(
    "collect-windows", "--log-epoch", $LogEpoch,
    "--state-file", $StateFile, "--spool-directory", $SpoolDir
))

# 3. Ingest every durable page, including pages completed before a query error.
if ((Invoke-PendingSpools) -ne 0) { exit 1 }
if ($collectionExit -ne 0) {
    Write-Log "collection failed (exit $collectionExit); completed pages retained/ingested; retry required"
    exit 1
}
Write-Log "collection and ingestion complete"
exit 0
