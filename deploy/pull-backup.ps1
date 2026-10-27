# Copy the newest server backup to this PC (run in PowerShell on Windows).
# Usage:  .\deploy\pull-backup.ps1 -Server 203.0.113.10 [-Dest F:\GFC\server-backups]
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [string]$Dest = "F:\GFC\server-backups",
    [string]$User = "root"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
$latest = (ssh "$User@$Server" "ls -1t /var/backups/gfc/gfc-*.tar.gz | head -n 1").Trim()
if (-not $latest) { throw "No backups found on $Server yet (the first one runs at 03:30 UTC, or run gfc-backup)." }
scp "${User}@${Server}:$latest" "$Dest\"
Write-Host "Saved $(Split-Path $latest -Leaf) to $Dest"
