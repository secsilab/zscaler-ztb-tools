# ZTB Download Tool

Lightweight script that pre-stages firmware across ZTB gateways in one command. No state file, no resume, no wizard, no reports — just download.

For the full upgrade workflow (HA-aware, resumable, reports), see [bulk-upgrade.md](bulk-upgrade.md).

## Usage

```bash
# Download latest firmware to all gateways
python3 ztb_download.py --version latest --all

# Download specific version to a site
python3 ztb_download.py --version 24.3.1 --site "Paris-*"

# Preview without downloading
python3 ztb_download.py --version latest --all --dry-run

# Download to gateways below a version
python3 ztb_download.py --version 24.3.1 --below-version 24.3.0
```

### PowerShell

```powershell
./ztb_download.ps1 -Version latest -All
./ztb_download.ps1 -Version 24.3.1 -Site "Paris-*"
./ztb_download.ps1 -Version latest -All -DryRun
./ztb_download.ps1 -Version 24.3.1 -BelowVersion 24.3.0
```

## Flags

| Flag (Python) | Flag (PowerShell) | Description |
|---|---|---|
| `--version <v\|latest>` | `-Version` | Target firmware version (required) |
| `--all` | `-All` | All gateways |
| `--site <pattern>` | `-Site` | By site name (glob) |
| `--cluster <id>` | `-Cluster` | By cluster ID |
| `--gateway <id,...>` | `-Gateway` | Comma-separated gateway IDs |
| `--below-version <v>` | `-BelowVersion` | Gateways below this version |
| `--dry-run` | `-DryRun` | Preview without executing |

At least one selection flag is required. Filters combine as AND.

## Credentials

Same `.env` file as the bulk upgrade tool. Override with `--client-id`, `--client-secret`, `--vanity-domain`, `--airgap-site` (or PowerShell equivalents `-ClientId`, etc.).

## What It Does

1. Authenticates via OAuth2
2. Fetches all gateways and available releases
3. Resolves `latest` to the newest version
4. Filters gateways, skips those already at target
5. For each gateway: cleans up old staged images, downloads the target version
6. Prints progress and summary

## What It Doesn't Do

- No activation/reboot (use `ztb_bulk_upgrade` for that)
- No HA-aware sequencing (download is non-disruptive)
- No state file or resume
- No reports (output is terminal only)
