# ZTB Bulk Upgrade Tool

## 1. Overview

`ztb_bulk_upgrade.py` is a bulk firmware management tool for Zscaler Zero Trust Branch (ZTB) appliances. It communicates with the AirGap API to list gateways, download firmware images, and orchestrate upgrades across an entire fleet. The tool supports download-only and full upgrade modes, is HA-aware (upgrading standby nodes before active ones for zero downtime), and maintains a persistent state file so that interrupted operations can be resumed without re-processing completed gateways.

## 2. Prerequisites

- **Python 3.10+** (standard library only, no pip dependencies)
- A `.env` file at the repository root with the following variables:

| Variable | Description | Example |
|---|---|---|
| `ZSCALER_CLIENT_ID` | OAuth2 client ID for the Zscaler API | `abc123...` |
| `ZSCALER_CLIENT_SECRET` | OAuth2 client secret | `secret...` |
| `ZSCALER_VANITY_DOMAIN` | Tenant vanity domain (used for token URL) | `secsilab` |
| `ZSCALER_AIRGAP_SITE` | AirGap site identifier (used for API base URL) | `thibaultparis` |

The token endpoint is derived as `https://<vanity_domain>.zslogin.net/oauth2/v1/token` and the API base as `https://<airgap_site>-api.goairgap.com`.

## 3. Quick Start

```bash
# Interactive wizard (default when no subcommand is given)
python3 ztb_bulk_upgrade.py

# List all gateways with current firmware versions
python3 ztb_bulk_upgrade.py inventory

# Download firmware to all gateways (no reboot, no downtime)
python3 ztb_bulk_upgrade.py download --version latest --all

# Upgrade all gateways to a specific version
python3 ztb_bulk_upgrade.py upgrade --version 24.3.1 --all

# Dry-run: see the execution plan without making any changes
python3 ztb_bulk_upgrade.py upgrade --version latest --all --dry-run

# Resume an interrupted operation
python3 ztb_bulk_upgrade.py resume
```

## 4. Commands

| Command | Description |
|---|---|
| *(none)* | Launches the interactive wizard |
| `inventory` | Lists all gateways with current versions, HA role, status, and version distribution |
| `download` | Stages firmware on selected gateways (no reboot, no service impact) |
| `upgrade` | Downloads firmware if needed and activates (triggers reboot), HA-aware sequencing |
| `resume` | Continues a previously interrupted download or upgrade from where it stopped |

## 5. Gateway Selection

Selection flags determine which gateways are targeted by the `download` and `upgrade` commands. At least one flag is required.

| Flag | Description |
|---|---|
| `--all` | Select all gateways in the fleet |
| `--site <pattern>` | Select gateways whose site name matches the glob pattern (e.g. `pve-ztb*`) |
| `--cluster <id>` | Select all gateways in a specific cluster (by cluster ID) |
| `--gateway <id,...>` | Select specific gateways by name (comma-separated) |
| `--below-version <v>` | Select gateways running a version below the specified threshold |
| `--from-file <path>` | Read gateway names or IDs from a file (one per line, `#` comments allowed) |

**Note:** When multiple flags are specified, they combine as AND -- all conditions must match. At least one selection flag is required.

## 6. Execution Flags

| Flag | Default | Description |
|---|---|---|
| `--version <v>` | *(required)* | Target firmware version, or `latest` to resolve automatically |
| `--dry-run` | off | Show the execution plan and exit without making changes |
| `--on-error <mode>` | `continue` | `continue` processes remaining gateways on failure; `stop` halts immediately |
| `--timeout <min>` | `15` | Per-gateway timeout in minutes for download and upgrade polling |

## 7. Credential Flags

Credentials can be provided via CLI flags, `.env` file, or environment variables. CLI flags take precedence over `.env`, which takes precedence over environment variables.

| Flag | Environment Variable | Description |
|---|---|---|
| `--client-id` | `ZSCALER_CLIENT_ID` | OAuth2 client ID |
| `--client-secret` | `ZSCALER_CLIENT_SECRET` | OAuth2 client secret |
| `--vanity-domain` | `ZSCALER_VANITY_DOMAIN` | Tenant vanity domain |
| `--airgap-site` | `ZSCALER_AIRGAP_SITE` | AirGap site name |
| `--env-file` | *(n/a)* | Path to `.env` file (default: `../.env` relative to script) |

**Note:** CLI flags override `.env` values. The `.env` file uses `setdefault`, so pre-existing environment variables are not overwritten.

## 8. Modes of Action

### Download Only

```bash
python3 ztb_bulk_upgrade.py download --version 25.1.2 --all
```

Stages the firmware image on each selected gateway. No reboot occurs, no service disruption. This is useful for pre-staging firmware during a maintenance window preparation.

### Full Upgrade

```bash
python3 ztb_bulk_upgrade.py upgrade --version 25.1.2 --all
```

Two-phase operation per gateway:

1. **Download** -- stages the firmware image (skipped if already downloaded)
2. **Activate** -- triggers the upgrade and reboot, then polls until the gateway is back online at the target version

If the image was previously downloaded (e.g. via an earlier `download` command or a resumed operation), the upgrade skips straight to activation.

## 9. HA-Aware Upgrade

For gateways in an HA cluster, the tool enforces a safe upgrade order:

1. **BACKUP/standby gateway first** -- upgraded and polled until online at the target version
2. **Wait for health check** -- confirms the standby is healthy before proceeding
3. **MASTER/active gateway** -- now effectively the backup after failover, upgraded next
4. **Cluster health verification** -- confirms all cluster members are online

This sequencing provides zero downtime for HA clusters. If a standby gateway fails to upgrade, the remaining gateways in that cluster are skipped (with `--on-error=continue`) or the entire run is halted (`--on-error=stop`).

## 10. State and Resume

The tool maintains a state file (`.ztb_upgrade_state.json` in the current directory) that is updated after each gateway completes or fails.

- **State tracking:** Each gateway has a status (`pending`, `in_progress`, `completed`, `failed`, `skipped`) and a phase (`cleanup`, `download`, `downloaded`, `activate`, `complete`)
- **Resume:** `resume` loads the state file, shows a progress summary, resets failed gateways for retry, and replays remaining work
- **Smart resume:** If a gateway failed during activation (phase `activate`) but the image was already downloaded, resume skips re-download and goes straight to activation
- **Skipped-due-to-failure:** Gateways that were skipped because of a prior failure in their cluster are automatically reset on resume

```bash
# Resume picks up where you left off
python3 ztb_bulk_upgrade.py resume
```

## 11. Reports

After each run (including resume), the tool generates two report files:

- **JSON:** `ztb_upgrade_report_<run_id>.json`
- **CSV:** `ztb_upgrade_report_<run_id>.csv` (Excel-friendly)

The `run_id` is a timestamp in `YYYYMMDD-HHMMSS` format (UTC).

### CSV Columns

| Column | Description |
|---|---|
| `gateway_id` | Unique gateway identifier |
| `gateway_name` | Human-readable gateway name |
| `site` | Site name the gateway belongs to |
| `cluster` | Cluster ID (empty for standalone) |
| `version_before` | Firmware version before the operation |
| `version_after` | Firmware version after (populated on success) |
| `status` | Final status: `completed`, `failed`, `skipped` |
| `phase` | Last phase reached: `cleanup`, `download`, `downloaded`, `activate`, `complete` |
| `duration` | Per-gateway elapsed time (e.g. `120s`) |
| `error` | Error message if failed, empty otherwise |

### JSON Report

The JSON report includes the same per-gateway data plus run-level metadata: `run_id`, `command`, `target_version`, `started`, `finished`, `duration_seconds`, and a `summary` object with counts by status.

## 12. Disk Space Management

Before downloading a new firmware image, the tool automatically cleans up old staged images on each gateway. The cleanup logic:

- Queries the gateway for its current `sw_image_status.images[]`
- Deletes any staged image that is **not** the currently running version and **not** the target version
- This is non-fatal: if cleanup fails, the download proceeds anyway

This prevents disk space exhaustion on gateways that have accumulated multiple firmware images over time.

## 13. Troubleshooting

| Problem | Solution |
|---|---|
| **Missing credentials** | Verify your `.env` file contains all four required variables (`ZSCALER_CLIENT_ID`, `ZSCALER_CLIENT_SECRET`, `ZSCALER_VANITY_DOMAIN`, `ZSCALER_AIRGAP_SITE`). Alternatively, pass them as CLI flags. |
| **Gateway stuck downloading** | Increase `--timeout` (default is 15 minutes). Large firmware images or slow WAN links may need 30+ minutes. |
| **Resume shows "nothing to resume"** | All gateways are completed or skipped. Check the CSV report for final status. |
| **Version not available** | Run `inventory` to see the list of available firmware releases and their version numbers. |
| **Disk space full on gateway** | The script auto-cleans old staged images before each download, but if the gateway storage is still full, manually check via the AirGap portal or API for leftover images. |
| **API connectivity error** | Verify network access to `<airgap_site>-api.goairgap.com` and `<vanity_domain>.zslogin.net`. Check that the OAuth2 client credentials are valid and not expired. |
| **HA cluster partially upgraded** | Use `resume` to continue. The tool will reset failed gateways and retry them while skipping already-completed ones. |

## 14. PowerShell Version

A functionally identical PowerShell version is provided as `ztb_bulk_upgrade.ps1`. It uses the same AirGap API endpoints, the same state file format, and the same HA-aware sequencing logic.

### Requirements

- **PowerShell 7+** (pwsh) for cross-platform support (Windows, macOS, Linux)
- Same `.env` file or environment variables as the Python version

### Parameter Mapping

PowerShell uses its own naming conventions. The mapping from Python CLI flags:

| Python flag | PowerShell parameter | Notes |
|---|---|---|
| `download` / `upgrade` / `inventory` / `resume` | `-Command` (positional) | First positional argument |
| `--version` | `-Version` | |
| `--all` | `-All` | Switch parameter |
| `--site <pattern>` | `-Site <pattern>` | |
| `--cluster <id>` | `-Cluster <id>` | |
| `--gateway <names>` | `-Gateway <names>` | Comma-separated |
| `--below-version <v>` | `-BelowVersion <v>` | |
| `--from-file <path>` | `-FromFile <path>` | |
| `--dry-run` | `-DryRun` | Switch parameter |
| `--on-error <mode>` | `-OnError <mode>` | `Continue` or `Stop` |
| `--timeout <min>` | `-Timeout <min>` | |
| `--client-id` | `-ClientId` | |
| `--client-secret` | `-ClientSecret` | |
| `--vanity-domain` | `-VanityDomain` | |
| `--airgap-site` | `-AirgapSite` | |
| `--env-file` | `-EnvFile` | |

### Quick Start (PowerShell)

```powershell
# Interactive wizard (default when no command is given)
./ztb_bulk_upgrade.ps1

# List all gateways with current versions
./ztb_bulk_upgrade.ps1 inventory

# Download firmware to all gateways (no reboot, no downtime)
./ztb_bulk_upgrade.ps1 download -Version latest -All

# Upgrade all gateways to a specific version
./ztb_bulk_upgrade.ps1 upgrade -Version 24.3.1 -All

# Dry-run: see the execution plan without making any changes
./ztb_bulk_upgrade.ps1 upgrade -Version latest -All -DryRun

# Upgrade gateways below a certain version
./ztb_bulk_upgrade.ps1 upgrade -Version latest -BelowVersion 24.3.0

# Resume an interrupted operation
./ztb_bulk_upgrade.ps1 resume
```

### State File Interoperability

The state file `.ztb_upgrade_state.json` is fully interoperable between the Python and PowerShell versions. You can:

- Start a download with Python and resume it with PowerShell (or vice versa)
- Check run status from either version
- The JSON schema is identical across both implementations
