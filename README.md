# Zscaler ZTB Tools

Automation tools for Zscaler Zero Trust Branch (ZTB) appliances. All scripts use the AirGap API and require only Python 3.10+ or PowerShell 7+ — no external dependencies.

## Tools at a Glance

| Tool | Purpose | Python | PowerShell |
|---|---|---|---|
| **Bulk Upgrade** | Full firmware lifecycle: inventory, download, upgrade, HA-aware, resume, wizard | `ztb_bulk_upgrade.py` | `ztb_bulk_upgrade.ps1` |
| **Download** | Pre-stage firmware across the fleet in one command | `ztb_download.py` | `ztb_download.ps1` |

## Setup

```bash
git clone https://github.com/secsilab/zscaler-ztb-tools.git
cd zscaler-ztb-tools
cp .env.example .env
# Edit .env with your Zscaler credentials
```

## Bulk Upgrade Tool

Full documentation: [docs/bulk-upgrade.md](docs/bulk-upgrade.md)

```bash
# Interactive wizard
python3 ztb_bulk_upgrade.py

# View inventory
python3 ztb_bulk_upgrade.py inventory

# Download firmware only (no reboot)
python3 ztb_bulk_upgrade.py download --version latest --all

# Upgrade with dry-run
python3 ztb_bulk_upgrade.py upgrade --version 24.3.1 --site "Paris-*" --dry-run

# Upgrade for real
python3 ztb_bulk_upgrade.py upgrade --version 24.3.1 --site "Paris-*"

# Resume interrupted run
python3 ztb_bulk_upgrade.py resume
```

<details>
<summary>PowerShell equivalent</summary>

```powershell
./ztb_bulk_upgrade.ps1
./ztb_bulk_upgrade.ps1 inventory
./ztb_bulk_upgrade.ps1 download -Version latest -All
./ztb_bulk_upgrade.ps1 upgrade -Version 24.3.1 -Site "Paris-*" -DryRun
./ztb_bulk_upgrade.ps1 upgrade -Version 24.3.1 -Site "Paris-*"
./ztb_bulk_upgrade.ps1 resume
```
</details>

## Download Tool (compact)

For quick pre-staging without the full upgrade workflow. No state, no resume, no wizard — just download.

Full documentation: [docs/download.md](docs/download.md)

```bash
python3 ztb_download.py --version latest --all
python3 ztb_download.py --version 24.3.1 --below-version 24.3.0 --dry-run
```

<details>
<summary>PowerShell equivalent</summary>

```powershell
./ztb_download.ps1 -Version latest -All
./ztb_download.ps1 -Version 24.3.1 -BelowVersion 24.3.0 -DryRun
```
</details>

## Credentials

All tools read credentials from `.env` (or CLI flags):

| Variable | Description |
|---|---|
| `ZSCALER_CLIENT_ID` | OAuth2 client ID |
| `ZSCALER_CLIENT_SECRET` | OAuth2 client secret |
| `ZSCALER_VANITY_DOMAIN` | Tenant vanity domain (e.g. `acme`) |
| `ZSCALER_AIRGAP_SITE` | AirGap site name (e.g. `my-site`) |

CLI flags (`--client-id` / `-ClientId`, etc.) override `.env` values.

## Interoperability

- Python and PowerShell versions have identical functionality
- State file `.ztb_upgrade_state.json` is interoperable — start in Python, resume in PowerShell (or vice versa)
- Same API calls, same logic, same output format

## License

MIT
