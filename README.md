# ZTB Tools

Automation tools for Zscaler Zero Trust Branch (ZTB) appliances via the AirGap API.

Available in both **Python** and **PowerShell** with identical functionality. Pick whichever fits your environment.

## Tools

### `ztb_bulk_upgrade` -- Bulk Firmware Upgrade

Full-featured firmware management tool: download, upgrade, HA-aware sequencing, resume, interactive wizard, and audit reports.

**Key features:**
- **Download-only** or **download + upgrade** modes
- **HA-aware**: upgrades standby first, waits for failover, then upgrades former master (zero downtime)
- **Flexible selection**: by site (glob), cluster, version threshold, gateway list, or file
- **Resumable**: state saved after each gateway, interrupted runs resume cleanly
- **Interactive wizard**: run without arguments for guided mode
- **Reports**: JSON + CSV output for audit trail
- **Dry-run**: preview the plan without executing

#### Quick start

**Python** (`ztb_bulk_upgrade.py`):
```bash
python3 ztb_bulk_upgrade.py                                          # Interactive wizard
python3 ztb_bulk_upgrade.py inventory                                # View inventory
python3 ztb_bulk_upgrade.py download --version latest --all          # Download only
python3 ztb_bulk_upgrade.py upgrade --version 24.3.1 --site "Paris-*" --dry-run
python3 ztb_bulk_upgrade.py resume                                   # Resume interrupted run
```

**PowerShell** (`ztb_bulk_upgrade.ps1`):
```powershell
./ztb_bulk_upgrade.ps1                                               # Interactive wizard
./ztb_bulk_upgrade.ps1 inventory                                     # View inventory
./ztb_bulk_upgrade.ps1 download -Version latest -All                 # Download only
./ztb_bulk_upgrade.ps1 upgrade -Version 24.3.1 -Site "Paris-*" -DryRun
./ztb_bulk_upgrade.ps1 resume                                        # Resume interrupted run
```

The state file `.ztb_upgrade_state.json` is interoperable between both versions -- you can start a run in Python and resume it in PowerShell, or vice versa.

Full documentation: [docs/ztb-bulk-upgrade.md](docs/ztb-bulk-upgrade.md)

---

### `ztb_download` -- Compact Download-Only Tool

Lightweight single-purpose script that pre-stages firmware across the fleet in one command. No state file, no resume, no wizard, no reports -- just download.

**Python** (`ztb_download.py`):
```bash
python3 ztb_download.py --version latest --all
python3 ztb_download.py --version 24.3.1 --site "Paris-*" --dry-run
```

**PowerShell** (`ztb_download.ps1`):
```powershell
./ztb_download.ps1 -Version latest -All
./ztb_download.ps1 -Version 24.3.1 -Site "Paris-*" -DryRun
```

---

## Prerequisites

- **Python**: 3.10+ (stdlib only, no external dependencies)
- **PowerShell**: 7+ (pwsh) for cross-platform support
- Zscaler credentials:

```bash
# .env file (same directory as script)
ZSCALER_CLIENT_ID=<your_client_id>
ZSCALER_CLIENT_SECRET=<your_client_secret>
ZSCALER_VANITY_DOMAIN=<your_vanity_domain>
ZSCALER_AIRGAP_SITE=<your_airgap_site>
```

Or pass credentials via CLI flags (`--client-id` / `-ClientId`, etc.).

## Contributing

More ZTB automation tools will be added over time. Each tool is a standalone script with no external dependencies.

## License

MIT
