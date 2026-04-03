# ZTB Tools

Automation tools for Zscaler Zero Trust Branch (ZTB) appliances via the AirGap API.

## Tools

### `ztb_bulk_upgrade.py` — Bulk Firmware Upgrade

Automates firmware download and upgrade across your entire ZTB fleet. Handles HA-aware sequencing, resumable operations, and interactive or CLI-driven workflows.

**Key features:**
- **Download-only** or **download + upgrade** modes
- **HA-aware**: upgrades standby first, waits for failover, then upgrades former master (zero downtime)
- **Flexible selection**: by site (glob), cluster, version threshold, gateway list, or file
- **Resumable**: state saved after each gateway, interrupted runs resume cleanly
- **Interactive wizard**: run without arguments for guided mode
- **Reports**: JSON + CSV output for audit trail
- **Dry-run**: preview the plan without executing

### Quick start

```bash
# Interactive wizard
python3 ztb_bulk_upgrade.py

# View inventory
python3 ztb_bulk_upgrade.py inventory

# Download firmware only (no reboot)
python3 ztb_bulk_upgrade.py download --version latest --all

# Upgrade all gateways below a version
python3 ztb_bulk_upgrade.py upgrade --version latest --below-version 24.3.0

# Dry-run first
python3 ztb_bulk_upgrade.py upgrade --version 24.3.1 --site "Paris-*" --dry-run

# Resume an interrupted run
python3 ztb_bulk_upgrade.py resume
```

Full documentation: [docs/ztb-bulk-upgrade.md](docs/ztb-bulk-upgrade.md)

## Prerequisites

- Python 3.10+ (stdlib only, no external dependencies)
- Zscaler credentials:

```bash
# .env file (same directory as script)
ZSCALER_CLIENT_ID=<your_client_id>
ZSCALER_CLIENT_SECRET=<your_client_secret>
ZSCALER_VANITY_DOMAIN=<your_vanity_domain>
ZSCALER_AIRGAP_SITE=<your_airgap_site>
```

Or pass credentials via CLI flags (`--client-id`, `--client-secret`, etc.).

## Contributing

More ZTB automation tools will be added over time. Each tool is a standalone Python script with no external dependencies.

## License

MIT
