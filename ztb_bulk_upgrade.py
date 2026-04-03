#!/usr/bin/env python3
"""
Bulk upgrade tool for Zscaler ZTB (Zero Trust Branch) gateways via AirGap API.

Supports inventory listing, firmware download, upgrade orchestration, and
resume of interrupted operations. Uses OAuth2 client_credentials auth.

Usage:
    # Interactive wizard (default)
    python3 zscaler/ztb_bulk_upgrade.py

    # List all gateways with current versions
    python3 zscaler/ztb_bulk_upgrade.py inventory

    # Download firmware to all gateways
    python3 zscaler/ztb_bulk_upgrade.py download --version 25.1.2 --all

    # Upgrade a specific site (dry-run first)
    python3 zscaler/ztb_bulk_upgrade.py upgrade --version 25.1.2 --site pve-ztb --dry-run
    python3 zscaler/ztb_bulk_upgrade.py upgrade --version 25.1.2 --site pve-ztb

    # Upgrade gateways below a certain version
    python3 zscaler/ztb_bulk_upgrade.py upgrade --version 25.1.2 --below-version 25.1.0

    # Resume an interrupted upgrade
    python3 zscaler/ztb_bulk_upgrade.py resume

Credentials: .env at repo root (ZSCALER_CLIENT_ID, ZSCALER_CLIENT_SECRET,
ZSCALER_VANITY_DOMAIN, ZSCALER_AIRGAP_SITE) or CLI flags / env vars.
"""
import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from fnmatch import fnmatch

# ── Constants ─────────────────────────────────────────────────────────────
STATE_FILE = ".ztb_upgrade_state.json"
POLL_INTERVAL = 30
DEFAULT_TIMEOUT = 15
TOKEN_AUDIENCE = "https://api.zscaler.com"
TOKEN_REFRESH_MARGIN = 60  # seconds before expiry to trigger refresh


# ── Env loading ───────────────────────────────────────────────────────────

def load_env(path=None):
    """Load key=value pairs from a .env file into os.environ (setdefault).

    Skips blank lines and comments. Does not override existing env vars.
    Default path: .env in the parent directory of this script's directory.
    """
    if path is None:
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            ".env",
        )
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())


# ── Config resolution ─────────────────────────────────────────────────────

_CREDENTIAL_KEYS = {
    "client_id":     "ZSCALER_CLIENT_ID",
    "client_secret": "ZSCALER_CLIENT_SECRET",
    "vanity_domain": "ZSCALER_VANITY_DOMAIN",
    "airgap_site":   "ZSCALER_AIRGAP_SITE",
}


def get_config(args):
    """Resolve credentials from CLI flags > .env > env vars.

    Returns a dict with keys: client_id, client_secret, vanity_domain,
    airgap_site, token_url, api_base.
    Exits with a clear error if any required credential is missing.
    """
    env_file = getattr(args, "env_file", None)
    load_env(env_file)

    config = {}
    missing = []
    for key, env_var in _CREDENTIAL_KEYS.items():
        # CLI flag takes precedence (may be None if not provided)
        cli_val = getattr(args, key, None)
        value = cli_val or os.environ.get(env_var)
        if not value:
            missing.append(f"  --{key.replace('_', '-')} / {env_var}")
        else:
            config[key] = value

    if missing:
        print("ERROR: Missing required credentials:", file=sys.stderr)
        for m in missing:
            print(m, file=sys.stderr)
        print("\nProvide via CLI flags, .env file, or environment variables.",
              file=sys.stderr)
        sys.exit(1)

    # Derived URLs
    config["token_url"] = (
        f"https://{config['vanity_domain']}.zslogin.net/oauth2/v1/token"
    )
    config["api_base"] = (
        f"https://{config['airgap_site']}-api.goairgap.com"
    )
    return config


# ── API error ─────────────────────────────────────────────────────────────

class ApiError(Exception):
    """HTTP error from the AirGap API."""

    def __init__(self, status, body, url):
        self.status = status
        self.body = body
        self.url = url
        super().__init__(f"HTTP {status} on {url}: {body[:300]}")


# ── API client ────────────────────────────────────────────────────────────

class ApiClient:
    """OAuth2 client for the ZTB AirGap API with automatic token refresh."""

    def __init__(self, config):
        self._client_id = config["client_id"]
        self._client_secret = config["client_secret"]
        self._token_url = config["token_url"]
        self._api_base = config["api_base"]
        self._token = None
        self._token_expiry = 0  # epoch timestamp

    # ── Auth ──────────────────────────────────────────────────────────

    def _ensure_token(self):
        """Obtain or refresh the OAuth2 token if needed."""
        if self._token and time.time() < (self._token_expiry - TOKEN_REFRESH_MARGIN):
            return
        data = urllib.parse.urlencode({
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "grant_type": "client_credentials",
            "audience": TOKEN_AUDIENCE,
        }).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        req = urllib.request.Request(self._token_url, data=data,
                                     headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req) as resp:
                result = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            raise ApiError(e.code, body, self._token_url)
        self._token = result["access_token"]
        self._token_expiry = time.time() + result.get("expires_in", 3600)

    # ── HTTP helpers ─────────────────────────────────────────────────

    def request(self, method, path, data=None):
        """Send an authenticated request to the AirGap API.

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, PATCH).
            path: API path (e.g. '/api/v2/Gateway/releases').
            data: Optional dict to send as JSON body.

        Returns:
            Parsed JSON response (dict or list).

        Raises:
            ApiError: On non-2xx HTTP responses.
        """
        self._ensure_token()
        url = f"{self._api_base}{path}"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers,
                                     method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            error_body = e.read().decode()
            raise ApiError(e.code, error_body, url)

    def get(self, path):
        """GET request to the AirGap API."""
        return self.request("GET", path)

    def post(self, path, data=None):
        """POST request to the AirGap API."""
        return self.request("POST", path, data)


# ── Inventory (Task 2) ────────────────────────────────────────────────────

def _build_cluster_site_map(api):
    """Build a cluster_id → site_name mapping from the Sites API.

    Returns:
        dict mapping int cluster_id to str site_name.
    """
    try:
        resp = api.get("/api/v2/Site/")
    except ApiError:
        return {}
    rows = resp.get("result", resp) if isinstance(resp, dict) else resp
    if isinstance(rows, dict):
        rows = rows.get("rows", [])
    site_map = {}
    for site in rows:
        name = site.get("name", site.get("display_name", "unknown"))
        for cluster in site.get("clusters", []):
            cid = cluster.get("cluster_id")
            if cid is not None:
                site_map[cid] = name
    return site_map


def fetch_gateways(api):
    """Fetch all gateways from the AirGap API.

    Returns:
        List of normalized gateway dicts with keys: id, name, site_id,
        site_name, cluster_id, running_version, desired_version, status,
        ha_role, download_status, sw_image_status.
        Sorted by site_name then name.
    """
    resp = api.get("/api/v2/Gateway/")

    # Unwrap response: may be {result: {rows: [...]}} or {result: [...]} or [...]
    if isinstance(resp, dict):
        inner = resp.get("result", resp)
        if isinstance(inner, dict):
            raw_gateways = inner.get("rows", [])
        elif isinstance(inner, list):
            raw_gateways = inner
        else:
            raw_gateways = []
    elif isinstance(resp, list):
        raw_gateways = resp
    else:
        raw_gateways = []

    if not raw_gateways:
        return []

    # Debug: if expected fields are missing, dump first gateway to stderr
    expected_fields = {"gateway_id", "gateway_name", "cluster_id", "running_version"}
    first_keys = set(raw_gateways[0].keys())
    if not expected_fields.issubset(first_keys):
        print(f"DEBUG: unexpected gateway fields: {sorted(first_keys)}",
              file=sys.stderr)
        print(json.dumps(raw_gateways[0], indent=2, default=str),
              file=sys.stderr)

    # Build cluster_id → site_name map
    site_map = _build_cluster_site_map(api)

    gateways = []
    for gw in raw_gateways:
        cluster_id = gw.get("cluster_id")
        vrrp = gw.get("vrrp_state", "")
        desired_state = gw.get("desired_state", "")
        operational_state = gw.get("operational_state", "")

        # Determine HA role
        if desired_state == "standalone" or operational_state == "standalone":
            ha_role = "standalone"
        elif vrrp == "master":
            ha_role = "active"
        elif vrrp == "backup":
            ha_role = "standby"
        else:
            ha_role = vrrp or "unknown"

        # Determine online status from health_color
        health = gw.get("health_color", "")
        if health == "green":
            status = "online"
        elif health == "red":
            status = "offline"
        else:
            status = health or "unknown"

        gateways.append({
            "id": gw.get("gateway_id", gw.get("id", "")),
            "name": gw.get("gateway_name", gw.get("name", "unknown")),
            "site_id": "",  # Not directly on gateway object
            "site_name": site_map.get(cluster_id, "unknown"),
            "cluster_id": cluster_id,
            "running_version": gw.get("running_version", ""),
            "desired_version": gw.get("desired_version", ""),
            "status": status,
            "ha_role": ha_role,
            "download_status": gw.get("download_status", {}),
            "sw_image_status": gw.get("sw_image_status", {}),
        })

    gateways.sort(key=lambda g: (g["site_name"], g["name"]))
    return gateways


def fetch_releases(api):
    """Fetch available firmware releases from the AirGap API.

    Returns:
        List of release dicts sorted by release_date descending (newest first).
    """
    resp = api.get("/api/v2/Gateway/releases")

    # Unwrap response
    if isinstance(resp, dict):
        releases = resp.get("result", [])
        if isinstance(releases, dict):
            releases = releases.get("rows", [])
    elif isinstance(resp, list):
        releases = resp
    else:
        releases = []

    # Sort newest first
    releases.sort(key=lambda r: r.get("release_date", ""), reverse=True)
    return releases


def resolve_version(api, version_arg):
    """Resolve a version argument to a concrete version string.

    If version_arg is "latest", returns the newest available version.
    Otherwise validates the version exists in the releases list.

    Returns:
        str: The resolved version string.

    Exits with error if the version is not found.
    """
    releases = fetch_releases(api)
    if not releases:
        print("ERROR: No releases available from the API.", file=sys.stderr)
        sys.exit(1)

    if version_arg == "latest":
        version = releases[0]["version_number"]
        return version

    available = [r["version_number"] for r in releases]
    if version_arg in available:
        return version_arg

    print(f"ERROR: Version '{version_arg}' not found in available releases.",
          file=sys.stderr)
    print(f"Available: {', '.join(available)}", file=sys.stderr)
    sys.exit(1)


# ── Gateway selection (Task 3) ───────────────────────────────────────────

def version_lt(a, b):
    """Compare version strings as tuples of ints. Returns True if a < b.

    Non-numeric suffixes (e.g. 'rc37', 'HF1') are stripped for comparison.
    If versions are equal in numeric parts, the raw strings are compared.
    """

    def parse(v):
        return tuple(int(x) for x in re.findall(r'\d+', v))

    pa, pb = parse(a), parse(b)
    if pa == pb:
        return a < b
    return pa < pb


def select_gateways(gateways, args):
    """Filter gateways based on CLI selection flags.

    Filters combine as AND (all specified filters must match).
    At least one selection flag must be specified.

    Returns:
        List of matching gateway dicts.
    """
    has_filter = any([
        getattr(args, "select_all", False),
        getattr(args, "site", None),
        getattr(args, "cluster", None),
        getattr(args, "gateway", None),
        getattr(args, "below_version", None),
        getattr(args, "from_file", None),
    ])

    if not has_filter:
        print("ERROR: No gateway selection specified. Use one of: "
              "--all, --site, --cluster, --gateway, --below-version, --from-file",
              file=sys.stderr)
        sys.exit(1)

    selected = list(gateways)

    # --all: no filtering needed
    if not getattr(args, "select_all", False):
        # --site: glob match on site_name
        if getattr(args, "site", None):
            pattern = args.site
            selected = [g for g in selected
                        if fnmatch(g["site_name"], pattern)]

        # --cluster: match on cluster_id (as string)
        if getattr(args, "cluster", None):
            cluster_val = args.cluster
            selected = [g for g in selected
                        if str(g["cluster_id"]) == cluster_val]

        # --gateway: comma-separated list of gateway names
        if getattr(args, "gateway", None):
            names = {n.strip() for n in args.gateway.split(",")}
            selected = [g for g in selected if g["name"] in names]

        # --from-file: one gateway ID/name per line
        if getattr(args, "from_file", None):
            try:
                with open(args.from_file) as f:
                    file_ids = {line.strip() for line in f
                                if line.strip() and not line.startswith("#")}
            except FileNotFoundError:
                print(f"ERROR: File not found: {args.from_file}", file=sys.stderr)
                sys.exit(1)
            selected = [g for g in selected
                        if g["name"] in file_ids or g["id"] in file_ids]

        # --below-version: only gateways running below specified version
        if getattr(args, "below_version", None):
            threshold = args.below_version
            selected = [g for g in selected
                        if g["running_version"]
                        and version_lt(g["running_version"], threshold)]

    return selected


def partition_by_cluster(gateways):
    """Group gateways by cluster_id.

    Returns:
        Tuple of (clusters_dict, standalone_list) where:
        - clusters_dict: {cluster_id: [gw, ...]} for gateways in HA clusters
        - standalone_list: [gw, ...] for standalone gateways
    """
    clusters = defaultdict(list)
    standalone = []

    for gw in gateways:
        if gw["ha_role"] == "standalone":
            standalone.append(gw)
        else:
            clusters[gw["cluster_id"]].append(gw)

    # Within each cluster, sort BACKUP/standby first (upgrade standby before active)
    for cid in clusters:
        clusters[cid].sort(
            key=lambda g: (0 if g["ha_role"] == "standby" else 1, g["name"])
        )

    return dict(clusters), standalone


def skip_at_target(gateways, target_version):
    """Separate gateways already at the target version.

    Returns:
        Tuple of (to_process, skipped) lists.
    """
    to_process = []
    skipped = []
    for gw in gateways:
        if gw["running_version"] == target_version:
            skipped.append(gw)
        else:
            to_process.append(gw)
    return to_process, skipped


# ── Pre-checks, plan display, dry-run (Task 4) ──────────────────────────

def run_prechecks(api, target_version):
    """Run pre-flight checks before an operation.

    Tests:
    1. API connectivity (fetch releases)
    2. Target version exists in available releases

    Exits on failure.
    """
    print("  [1/2] Checking API connectivity...", end=" ", flush=True)
    try:
        releases = fetch_releases(api)
    except (ApiError, urllib.error.URLError) as e:
        print("FAILED")
        print(f"ERROR: Cannot reach AirGap API: {e}", file=sys.stderr)
        sys.exit(1)
    print("OK")

    print(f"  [2/2] Verifying target version {target_version}...", end=" ", flush=True)
    available = [r["version_number"] for r in releases]
    if target_version not in available:
        print("FAILED")
        print(f"ERROR: Version '{target_version}' not available.",
              file=sys.stderr)
        print(f"Available: {', '.join(available)}", file=sys.stderr)
        sys.exit(1)
    print("OK")


def display_plan(command, target, clusters, standalone, skipped, on_error,
                 dry_run):
    """Display the execution plan for download/upgrade.

    Args:
        command: 'download' or 'upgrade'
        target: target version string
        clusters: dict of {cluster_id: [gw, ...]}
        standalone: list of standalone gateways
        skipped: list of gateways already at target
        on_error: 'continue' or 'stop'
        dry_run: bool
    """
    total = sum(len(gws) for gws in clusters.values()) + len(standalone)

    mode = "DRY RUN" if dry_run else "LIVE"
    print(f"\n{'='*70}")
    print(f"  {command.upper()} PLAN [{mode}]")
    print(f"{'='*70}")
    print(f"  Target version : {target}")
    print(f"  Gateways       : {total} to process, {len(skipped)} skipped (already at target)")
    print(f"  On error       : {on_error}")

    if skipped:
        print(f"\n  Skipped (already at {target}):")
        for gw in skipped:
            print(f"    - {gw['name']} ({gw['site_name']})")

    step = 1

    if clusters:
        print(f"\n  Clustered gateways (standby first, then active):")
        for cid, gws in sorted(clusters.items()):
            site = gws[0]["site_name"] if gws else "unknown"
            print(f"    Cluster {cid} ({site}):")
            for gw in gws:
                print(f"      Step {step}: {gw['name']} [{gw['ha_role']}] "
                      f"({gw['running_version']} → {target})")
                step += 1

    if standalone:
        print(f"\n  Standalone gateways:")
        for gw in standalone:
            print(f"      Step {step}: {gw['name']} ({gw['site_name']}) "
                  f"({gw['running_version']} → {target})")
            step += 1

    print()


def _prepare_run(api, args, command):
    """Orchestrate pre-checks, selection, and plan display.

    Steps: resolve_version → run_prechecks → fetch_gateways →
           select_gateways → skip_at_target → partition_by_cluster →
           display_plan.

    On dry-run: prints plan and exits.
    Otherwise: prompts for confirmation.

    Returns:
        Tuple of (target, clusters, standalone, skipped).
    """
    print(f"\n--- {command.upper()} preparation ---\n")

    # Resolve version
    target = resolve_version(api, args.version)
    print(f"  Target version: {target}")

    # Pre-checks
    print("\n  Pre-checks:")
    run_prechecks(api, target)

    # Fetch and filter
    gateways = fetch_gateways(api)
    print(f"\n  Fetching gateways... {len(gateways)} found")

    selected = select_gateways(gateways, args)
    if not selected:
        print("ERROR: No gateways match the selection criteria.",
              file=sys.stderr)
        sys.exit(1)
    print(f"  Selected: {len(selected)} gateway(s)")

    # Skip already-at-target
    to_process, skipped = skip_at_target(selected, target)

    if not to_process:
        print(f"\n  All {len(skipped)} selected gateway(s) are already at "
              f"version {target}. Nothing to do.")
        sys.exit(0)

    # Partition
    clusters, standalone = partition_by_cluster(to_process)

    # Display plan
    dry_run = getattr(args, "dry_run", False)
    on_error = getattr(args, "on_error", "continue")
    display_plan(command, target, clusters, standalone, skipped, on_error,
                 dry_run)

    if dry_run:
        print("  Dry-run mode — no changes made.")
        sys.exit(0)

    # Confirm
    try:
        answer = input("  Proceed? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n  Aborted.")
        sys.exit(1)

    if answer not in ("y", "yes"):
        print("  Aborted.")
        sys.exit(1)

    return target, clusters, standalone, skipped


# ── State management (Task 5) ────────────────────────────────────────────

def create_state(command, target_version, clusters, standalone, skipped,
                 on_error):
    """Create initial state dict for a run.

    Args:
        command: 'download' or 'upgrade'
        target_version: target firmware version string
        clusters: dict {cluster_id: [gw_dicts]}
        standalone: list of standalone gw_dicts
        skipped: list of gw_dicts already at target
        on_error: 'continue' or 'stop'

    Returns:
        State dict with run metadata and per-gateway entries.
    """
    now = datetime.now(timezone.utc)
    run_id = now.strftime("%Y%m%d-%H%M%S")

    # Build ordered list of cluster IDs (sorted for determinism)
    clusters_order = sorted(clusters.keys(), key=lambda c: str(c))

    gateways = {}

    # Add clustered gateways
    for cid in clusters_order:
        for gw in clusters[cid]:
            gateways[str(gw["id"])] = {
                "name": gw["name"],
                "site": gw.get("site_name", "unknown"),
                "cluster_id": gw.get("cluster_id"),
                "ha_role": gw.get("ha_role", "unknown"),
                "version_before": gw.get("running_version", ""),
                "version_after": None,
                "status": "pending",
                "phase": None,
                "error": None,
                "started": None,
                "finished": None,
            }

    # Add standalone gateways
    for gw in standalone:
        gateways[str(gw["id"])] = {
            "name": gw["name"],
            "site": gw.get("site_name", "unknown"),
            "cluster_id": gw.get("cluster_id"),
            "ha_role": gw.get("ha_role", "standalone"),
            "version_before": gw.get("running_version", ""),
            "version_after": None,
            "status": "pending",
            "phase": None,
            "error": None,
            "started": None,
            "finished": None,
        }

    # Add skipped gateways
    for gw in skipped:
        gateways[str(gw["id"])] = {
            "name": gw["name"],
            "site": gw.get("site_name", "unknown"),
            "cluster_id": gw.get("cluster_id"),
            "ha_role": gw.get("ha_role", "unknown"),
            "version_before": gw.get("running_version", ""),
            "version_after": gw.get("running_version", ""),
            "status": "skipped",
            "phase": None,
            "error": None,
            "started": None,
            "finished": None,
        }

    return {
        "run_id": run_id,
        "command": command,
        "target_version": target_version,
        "on_error": on_error,
        "clusters_order": [str(c) for c in clusters_order],
        "started": now.isoformat(),
        "finished": None,
        "gateways": gateways,
    }


def save_state(state):
    """Persist state to the state file (JSON, human-readable)."""
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2, default=str)


def load_state():
    """Load state from the state file.

    Returns:
        State dict, or None if file does not exist.
    """
    if not os.path.exists(STATE_FILE):
        return None
    with open(STATE_FILE) as f:
        return json.load(f)


def update_gateway_state(state, gw_id, **kwargs):
    """Update a gateway's fields in the state and persist immediately.

    Args:
        state: the state dict (modified in place)
        gw_id: gateway ID (string key in state["gateways"])
        **kwargs: fields to update (e.g. status="downloading", phase="download")
    """
    gw_id = str(gw_id)
    if gw_id in state["gateways"]:
        state["gateways"][gw_id].update(kwargs)
        save_state(state)


# ── Core engine (Task 6) ────────────────────────────────────────────────

def cleanup_old_images(api, gw_id, target_version):
    """Delete old staged images from a gateway to free disk space.

    Checks sw_image_status.images[] for staged images that are not the
    currently running version and not the target version, then deletes them.
    """
    try:
        gw_data = api.get(f"/api/v2/Gateway/id/{gw_id}")
        # Unwrap if needed
        if isinstance(gw_data, dict) and "result" in gw_data:
            gw_data = gw_data["result"]
            if isinstance(gw_data, list) and gw_data:
                gw_data = gw_data[0]
    except ApiError:
        return  # Non-fatal, proceed with download

    running = gw_data.get("running_version", "")
    images = gw_data.get("sw_image_status", {}).get("images", [])

    for img in images:
        img_version = img.get("version", "")
        if img_version and img_version != running and img_version != target_version:
            try:
                api.post(
                    f"/api/v2/Gateway/sw_image_update/id/{gw_id}",
                    {"action": "delete", "version": img_version},
                )
            except ApiError:
                pass  # Non-fatal


def download_image(api, gw_id, target_version):
    """Initiate firmware download on a gateway.

    POST /api/v2/Gateway/sw_image_update/id/{gw_id}
    """
    return api.post(
        f"/api/v2/Gateway/sw_image_update/id/{gw_id}",
        {"action": "download", "version": target_version},
    )


def activate_upgrade(api, gw_id, target_version):
    """Activate a firmware upgrade on a gateway.

    POST /api/v2/Gateway/upgrade
    """
    return api.post(
        "/api/v2/Gateway/upgrade",
        {"gateway_id": gw_id, "desired_version": target_version},
    )


def check_image_downloaded(api, gw_id, target_version):
    """Check if the target firmware image is downloaded on a gateway.

    Returns True if the image status shows downloaded/completed.
    """
    try:
        gw_data = api.get(f"/api/v2/Gateway/id/{gw_id}")
        if isinstance(gw_data, dict) and "result" in gw_data:
            gw_data = gw_data["result"]
            if isinstance(gw_data, list) and gw_data:
                gw_data = gw_data[0]
    except ApiError:
        return False

    # Check sw_image_status.images[]
    images = gw_data.get("sw_image_status", {}).get("images", [])
    for img in images:
        if img.get("version") == target_version:
            status = img.get("status", "").lower()
            if status in ("downloaded", "completed"):
                return True

    # Also check download_status.versions[]
    versions = gw_data.get("download_status", {}).get("versions", [])
    for ver in versions:
        if ver.get("version") == target_version:
            status = ver.get("status", "").lower()
            if status in ("downloaded", "completed"):
                return True

    return False


def poll_gateway(api, gw_id, target_version, timeout_minutes):
    """Poll a gateway until it is online at the target version, or timeout.

    Args:
        api: ApiClient instance
        gw_id: gateway ID
        target_version: expected version after upgrade
        timeout_minutes: max wait time in minutes

    Returns:
        True if gateway is online at target version, False on timeout.
    """
    deadline = time.time() + (timeout_minutes * 60)
    while time.time() < deadline:
        try:
            gw_data = api.get(f"/api/v2/Gateway/id/{gw_id}")
            if isinstance(gw_data, dict) and "result" in gw_data:
                gw_data = gw_data["result"]
                if isinstance(gw_data, list) and gw_data:
                    gw_data = gw_data[0]

            running = gw_data.get("running_version", "")
            health = gw_data.get("health_color", "")
            if running == target_version and health == "green":
                return True
        except (ApiError, urllib.error.URLError):
            pass  # Gateway may be rebooting, keep polling

        time.sleep(POLL_INTERVAL)

    return False


def process_gateway(api, state, gw_id, target_version, command, timeout):
    """Orchestrate download/upgrade for a single gateway.

    Args:
        api: ApiClient instance
        state: state dict (modified in place)
        gw_id: gateway ID string
        target_version: target firmware version
        command: 'download' or 'upgrade'
        timeout: per-gateway timeout in minutes

    Returns:
        True on success, False on failure.
    """
    gw_state = state["gateways"].get(str(gw_id))
    if not gw_state:
        return False

    gw_name = gw_state["name"]
    ha_label = gw_state["ha_role"].upper()
    t0 = time.time()

    update_gateway_state(state, gw_id, status="in_progress",
                         started=datetime.now(timezone.utc).isoformat())

    # Phase 1: Download (if not already downloaded)
    if gw_state.get("phase") != "downloaded":
        print(f"  {gw_name} ({ha_label})  cleaning old images...", end=" ",
              flush=True)
        update_gateway_state(state, gw_id, phase="cleanup")
        try:
            cleanup_old_images(api, gw_id, target_version)
            print("done")
        except Exception as e:
            print(f"warning: {e}")
            # Non-fatal, continue

        print(f"  {gw_name} ({ha_label})  downloading...", end=" ", flush=True)
        update_gateway_state(state, gw_id, phase="download")
        try:
            download_image(api, gw_id, target_version)
        except ApiError as e:
            elapsed = int(time.time() - t0)
            print(f"FAILED ({elapsed}s)")
            update_gateway_state(state, gw_id, status="failed",
                                 phase="download", error=str(e),
                                 finished=datetime.now(timezone.utc).isoformat())
            return False

        # Poll until download completes
        dl_deadline = time.time() + (timeout * 60)
        while time.time() < dl_deadline:
            if check_image_downloaded(api, gw_id, target_version):
                break
            time.sleep(POLL_INTERVAL)
        else:
            elapsed = int(time.time() - t0)
            print(f"TIMEOUT ({elapsed}s)")
            update_gateway_state(state, gw_id, status="failed",
                                 phase="download", error="download timed out",
                                 finished=datetime.now(timezone.utc).isoformat())
            return False

        elapsed = int(time.time() - t0)
        print(f"done ({elapsed}s)")
        update_gateway_state(state, gw_id, phase="downloaded")

    # If command is download-only, we're done
    if command == "download":
        update_gateway_state(state, gw_id, status="completed",
                             phase="downloaded",
                             finished=datetime.now(timezone.utc).isoformat())
        return True

    # Phase 2: Activate upgrade
    print(f"  {gw_name} ({ha_label})  upgrading...", end=" ", flush=True)
    update_gateway_state(state, gw_id, phase="activate")
    try:
        activate_upgrade(api, gw_id, target_version)
    except ApiError as e:
        elapsed = int(time.time() - t0)
        print(f"FAILED ({elapsed}s)")
        update_gateway_state(state, gw_id, status="failed",
                             phase="activate", error=str(e),
                             finished=datetime.now(timezone.utc).isoformat())
        return False

    # Poll until gateway is online at target version
    if poll_gateway(api, gw_id, target_version, timeout):
        elapsed = int(time.time() - t0)
        print(f"done ({elapsed}s)")
        update_gateway_state(state, gw_id, status="completed",
                             phase="complete",
                             version_after=target_version,
                             finished=datetime.now(timezone.utc).isoformat())
        return True
    else:
        elapsed = int(time.time() - t0)
        print(f"TIMEOUT ({elapsed}s)")
        update_gateway_state(state, gw_id, status="failed",
                             phase="activate",
                             error="upgrade timed out waiting for gateway",
                             finished=datetime.now(timezone.utc).isoformat())
        return False


def process_cluster(api, state, cluster_id, gw_ids, target_version, command,
                    args):
    """Process a cluster with HA-aware ordering.

    Processes standby/backup gateways first, then active.
    On failure with on_error="stop": returns False immediately.
    On failure with on_error="continue": skips remaining in cluster.

    Args:
        api: ApiClient instance
        state: state dict
        cluster_id: cluster identifier
        gw_ids: list of gateway ID strings in this cluster
        target_version: target firmware version
        command: 'download' or 'upgrade'
        args: parsed CLI args (has on_error, timeout)

    Returns:
        True if all gateways succeeded, False if any failed.
    """
    on_error = getattr(args, "on_error", "continue")
    timeout = getattr(args, "timeout", DEFAULT_TIMEOUT)

    # Sort gateway IDs: standby/backup first
    def sort_key(gw_id):
        gw = state["gateways"].get(str(gw_id), {})
        role = gw.get("ha_role", "unknown")
        return (0 if role == "standby" else 1, gw.get("name", ""))

    sorted_ids = sorted(gw_ids, key=sort_key)

    cluster_ok = True
    for gw_id in sorted_ids:
        gw = state["gateways"].get(str(gw_id), {})
        # Skip already completed or skipped
        if gw.get("status") in ("completed", "skipped"):
            continue

        success = process_gateway(api, state, gw_id, target_version, command,
                                  timeout)
        if not success:
            cluster_ok = False
            if on_error == "stop":
                return False
            # on_error == "continue": skip remaining in this cluster
            for remaining_id in sorted_ids[sorted_ids.index(gw_id) + 1:]:
                remaining = state["gateways"].get(str(remaining_id), {})
                if remaining.get("status") == "pending":
                    update_gateway_state(
                        state, remaining_id,
                        status="skipped",
                        error="skipped due to prior failure in cluster",
                    )
            break

    return cluster_ok


def _run(api, command, target, clusters, standalone, skipped, args):
    """Top-level orchestration for download/upgrade.

    Creates state, processes clusters sequentially, then standalone gateways,
    and generates summary and reports.

    Args:
        api: ApiClient instance
        command: 'download' or 'upgrade'
        target: target firmware version
        clusters: dict {cluster_id: [gw_dicts]}
        standalone: list of standalone gw_dicts
        skipped: list of skipped gw_dicts
        args: parsed CLI args
    """
    on_error = getattr(args, "on_error", "continue")
    timeout = getattr(args, "timeout", DEFAULT_TIMEOUT)
    t0 = time.time()

    state = create_state(command, target, clusters, standalone, skipped,
                         on_error)
    save_state(state)
    print(f"\n  State file: {STATE_FILE} (run_id: {state['run_id']})\n")

    # Process clusters sequentially
    for cid in state["clusters_order"]:
        # Collect gateway IDs for this cluster (handle int/str key mismatch)
        cluster_gws = clusters.get(cid, [])
        if not cluster_gws:
            try:
                cluster_gws = clusters.get(int(cid), [])
            except (ValueError, TypeError):
                pass
        gw_ids = [str(gw["id"]) for gw in cluster_gws]
        if not gw_ids:
            continue

        site = state["gateways"][gw_ids[0]]["site"] if gw_ids else "unknown"
        print(f"  --- Cluster {cid} ({site}) ---")

        ok = process_cluster(api, state, cid, gw_ids, target, command, args)
        if not ok and on_error == "stop":
            print("\n  Stopping due to failure (--on-error=stop).")
            break

    # Process standalone gateways
    if standalone:
        print(f"\n  --- Standalone gateways ---")
        for gw in standalone:
            gw_id = str(gw["id"])
            gw_state = state["gateways"].get(gw_id, {})
            if gw_state.get("status") in ("completed", "skipped"):
                continue
            ok = process_gateway(api, state, gw_id, target, command, timeout)
            if not ok and on_error == "stop":
                print("\n  Stopping due to failure (--on-error=stop).")
                break

    elapsed = time.time() - t0
    state["finished"] = datetime.now(timezone.utc).isoformat()
    save_state(state)

    print()
    print_summary(state, elapsed)
    write_reports(state, elapsed)


# ── Resume (Task 7) ─────────────────────────────────────────────────────


# ── Summary and reports (Task 8) ────────────────────────────────────────

def print_summary(state, elapsed_seconds):
    """Display a summary of the run with status counts.

    Args:
        state: state dict with gateway entries
        elapsed_seconds: total elapsed time in seconds
    """
    gateways = state.get("gateways", {})

    completed = [g for g in gateways.values() if g["status"] == "completed"]
    failed = [g for g in gateways.values() if g["status"] == "failed"]
    skipped = [g for g in gateways.values() if g["status"] == "skipped"]
    pending = [g for g in gateways.values()
               if g["status"] not in ("completed", "failed", "skipped")]

    minutes = int(elapsed_seconds) // 60
    seconds = int(elapsed_seconds) % 60

    print(f"{'='*70}")
    print(f"  {state.get('command', 'operation').upper()} SUMMARY "
          f"(run_id: {state['run_id']})")
    print(f"{'='*70}")
    print(f"  Target version : {state.get('target_version', '?')}")
    print(f"  Elapsed time   : {minutes}m {seconds}s")
    print()
    print(f"  \u2713 Completed : {len(completed)}")
    print(f"  \u2717 Failed    : {len(failed)}")
    print(f"  \u25cb Skipped   : {len(skipped)}")
    print(f"  \u2022 Pending   : {len(pending)}")

    if failed:
        print(f"\n  Failed gateways:")
        for g in failed:
            error_msg = g.get("error", "unknown error")
            print(f"    \u2717 {g['name']} — {error_msg}")

    print()


def write_reports(state, elapsed_seconds):
    """Generate JSON and CSV report files for the run.

    Args:
        state: state dict
        elapsed_seconds: total elapsed time in seconds
    """
    run_id = state.get("run_id", "unknown")
    gateways = state.get("gateways", {})

    # Summary counts
    counts = {"completed": 0, "failed": 0, "skipped": 0, "pending": 0}
    for g in gateways.values():
        status = g["status"]
        if status in counts:
            counts[status] += 1
        else:
            counts["pending"] += 1

    # JSON report
    json_path = f"ztb_upgrade_report_{run_id}.json"
    report = {
        "run_id": run_id,
        "command": state.get("command"),
        "target_version": state.get("target_version"),
        "started": state.get("started"),
        "finished": state.get("finished"),
        "duration_seconds": round(elapsed_seconds, 1),
        "summary": counts,
        "gateways": gateways,
    }
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    # CSV report
    csv_path = f"ztb_upgrade_report_{run_id}.csv"
    fieldnames = [
        "gateway_id", "gateway_name", "site", "cluster", "version_before",
        "version_after", "status", "phase", "duration", "error",
    ]
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for gw_id, g in gateways.items():
            # Calculate per-gateway duration
            duration = ""
            if g.get("started") and g.get("finished"):
                try:
                    t_start = datetime.fromisoformat(g["started"])
                    t_end = datetime.fromisoformat(g["finished"])
                    duration = f"{(t_end - t_start).total_seconds():.0f}s"
                except (ValueError, TypeError):
                    pass
            writer.writerow({
                "gateway_id": gw_id,
                "gateway_name": g.get("name", ""),
                "site": g.get("site", ""),
                "cluster": g.get("cluster_id", ""),
                "version_before": g.get("version_before", ""),
                "version_after": g.get("version_after", ""),
                "status": g.get("status", ""),
                "phase": g.get("phase", ""),
                "duration": duration,
                "error": g.get("error", ""),
            })

    print(f"  Reports:")
    print(f"    JSON: {json_path}")
    print(f"    CSV:  {csv_path}")
    print()


# ── Commands ─────────────────────────────────────────────────────────────

def cmd_inventory(api, args):
    """List all gateways with current firmware versions."""
    gateways = fetch_gateways(api)
    releases = fetch_releases(api)

    latest = releases[0]["version_number"] if releases else "unknown"
    total = len(gateways)

    print(f"\n{'='*70}")
    print(f"  ZTB Gateway Inventory — {total} gateway(s), latest firmware: {latest}")
    print(f"{'='*70}")

    # Version distribution
    version_counts = defaultdict(int)
    for gw in gateways:
        version_counts[gw["running_version"] or "(unknown)"] += 1

    print(f"\n  Version distribution:")
    for ver, count in sorted(version_counts.items()):
        marker = " (latest)" if ver == latest else ""
        print(f"    {ver}: {count} gateway(s){marker}")

    # Table
    print(f"\n  {'Gateway':<22} {'Site':<20} {'Cluster':>7}  {'HA Role':<10} {'Version':<15} {'Status'}")
    print(f"  {'-'*22} {'-'*20} {'-'*7}  {'-'*10} {'-'*15} {'-'*8}")
    for gw in gateways:
        status_icon = "\u2713" if gw["status"] == "online" else "\u2717"
        cluster_str = str(gw["cluster_id"]) if gw["cluster_id"] else "-"
        print(f"  {gw['name']:<22} {gw['site_name']:<20} {cluster_str:>7}  "
              f"{gw['ha_role']:<10} {gw['running_version']:<15} "
              f"{status_icon} {gw['status']}")

    print()


def cmd_download(api, args):
    """Download firmware to selected gateways."""
    target, clusters, standalone, skipped = _prepare_run(api, args, "download")
    _run(api, "download", target, clusters, standalone, skipped, args)


def cmd_upgrade(api, args):
    """Upgrade selected gateways to a target version."""
    target, clusters, standalone, skipped = _prepare_run(api, args, "upgrade")
    _run(api, "upgrade", target, clusters, standalone, skipped, args)


def cmd_resume(api, args):
    """Resume an interrupted upgrade operation.

    Loads state from the state file, shows summary of progress, resets
    failed gateways for retry, and replays the remaining work.
    """
    state = load_state()
    if not state:
        print(f"ERROR: No state file found ({STATE_FILE}). Nothing to resume.",
              file=sys.stderr)
        sys.exit(1)

    command = state.get("command", "upgrade")
    target = state.get("target_version", "")
    on_error = state.get("on_error", "continue")
    gateways = state.get("gateways", {})

    # Count current status
    completed = [gid for gid, g in gateways.items()
                 if g["status"] == "completed"]
    failed = [gid for gid, g in gateways.items()
              if g["status"] == "failed"]
    skipped = [gid for gid, g in gateways.items()
               if g["status"] == "skipped"]
    pending = [gid for gid, g in gateways.items()
               if g["status"] not in ("completed", "failed", "skipped")]

    print(f"\n{'='*70}")
    print(f"  RESUME — run_id: {state['run_id']}")
    print(f"{'='*70}")
    print(f"  Command        : {command}")
    print(f"  Target version : {target}")
    print(f"  Completed      : {len(completed)}")
    print(f"  Failed         : {len(failed)}")
    print(f"  Skipped        : {len(skipped)}")
    print(f"  Pending        : {len(pending)}")

    if not failed and not pending:
        print("\n  Nothing to resume — all gateways are completed or skipped.")
        return

    # Reset failed gateways for retry
    if failed:
        print(f"\n  Resetting {len(failed)} failed gateway(s) for retry:")
        for gid in failed:
            g = gateways[gid]
            # If phase was "activate" and command is "upgrade", skip re-download
            if g.get("phase") == "activate" and command == "upgrade":
                new_status = "pending"
                new_phase = "downloaded"
                print(f"    {g['name']}: reset to pending (skip download, "
                      f"image already staged)")
            else:
                new_status = "pending"
                new_phase = None
                print(f"    {g['name']}: reset to pending")

            update_gateway_state(state, gid, status=new_status,
                                 phase=new_phase, error=None, finished=None)

    # Also reset skipped-due-to-failure gateways
    for gid, g in gateways.items():
        if (g["status"] == "skipped"
                and g.get("error", "").startswith("skipped due to")):
            update_gateway_state(state, gid, status="pending", phase=None,
                                 error=None)

    # Confirm
    try:
        answer = input("\n  Proceed with resume? [y/N] ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n  Aborted.")
        sys.exit(1)

    if answer not in ("y", "yes"):
        print("  Aborted.")
        sys.exit(1)

    t0 = time.time()
    timeout = getattr(args, "timeout", DEFAULT_TIMEOUT)

    # Replay cluster order from state
    for cid in state.get("clusters_order", []):
        # Collect gateway IDs for this cluster that still need processing
        gw_ids = [gid for gid, g in gateways.items()
                  if str(g.get("cluster_id")) == str(cid)
                  and g["status"] not in ("completed", "skipped")]
        if not gw_ids:
            continue

        site = gateways[gw_ids[0]]["site"] if gw_ids else "unknown"
        print(f"\n  --- Cluster {cid} ({site}) ---")

        ok = process_cluster(api, state, cid, gw_ids, target, command, args)
        if not ok and on_error == "stop":
            print("\n  Stopping due to failure (--on-error=stop).")
            break

    # Process standalone gateways (those without a cluster in clusters_order)
    cluster_gw_ids = set()
    for cid in state.get("clusters_order", []):
        for gid, g in gateways.items():
            if str(g.get("cluster_id")) == str(cid):
                cluster_gw_ids.add(gid)

    standalone_ids = [gid for gid, g in gateways.items()
                      if gid not in cluster_gw_ids
                      and g["status"] not in ("completed", "skipped")]
    if standalone_ids:
        print(f"\n  --- Standalone gateways ---")
        for gw_id in standalone_ids:
            ok = process_gateway(api, state, gw_id, target, command, timeout)
            if not ok and on_error == "stop":
                print("\n  Stopping due to failure (--on-error=stop).")
                break

    elapsed = time.time() - t0
    state["finished"] = datetime.now(timezone.utc).isoformat()
    save_state(state)

    print()
    print_summary(state, elapsed)
    write_reports(state, elapsed)


def prompt_choice(prompt, options, allow_multi=False):
    """Display numbered options and return selected index (or list if multi).

    Args:
        prompt: Header text shown above options.
        options: List of option label strings.
        allow_multi: If True, accept comma-separated indices.

    Returns:
        int (0-based) or list[int] if allow_multi.

    Raises:
        EOFError / KeyboardInterrupt: propagated to caller.
    """
    print(f"\n  {prompt}")
    for i, opt in enumerate(options, 1):
        print(f"    {i}. {opt}")

    hint = "comma-separated" if allow_multi else "number"
    while True:
        raw = input(f"  Choice ({hint}): ").strip()
        if not raw:
            continue
        if allow_multi:
            try:
                indices = [int(x.strip()) - 1 for x in raw.split(",")]
                if all(0 <= idx < len(options) for idx in indices):
                    return indices
            except ValueError:
                pass
            print(f"    Invalid input. Enter numbers 1-{len(options)} "
                  f"separated by commas.")
        else:
            try:
                idx = int(raw) - 1
                if 0 <= idx < len(options):
                    return idx
            except ValueError:
                pass
            print(f"    Invalid input. Enter a number 1-{len(options)}.")


def run_wizard():
    """Interactive upgrade wizard (no subcommand).

    Guides the user through: action selection, version choice, gateway
    filtering, error handling, plan review, and confirmation before
    launching a download or upgrade operation.
    """
    try:
        _run_wizard_inner()
    except (EOFError, KeyboardInterrupt):
        print("\n  Aborted.")


def _run_wizard_inner():
    """Inner implementation of the interactive wizard."""
    print(f"\n{'='*70}")
    print("  ZTB Bulk Upgrade — Interactive Wizard")
    print(f"{'='*70}")

    # ── Step 1: Load credentials and connect ─────────────────────────
    args = argparse.Namespace()  # empty namespace for get_config
    config = get_config(args)
    api = ApiClient(config)

    print("\n  Connecting to AirGap API...")
    gateways = fetch_gateways(api)
    releases = fetch_releases(api)

    if not gateways:
        print("  No gateways found in tenant. Nothing to do.")
        return

    latest = releases[0]["version_number"] if releases else "unknown"
    print(f"  Found {len(gateways)} gateway(s), latest firmware: {latest}")

    # ── Step 2: Choose action ────────────────────────────────────────
    action = prompt_choice(
        "What would you like to do?",
        ["View inventory", "Download firmware only", "Download + Upgrade"],
    )

    if action == 0:
        inv_args = argparse.Namespace()
        cmd_inventory(api, inv_args)
        return

    command = "download" if action == 1 else "upgrade"

    # ── Step 3: Choose target version ────────────────────────────────
    max_shown = min(5, len(releases))
    version_options = []
    for r in releases[:max_shown]:
        date_str = r.get("release_date", "")[:10] or "unknown date"
        version_options.append(f"{r['version_number']}  ({date_str})")
    version_options.append("Enter manually")

    ver_idx = prompt_choice("Target version:", version_options)

    if ver_idx < max_shown:
        target = releases[ver_idx]["version_number"]
    else:
        raw_ver = input("  Version string: ").strip()
        if not raw_ver:
            print("  Aborted.")
            return
        target = resolve_version(api, raw_ver)

    print(f"\n  Target version: {target}")

    # ── Step 4: Show upgrade gap ─────────────────────────────────────
    to_process, already_at = skip_at_target(gateways, target)
    print(f"  {len(to_process)} gateway(s) need upgrade, "
          f"{len(already_at)} already at {target}")

    if not to_process:
        print("  Nothing to do — all gateways are at the target version.")
        return

    # ── Step 5: Gateway selection ────────────────────────────────────
    # Build data for site/cluster options
    sites = defaultdict(list)
    clusters_map = defaultdict(list)
    for gw in to_process:
        sites[gw["site_name"]].append(gw)
        if gw["cluster_id"]:
            clusters_map[gw["cluster_id"]].append(gw)

    selection_options = [
        f"All ({len(to_process)} gateway(s))",
        "By site",
        "By cluster",
        "Below a specific version",
        "From file",
    ]
    sel_idx = prompt_choice("Select gateways:", selection_options)

    selected = list(to_process)  # default: all

    if sel_idx == 0:
        # All — keep selected as is
        pass

    elif sel_idx == 1:
        # By site
        site_names = sorted(sites.keys())
        if not site_names:
            print("  No sites found.")
            return
        site_options = [f"{s} ({len(sites[s])} gw)" for s in site_names]
        chosen = prompt_choice("Select site(s):", site_options,
                               allow_multi=True)
        chosen_sites = {site_names[i] for i in chosen}
        selected = [gw for gw in to_process
                    if gw["site_name"] in chosen_sites]

    elif sel_idx == 2:
        # By cluster
        cluster_ids = sorted(clusters_map.keys(), key=str)
        if not cluster_ids:
            print("  No clusters found (all gateways are standalone).")
            return
        cluster_options = []
        for cid in cluster_ids:
            gws = clusters_map[cid]
            site = gws[0]["site_name"] if gws else "unknown"
            cluster_options.append(f"Cluster {cid} — {site} ({len(gws)} gw)")
        chosen = prompt_choice("Select cluster(s):", cluster_options,
                               allow_multi=True)
        chosen_ids = {cluster_ids[i] for i in chosen}
        selected = [gw for gw in to_process
                    if gw["cluster_id"] in chosen_ids]

    elif sel_idx == 3:
        # Below a specific version
        threshold = input("  Version threshold (gateways below this): ").strip()
        if not threshold:
            print("  Aborted.")
            return
        selected = [gw for gw in to_process
                    if gw["running_version"]
                    and version_lt(gw["running_version"], threshold)]

    elif sel_idx == 4:
        # From file
        fpath = input("  File path (one gateway name per line): ").strip()
        if not fpath:
            print("  Aborted.")
            return
        try:
            with open(fpath) as f:
                file_ids = {line.strip() for line in f
                            if line.strip() and not line.startswith("#")}
        except FileNotFoundError:
            print(f"  ERROR: File not found: {fpath}")
            return
        selected = [gw for gw in to_process
                    if gw["name"] in file_ids or gw["id"] in file_ids]

    if not selected:
        print("  No gateways match the selection. Aborting.")
        return

    print(f"\n  Selected {len(selected)} gateway(s) for {command}.")

    # ── Step 6: On-error behavior ────────────────────────────────────
    err_idx = prompt_choice("On error:", ["Continue", "Stop"])
    on_error = "continue" if err_idx == 0 else "stop"

    # ── Step 7: Partition, display plan, confirm ─────────────────────
    # Re-split selected against target (already filtered, but
    # partition needs only the to-process set)
    final_process, final_skipped = skip_at_target(selected, target)
    if not final_process:
        print("  All selected gateways are already at target. Nothing to do.")
        return

    clusters, standalone = partition_by_cluster(final_process)
    display_plan(command, target, clusters, standalone,
                 final_skipped + already_at, on_error, dry_run=False)

    answer = input("  Proceed? [y/N] ").strip().lower()
    if answer not in ("y", "yes"):
        print("  Aborted.")
        return

    # ── Step 8: Build args namespace and run ─────────────────────────
    run_args = argparse.Namespace(
        on_error=on_error,
        timeout=DEFAULT_TIMEOUT,
        dry_run=False,
    )
    _run(api, command, target, clusters, standalone,
         final_skipped + already_at, run_args)


# ── CLI ───────────────────────────────────────────────────────────────────

def _add_credential_flags(parser):
    """Add global credential flags to a parser."""
    cred = parser.add_argument_group("credentials")
    cred.add_argument("--client-id", dest="client_id",
                      help="Zscaler OAuth2 client ID")
    cred.add_argument("--client-secret", dest="client_secret",
                      help="Zscaler OAuth2 client secret")
    cred.add_argument("--vanity-domain", dest="vanity_domain",
                      help="Zscaler vanity domain (e.g. secsilab)")
    cred.add_argument("--airgap-site", dest="airgap_site",
                      help="AirGap site name (e.g. thibaultparis)")
    cred.add_argument("--env-file", dest="env_file",
                      help="Path to .env file (default: ../.env)")


def _add_selection_flags(parser):
    """Add gateway selection flags to a subcommand parser."""
    sel = parser.add_argument_group("selection")
    sel.add_argument("--all", action="store_true", dest="select_all",
                     help="Select all gateways")
    sel.add_argument("--site", help="Select gateways by site name")
    sel.add_argument("--cluster", help="Select gateways by cluster name")
    sel.add_argument("--gateway", help="Select a specific gateway by name")
    sel.add_argument("--below-version", dest="below_version",
                     help="Select gateways below this version")
    sel.add_argument("--from-file", dest="from_file",
                     help="Read gateway names from a file (one per line)")


def _add_execution_flags(parser):
    """Add execution flags to a subcommand parser."""
    exe = parser.add_argument_group("execution")
    exe.add_argument("--dry-run", action="store_true", dest="dry_run",
                     help="Show what would be done without doing it")
    exe.add_argument("--on-error", dest="on_error", default="continue",
                     choices=["continue", "stop"],
                     help="Behavior on error (default: continue)")
    exe.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                     help=f"Per-gateway timeout in minutes (default: {DEFAULT_TIMEOUT})")


def build_parser():
    """Build the argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="ztb_bulk_upgrade",
        description="Bulk upgrade tool for Zscaler ZTB gateways (AirGap API)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  %(prog)s                                    # interactive wizard\n"
            "  %(prog)s inventory                          # list gateways\n"
            "  %(prog)s download --version 25.1.2 --all    # download firmware\n"
            "  %(prog)s upgrade --version 25.1.2 --site x  # upgrade site\n"
            "  %(prog)s resume                             # resume interrupted op\n"
        ),
    )
    _add_credential_flags(parser)

    subs = parser.add_subparsers(dest="command")

    # inventory
    subs.add_parser("inventory", help="List gateways with current versions")

    # download
    p_dl = subs.add_parser("download", help="Download firmware to gateways")
    p_dl.add_argument("--version", required=True,
                      help="Target firmware version")
    _add_selection_flags(p_dl)
    _add_execution_flags(p_dl)

    # upgrade
    p_up = subs.add_parser("upgrade", help="Upgrade gateways")
    p_up.add_argument("--version", required=True,
                      help="Target firmware version")
    _add_selection_flags(p_up)
    _add_execution_flags(p_up)

    # resume
    p_resume = subs.add_parser("resume", help="Resume an interrupted operation")
    _add_execution_flags(p_resume)

    return parser


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        run_wizard()
        return

    config = get_config(args)
    api = ApiClient(config)

    dispatch = {
        "inventory": cmd_inventory,
        "download":  cmd_download,
        "upgrade":   cmd_upgrade,
        "resume":    cmd_resume,
    }
    dispatch[args.command](api, args)


if __name__ == "__main__":
    main()
