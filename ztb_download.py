#!/usr/bin/env python3
"""
Compact firmware download tool for Zscaler ZTB gateways via AirGap API.

Pre-stages firmware across the fleet in one command. No state file,
no resume, no wizard, no reports -- just download.

Usage:
    python3 ztb_download.py --version latest --all
    python3 ztb_download.py --version 24.3.1 --site "Paris-*" --dry-run
    python3 ztb_download.py --version latest --below-version 24.3.0
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from fnmatch import fnmatch

TOKEN_AUDIENCE = "https://api.zscaler.com"
TOKEN_REFRESH_MARGIN = 60
POLL_INTERVAL = 20
DOWNLOAD_TIMEOUT = 900  # 15 minutes


# ── Env & config ─────────────────────────────────────────────────────────

def load_env(path=None):
    if path is None:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip())


def get_config(args):
    load_env(getattr(args, "env_file", None))
    keys = {
        "client_id": "ZSCALER_CLIENT_ID",
        "client_secret": "ZSCALER_CLIENT_SECRET",
        "vanity_domain": "ZSCALER_VANITY_DOMAIN",
        "airgap_site": "ZSCALER_AIRGAP_SITE",
    }
    config, missing = {}, []
    for key, env_var in keys.items():
        value = getattr(args, key, None) or os.environ.get(env_var)
        if not value:
            missing.append(f"  --{key.replace('_', '-')} / {env_var}")
        else:
            config[key] = value
    if missing:
        print("ERROR: Missing credentials:", file=sys.stderr)
        for m in missing:
            print(m, file=sys.stderr)
        sys.exit(1)
    config["token_url"] = f"https://{config['vanity_domain']}.zslogin.net/oauth2/v1/token"
    config["api_base"] = f"https://{config['airgap_site']}-api.goairgap.com"
    return config


# ── API client ───────────────────────────────────────────────────────────

class ApiClient:
    def __init__(self, config):
        self._cid = config["client_id"]
        self._secret = config["client_secret"]
        self._token_url = config["token_url"]
        self._base = config["api_base"]
        self._token = None
        self._expiry = 0

    def _ensure_token(self):
        if self._token and time.time() < (self._expiry - TOKEN_REFRESH_MARGIN):
            return
        data = urllib.parse.urlencode({
            "client_id": self._cid, "client_secret": self._secret,
            "grant_type": "client_credentials", "audience": TOKEN_AUDIENCE,
        }).encode()
        req = urllib.request.Request(
            self._token_url, data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read().decode())
        self._token = result["access_token"]
        self._expiry = time.time() + result.get("expires_in", 3600)

    def request(self, method, path, data=None):
        self._ensure_token()
        url = f"{self._base}{path}"
        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"HTTP {e.code} on {url}: {e.read().decode()[:200]}")

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, data=None):
        return self.request("POST", path, data)


# ── Data helpers ─────────────────────────────────────────────────────────

def unwrap(resp):
    if isinstance(resp, list):
        return resp
    if isinstance(resp, dict):
        inner = resp.get("result", resp)
        if isinstance(inner, dict):
            return inner.get("rows", [])
        if isinstance(inner, list):
            return inner
    return []


def fetch_gateways(api):
    rows = unwrap(api.get("/api/v2/Gateway/"))
    site_map = {}
    try:
        for site in unwrap(api.get("/api/v2/Site/")):
            name = site.get("name", "unknown")
            for cl in site.get("clusters", []):
                cid = cl.get("cluster_id")
                if cid is not None:
                    site_map[cid] = name
    except Exception:
        pass

    gateways = []
    for gw in rows:
        cid = gw.get("cluster_id")
        gateways.append({
            "id": gw.get("gateway_id", gw.get("id", "")),
            "name": gw.get("gateway_name", gw.get("name", "unknown")),
            "site_name": site_map.get(cid, "unknown"),
            "cluster_id": cid,
            "running_version": gw.get("running_version", ""),
        })
    gateways.sort(key=lambda g: (g["site_name"], g["name"]))
    return gateways


def resolve_version(api, version_arg):
    releases = unwrap(api.get("/api/v2/Gateway/releases"))
    releases.sort(key=lambda r: r.get("release_date", ""), reverse=True)
    if not releases:
        print("ERROR: No releases available.", file=sys.stderr)
        sys.exit(1)
    if version_arg == "latest":
        return releases[0]["version_number"]
    available = [r["version_number"] for r in releases]
    if version_arg in available:
        return version_arg
    print(f"ERROR: Version '{version_arg}' not found. Available: {', '.join(available)}", file=sys.stderr)
    sys.exit(1)


def version_lt(a, b):
    def parse(v):
        return tuple(int(x) for x in re.findall(r'\d+', v))
    pa, pb = parse(a), parse(b)
    return pa < pb if pa != pb else a < b


def select_gateways(gateways, args):
    if not any([args.select_all, args.site, args.cluster, args.gateway, args.below_version]):
        print("ERROR: No selection. Use --all, --site, --cluster, --gateway, or --below-version", file=sys.stderr)
        sys.exit(1)
    selected = list(gateways)
    if not args.select_all:
        if args.site:
            selected = [g for g in selected if fnmatch(g["site_name"], args.site)]
        if args.cluster:
            selected = [g for g in selected if str(g["cluster_id"]) == args.cluster]
        if args.gateway:
            names = {n.strip() for n in args.gateway.split(",")}
            selected = [g for g in selected if g["name"] in names]
        if args.below_version:
            selected = [g for g in selected if g["running_version"] and version_lt(g["running_version"], args.below_version)]
    return selected


# ── Download logic ───────────────────────────────────────────────────────

def cleanup_old_images(api, gw_id, target_version):
    try:
        gw_data = api.get(f"/api/v2/Gateway/id/{gw_id}")
        if isinstance(gw_data, dict) and "result" in gw_data:
            gw_data = gw_data["result"]
            if isinstance(gw_data, list) and gw_data:
                gw_data = gw_data[0]
        running = gw_data.get("running_version", "")
        for img in gw_data.get("sw_image_status", {}).get("images", []):
            v = img.get("version", "")
            if v and v != running and v != target_version:
                try:
                    api.post(f"/api/v2/Gateway/sw_image_update/id/{gw_id}",
                             {"action": "delete", "version": v})
                except Exception:
                    pass
    except Exception:
        pass


def is_already_downloaded(api, gw_id, target_version):
    try:
        gw_data = api.get(f"/api/v2/Gateway/id/{gw_id}")
        if isinstance(gw_data, dict) and "result" in gw_data:
            gw_data = gw_data["result"]
            if isinstance(gw_data, list) and gw_data:
                gw_data = gw_data[0]
        for img in gw_data.get("sw_image_status", {}).get("images", []):
            if img.get("version") == target_version and img.get("status", "").lower() in ("downloaded", "completed"):
                return True
        for ver in gw_data.get("download_status", {}).get("versions", []):
            if ver.get("version") == target_version and ver.get("status", "").lower() in ("downloaded", "completed"):
                return True
    except Exception:
        pass
    return False


def download_and_poll(api, gw_id, target_version):
    api.post(f"/api/v2/Gateway/sw_image_update/id/{gw_id}",
             {"action": "download", "version": target_version})
    deadline = time.time() + DOWNLOAD_TIMEOUT
    while time.time() < deadline:
        if is_already_downloaded(api, gw_id, target_version):
            return True
        time.sleep(POLL_INTERVAL)
    return False


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Compact ZTB firmware download tool")
    p.add_argument("--version", required=True, help="Target version or 'latest'")
    p.add_argument("--all", dest="select_all", action="store_true", help="All gateways")
    p.add_argument("--site", help="Site name glob pattern")
    p.add_argument("--cluster", help="Cluster ID")
    p.add_argument("--gateway", help="Gateway names (comma-separated)")
    p.add_argument("--below-version", help="Only gateways below this version")
    p.add_argument("--dry-run", action="store_true", help="Preview without executing")
    p.add_argument("--client-id", dest="client_id")
    p.add_argument("--client-secret", dest="client_secret")
    p.add_argument("--vanity-domain", dest="vanity_domain")
    p.add_argument("--airgap-site", dest="airgap_site")
    p.add_argument("--env-file", dest="env_file")
    args = p.parse_args()

    config = get_config(args)
    api = ApiClient(config)

    target = resolve_version(api, args.version)
    print(f"Target version: {target}")

    gateways = fetch_gateways(api)
    selected = select_gateways(gateways, args)

    # Split already-at-target
    to_process = [g for g in selected if g["running_version"] != target]
    at_target = [g for g in selected if g["running_version"] == target]

    if at_target:
        print(f"Skipping {len(at_target)} gateway(s) already at {target}")

    if not to_process:
        print("Nothing to download.")
        return

    print(f"Downloading firmware to {len(to_process)} gateway(s)...")
    if args.dry_run:
        for i, gw in enumerate(to_process, 1):
            print(f"  [{i}/{len(to_process)}] {gw['name']} ({gw['site_name']}, "
                  f"current: {gw['running_version']}) -- DRY RUN")
        print(f"\nDry run complete. {len(to_process)} gateway(s) would be processed.")
        return

    downloaded, skipped, failed = 0, 0, 0
    for i, gw in enumerate(to_process, 1):
        label = f"[{i}/{len(to_process)}] {gw['name']}"
        t0 = time.time()

        # Check if already downloaded
        if is_already_downloaded(api, gw["id"], target):
            print(f"  {label}... skipped (already downloaded)")
            skipped += 1
            continue

        print(f"  {label}...", end=" ", flush=True)
        try:
            cleanup_old_images(api, gw["id"], target)
            ok = download_and_poll(api, gw["id"], target)
            elapsed = int(time.time() - t0)
            if ok:
                print(f"done ({elapsed}s)")
                downloaded += 1
            else:
                print(f"TIMEOUT ({elapsed}s)")
                failed += 1
        except Exception as e:
            elapsed = int(time.time() - t0)
            print(f"FAILED ({elapsed}s) -- {e}")
            failed += 1

    print(f"\nSummary: {downloaded} downloaded, {skipped} skipped, {failed} failed")


if __name__ == "__main__":
    main()
