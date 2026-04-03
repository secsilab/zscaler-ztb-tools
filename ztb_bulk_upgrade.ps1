#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Bulk upgrade tool for Zscaler ZTB (Zero Trust Branch) gateways via AirGap API.

.DESCRIPTION
    Supports inventory listing, firmware download, upgrade orchestration, and
    resume of interrupted operations. Uses OAuth2 client_credentials auth.

.PARAMETER Command
    The operation to perform: inventory, download, upgrade, or resume.
    If omitted and no other parameters are specified, launches the interactive wizard.

.PARAMETER Version
    Target firmware version (e.g. 25.1.2 or 'latest'). Required for download/upgrade.

.PARAMETER All
    Select all gateways.

.PARAMETER Site
    Select gateways by site name (supports glob/wildcard patterns).

.PARAMETER Cluster
    Select gateways by cluster ID.

.PARAMETER Gateway
    Select specific gateway(s) by name (comma-separated).

.PARAMETER BelowVersion
    Select gateways running below this version.

.PARAMETER FromFile
    Read gateway names/IDs from a file (one per line).

.PARAMETER DryRun
    Show what would be done without making changes.

.PARAMETER OnError
    Behavior on error: Continue or Stop. Default: Continue.

.PARAMETER Timeout
    Per-gateway timeout in minutes. Default: 15.

.PARAMETER ClientId
    Zscaler OAuth2 client ID (overrides .env / env var).

.PARAMETER ClientSecret
    Zscaler OAuth2 client secret (overrides .env / env var).

.PARAMETER VanityDomain
    Zscaler vanity domain, e.g. acme (overrides .env / env var).

.PARAMETER AirgapSite
    AirGap site name, e.g. my-site (overrides .env / env var).

.PARAMETER EnvFile
    Path to .env file. Default: ../.env relative to script directory.

.EXAMPLE
    # Interactive wizard (default)
    ./ztb_bulk_upgrade.ps1

.EXAMPLE
    # List all gateways with current versions
    ./ztb_bulk_upgrade.ps1 inventory

.EXAMPLE
    # Download firmware to all gateways
    ./ztb_bulk_upgrade.ps1 download -Version 25.1.2 -All

.EXAMPLE
    # Upgrade a specific site (dry-run first)
    ./ztb_bulk_upgrade.ps1 upgrade -Version 25.1.2 -Site branch-01 -DryRun
    ./ztb_bulk_upgrade.ps1 upgrade -Version 25.1.2 -Site branch-01

.EXAMPLE
    # Upgrade gateways below a certain version
    ./ztb_bulk_upgrade.ps1 upgrade -Version 25.1.2 -BelowVersion 25.1.0

.EXAMPLE
    # Resume an interrupted upgrade
    ./ztb_bulk_upgrade.ps1 resume
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('inventory', 'download', 'upgrade', 'resume')]
    [string]$Command,

    [string]$Version,
    [switch]$All,
    [string]$Site,
    [string]$Cluster,
    [string]$Gateway,
    [string]$BelowVersion,
    [string]$FromFile,
    [switch]$DryRun,

    [ValidateSet('Continue', 'Stop')]
    [string]$OnError = 'Continue',

    [int]$Timeout = 15,

    [string]$ClientId,
    [string]$ClientSecret,
    [string]$VanityDomain,
    [string]$AirgapSite,
    [string]$EnvFile
)

# ── Constants ─────────────────────────────────────────────────────────────
$script:STATE_FILE = ".ztb_upgrade_state.json"
$script:POLL_INTERVAL = 30
$script:DEFAULT_TIMEOUT = 15
$script:TOKEN_AUDIENCE = "https://api.zscaler.com"
$script:TOKEN_REFRESH_MARGIN = 60  # seconds before expiry to trigger refresh

# ── Env loading ───────────────────────────────────────────────────────────

function Import-EnvFile {
    <#
    .SYNOPSIS
        Load key=value pairs from a .env file into environment variables (setdefault behavior).
    #>
    param([string]$Path)

    if (-not $Path) {
        $Path = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -ErrorAction SilentlyContinue) ".env"
        if (-not $Path -or -not (Test-Path $Path)) {
            $Path = Join-Path (Split-Path $PSScriptRoot -Parent) ".env"
        }
    }

    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) {
        return
    }

    foreach ($line in Get-Content $Path) {
        $line = $line.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
            $eqIndex = $line.IndexOf('=')
            $key = $line.Substring(0, $eqIndex).Trim()
            $value = $line.Substring($eqIndex + 1).Trim()
            # setdefault: don't override existing env vars
            if (-not [System.Environment]::GetEnvironmentVariable($key)) {
                [System.Environment]::SetEnvironmentVariable($key, $value)
            }
        }
    }
}

# ── Config resolution ─────────────────────────────────────────────────────

$script:CREDENTIAL_KEYS = [ordered]@{
    'client_id'     = 'ZSCALER_CLIENT_ID'
    'client_secret' = 'ZSCALER_CLIENT_SECRET'
    'vanity_domain' = 'ZSCALER_VANITY_DOMAIN'
    'airgap_site'   = 'ZSCALER_AIRGAP_SITE'
}

function Get-ZtbConfig {
    <#
    .SYNOPSIS
        Resolve credentials from CLI flags > .env > env vars.
    #>
    param(
        [string]$CliClientId,
        [string]$CliClientSecret,
        [string]$CliVanityDomain,
        [string]$CliAirgapSite,
        [string]$CliEnvFile
    )

    Import-EnvFile -Path $CliEnvFile

    $cliOverrides = @{
        'client_id'     = $CliClientId
        'client_secret' = $CliClientSecret
        'vanity_domain' = $CliVanityDomain
        'airgap_site'   = $CliAirgapSite
    }

    $config = @{}
    $missing = @()

    foreach ($entry in $script:CREDENTIAL_KEYS.GetEnumerator()) {
        $key = $entry.Key
        $envVar = $entry.Value

        # CLI flag takes precedence
        $value = $cliOverrides[$key]
        if (-not $value) {
            $value = [System.Environment]::GetEnvironmentVariable($envVar)
        }

        if (-not $value) {
            $flagName = '--' + ($key -replace '_', '-')
            $missing += "  $flagName / $envVar"
        } else {
            $config[$key] = $value
        }
    }

    if ($missing.Count -gt 0) {
        Write-Host "ERROR: Missing required credentials:" -ForegroundColor Red
        foreach ($m in $missing) {
            Write-Host $m -ForegroundColor Red
        }
        Write-Host "`nProvide via CLI flags, .env file, or environment variables." -ForegroundColor Red
        exit 1
    }

    # Derived URLs
    $config['token_url'] = "https://$($config['vanity_domain']).zslogin.net/oauth2/v1/token"
    $config['api_base'] = "https://$($config['airgap_site'])-api.goairgap.com"

    return $config
}

# ── API client class ──────────────────────────────────────────────────────

class ApiClient {
    [string]$ClientId
    [string]$ClientSecret
    [string]$TokenUrl
    [string]$ApiBase
    [string]$Token
    [double]$TokenExpiry

    ApiClient([hashtable]$config) {
        $this.ClientId = $config['client_id']
        $this.ClientSecret = $config['client_secret']
        $this.TokenUrl = $config['token_url']
        $this.ApiBase = $config['api_base']
        $this.Token = $null
        $this.TokenExpiry = 0
    }

    # ── Auth ──────────────────────────────────────────────────────────

    [void] EnsureToken() {
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($this.Token -and $now -lt ($this.TokenExpiry - $script:TOKEN_REFRESH_MARGIN)) {
            return
        }

        $body = @{
            client_id     = $this.ClientId
            client_secret = $this.ClientSecret
            grant_type    = 'client_credentials'
            audience      = $script:TOKEN_AUDIENCE
        }

        try {
            $response = Invoke-RestMethod -Uri $this.TokenUrl -Method Post `
                -ContentType 'application/x-www-form-urlencoded' `
                -Body $body -ErrorAction Stop
        } catch {
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
            }
            throw "HTTP $statusCode on $($this.TokenUrl): $($_.Exception.Message)"
        }

        $this.Token = $response.access_token
        $expiresIn = if ($response.expires_in) { $response.expires_in } else { 3600 }
        $this.TokenExpiry = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $expiresIn
    }

    # ── HTTP helpers ─────────────────────────────────────────────────

    [object] Request([string]$method, [string]$path, [object]$data) {
        $this.EnsureToken()
        $url = "$($this.ApiBase)$path"

        $headers = @{
            'Authorization' = "Bearer $($this.Token)"
            'Accept'        = 'application/json'
        }

        $params = @{
            Uri         = $url
            Method      = $method
            Headers     = $headers
            ContentType = 'application/json'
            ErrorAction = 'Stop'
        }

        if ($null -ne $data) {
            $params['Body'] = ($data | ConvertTo-Json -Depth 10 -Compress)
        }

        try {
            $response = Invoke-RestMethod @params
            return $response
        } catch {
            $statusCode = 0
            $errorBody = $_.Exception.Message
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                try {
                    $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
                    $errorBody = $reader.ReadToEnd()
                    $reader.Close()
                } catch {
                    # Keep the original error message
                }
            }
            throw "HTTP $statusCode on ${url}: $($errorBody.Substring(0, [Math]::Min(300, $errorBody.Length)))"
        }
    }

    [object] Get([string]$path) {
        return $this.Request('GET', $path, $null)
    }

    [object] Post([string]$path, [object]$data) {
        return $this.Request('POST', $path, $data)
    }

    [object] Post([string]$path) {
        return $this.Request('POST', $path, $null)
    }
}

# ── Inventory ─────────────────────────────────────────────────────────────

function Build-ClusterSiteMap {
    <#
    .SYNOPSIS
        Build a cluster_id -> site_name mapping from the Sites API.
    #>
    param([ApiClient]$Api)

    try {
        $resp = $Api.Get("/api/v2/Site/")
    } catch {
        return @{}
    }

    $rows = $resp
    if ($resp -is [hashtable] -or $resp.PSObject.Properties.Name -contains 'result') {
        $inner = $resp.result
        if ($null -eq $inner) { $inner = $resp }
        if ($inner -is [hashtable] -or ($inner.PSObject -and $inner.PSObject.Properties.Name -contains 'rows')) {
            $rows = $inner.rows
        } elseif ($inner -is [array]) {
            $rows = $inner
        } else {
            $rows = @()
        }
    }
    if ($null -eq $rows) { $rows = @() }

    $siteMap = @{}
    foreach ($site in $rows) {
        $name = if ($site.name) { $site.name } elseif ($site.display_name) { $site.display_name } else { 'unknown' }
        if ($site.clusters) {
            foreach ($cluster in $site.clusters) {
                $cid = $cluster.cluster_id
                if ($null -ne $cid) {
                    $siteMap[$cid] = $name
                }
            }
        }
    }
    return $siteMap
}

function Get-UnwrappedRows {
    <#
    .SYNOPSIS
        Unwrap API response that may be {result: {rows: [...]}} or {result: [...]} or [...].
    #>
    param([object]$Response)

    if ($null -eq $Response) { return @() }

    if ($Response -is [array]) {
        return $Response
    }

    $inner = $Response
    if ($Response.PSObject -and $Response.PSObject.Properties.Name -contains 'result') {
        $inner = $Response.result
    }

    if ($null -eq $inner) { return @() }

    if ($inner -is [array]) {
        return $inner
    }

    if ($inner.PSObject -and $inner.PSObject.Properties.Name -contains 'rows') {
        $rows = $inner.rows
        if ($null -eq $rows) { return @() }
        return $rows
    }

    return @()
}

function Get-Gateways {
    <#
    .SYNOPSIS
        Fetch all gateways from the AirGap API, normalized and sorted.
    #>
    param([ApiClient]$Api)

    $resp = $Api.Get("/api/v2/Gateway/")
    $rawGateways = Get-UnwrappedRows -Response $resp

    if ($rawGateways.Count -eq 0) {
        return @()
    }

    # Debug: check for expected fields
    $expectedFields = @('gateway_id', 'gateway_name', 'cluster_id', 'running_version')
    $firstKeys = @($rawGateways[0].PSObject.Properties.Name)
    $missingFields = $expectedFields | Where-Object { $_ -notin $firstKeys }
    if ($missingFields.Count -gt 0) {
        Write-Host "DEBUG: unexpected gateway fields: $($firstKeys -join ', ')" -ForegroundColor Yellow
        Write-Host ($rawGateways[0] | ConvertTo-Json -Depth 5) -ForegroundColor Yellow
    }

    # Build cluster_id -> site_name map
    $siteMap = Build-ClusterSiteMap -Api $Api

    $gateways = @()
    foreach ($gw in $rawGateways) {
        $clusterId = $gw.cluster_id
        $vrrp = if ($gw.vrrp_state) { $gw.vrrp_state } else { '' }
        $desiredState = if ($gw.desired_state) { $gw.desired_state } else { '' }
        $operationalState = if ($gw.operational_state) { $gw.operational_state } else { '' }

        # Determine HA role
        if ($desiredState -eq 'standalone' -or $operationalState -eq 'standalone') {
            $haRole = 'standalone'
        } elseif ($vrrp -eq 'master') {
            $haRole = 'active'
        } elseif ($vrrp -eq 'backup') {
            $haRole = 'standby'
        } else {
            $haRole = if ($vrrp) { $vrrp } else { 'unknown' }
        }

        # Determine online status from health_color
        $health = if ($gw.health_color) { $gw.health_color } else { '' }
        if ($health -eq 'green') {
            $status = 'online'
        } elseif ($health -eq 'red') {
            $status = 'offline'
        } else {
            $status = if ($health) { $health } else { 'unknown' }
        }

        $gwId = if ($gw.gateway_id) { $gw.gateway_id } elseif ($gw.id) { $gw.id } else { '' }
        $gwName = if ($gw.gateway_name) { $gw.gateway_name } elseif ($gw.name) { $gw.name } else { 'unknown' }
        $siteName = if ($siteMap.ContainsKey($clusterId)) { $siteMap[$clusterId] } else { 'unknown' }

        $gateways += [PSCustomObject]@{
            id               = $gwId
            name             = $gwName
            site_id          = ''
            site_name        = $siteName
            cluster_id       = $clusterId
            running_version  = if ($gw.running_version) { $gw.running_version } else { '' }
            desired_version  = if ($gw.desired_version) { $gw.desired_version } else { '' }
            status           = $status
            ha_role          = $haRole
            download_status  = if ($gw.download_status) { $gw.download_status } else { @{} }
            sw_image_status  = if ($gw.sw_image_status) { $gw.sw_image_status } else { @{} }
        }
    }

    $gateways = $gateways | Sort-Object -Property site_name, name
    return $gateways
}

function Get-Releases {
    <#
    .SYNOPSIS
        Fetch available firmware releases from the AirGap API, newest first.
    #>
    param([ApiClient]$Api)

    $resp = $Api.Get("/api/v2/Gateway/releases")
    $releases = Get-UnwrappedRows -Response $resp

    if ($releases.Count -eq 0) { return @() }

    # Sort newest first by release_date
    $releases = $releases | Sort-Object -Property { $_.release_date } -Descending
    return $releases
}

function Resolve-FirmwareVersion {
    <#
    .SYNOPSIS
        Resolve a version argument to a concrete version string.
    #>
    param(
        [ApiClient]$Api,
        [string]$VersionArg
    )

    $releases = Get-Releases -Api $Api
    if ($releases.Count -eq 0) {
        Write-Host "ERROR: No releases available from the API." -ForegroundColor Red
        exit 1
    }

    if ($VersionArg -eq 'latest') {
        return $releases[0].version_number
    }

    $available = @($releases | ForEach-Object { $_.version_number })
    if ($VersionArg -in $available) {
        return $VersionArg
    }

    Write-Host "ERROR: Version '$VersionArg' not found in available releases." -ForegroundColor Red
    Write-Host "Available: $($available -join ', ')" -ForegroundColor Red
    exit 1
}

# ── Gateway selection ─────────────────────────────────────────────────────

function Compare-VersionLt {
    <#
    .SYNOPSIS
        Compare version strings as tuples of ints. Returns $true if $A < $B.
    #>
    param(
        [string]$A,
        [string]$B
    )

    $parseVersion = {
        param([string]$v)
        $nums = [regex]::Matches($v, '\d+') | ForEach-Object { [int]$_.Value }
        return @($nums)
    }

    $pa = & $parseVersion $A
    $pb = & $parseVersion $B

    # Compare element by element
    $maxLen = [Math]::Max($pa.Count, $pb.Count)
    for ($i = 0; $i -lt $maxLen; $i++) {
        $va = if ($i -lt $pa.Count) { $pa[$i] } else { 0 }
        $vb = if ($i -lt $pb.Count) { $pb[$i] } else { 0 }
        if ($va -lt $vb) { return $true }
        if ($va -gt $vb) { return $false }
    }

    # Numeric parts are equal, fall back to string comparison
    return $A -lt $B
}

function Select-Gateways {
    <#
    .SYNOPSIS
        Filter gateways based on selection parameters.
    #>
    param(
        [array]$Gateways,
        [bool]$SelectAll,
        [string]$SiteFilter,
        [string]$ClusterFilter,
        [string]$GatewayFilter,
        [string]$BelowVersionFilter,
        [string]$FromFileFilter
    )

    $hasFilter = $SelectAll -or $SiteFilter -or $ClusterFilter -or $GatewayFilter -or $BelowVersionFilter -or $FromFileFilter

    if (-not $hasFilter) {
        Write-Host "ERROR: No gateway selection specified. Use one of: -All, -Site, -Cluster, -Gateway, -BelowVersion, -FromFile" -ForegroundColor Red
        exit 1
    }

    $selected = @($Gateways)

    if (-not $SelectAll) {
        # -Site: wildcard match on site_name
        if ($SiteFilter) {
            $selected = @($selected | Where-Object { $_.site_name -like $SiteFilter })
        }

        # -Cluster: match on cluster_id (as string)
        if ($ClusterFilter) {
            $selected = @($selected | Where-Object { [string]$_.cluster_id -eq $ClusterFilter })
        }

        # -Gateway: comma-separated list of gateway names
        if ($GatewayFilter) {
            $names = @($GatewayFilter -split ',' | ForEach-Object { $_.Trim() })
            $selected = @($selected | Where-Object { $_.name -in $names })
        }

        # -FromFile: one gateway ID/name per line
        if ($FromFileFilter) {
            if (-not (Test-Path $FromFileFilter)) {
                Write-Host "ERROR: File not found: $FromFileFilter" -ForegroundColor Red
                exit 1
            }
            $fileIds = @(Get-Content $FromFileFilter | ForEach-Object { $_.Trim() } |
                Where-Object { $_ -and -not $_.StartsWith('#') })
            $selected = @($selected | Where-Object { $_.name -in $fileIds -or $_.id -in $fileIds })
        }

        # -BelowVersion: only gateways running below specified version
        if ($BelowVersionFilter) {
            $selected = @($selected | Where-Object {
                $_.running_version -and (Compare-VersionLt -A $_.running_version -B $BelowVersionFilter)
            })
        }
    }

    return $selected
}

function Split-ByCluster {
    <#
    .SYNOPSIS
        Group gateways by cluster_id, returning clusters dict and standalone list.
        Within each cluster, standby gateways come first.
    #>
    param([array]$Gateways)

    $clusters = @{}
    $standalone = @()

    foreach ($gw in $Gateways) {
        if ($gw.ha_role -eq 'standalone') {
            $standalone += $gw
        } else {
            $cid = $gw.cluster_id
            if (-not $clusters.ContainsKey($cid)) {
                $clusters[$cid] = @()
            }
            $clusters[$cid] += $gw
        }
    }

    # Within each cluster, sort standby first
    foreach ($cid in @($clusters.Keys)) {
        $clusters[$cid] = @($clusters[$cid] | Sort-Object -Property {
            if ($_.ha_role -eq 'standby') { 0 } else { 1 }
        }, name)
    }

    return @{
        Clusters   = $clusters
        Standalone = $standalone
    }
}

function Split-AtTarget {
    <#
    .SYNOPSIS
        Separate gateways already at the target version from those needing processing.
    #>
    param(
        [array]$Gateways,
        [string]$TargetVersion
    )

    $toProcess = @()
    $skipped = @()

    foreach ($gw in $Gateways) {
        if ($gw.running_version -eq $TargetVersion) {
            $skipped += $gw
        } else {
            $toProcess += $gw
        }
    }

    return @{
        ToProcess = $toProcess
        Skipped   = $skipped
    }
}

# ── Pre-checks, plan display, dry-run ─────────────────────────────────────

function Invoke-PreChecks {
    <#
    .SYNOPSIS
        Run pre-flight checks: API connectivity and target version validation.
    #>
    param(
        [ApiClient]$Api,
        [string]$TargetVersion
    )

    Write-Host "  [1/2] Checking API connectivity..." -NoNewline
    try {
        $releases = Get-Releases -Api $Api
    } catch {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host "ERROR: Cannot reach AirGap API: $_" -ForegroundColor Red
        exit 1
    }
    Write-Host " OK" -ForegroundColor Green

    Write-Host "  [2/2] Verifying target version $TargetVersion..." -NoNewline
    $available = @($releases | ForEach-Object { $_.version_number })
    if ($TargetVersion -notin $available) {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host "ERROR: Version '$TargetVersion' not available." -ForegroundColor Red
        Write-Host "Available: $($available -join ', ')" -ForegroundColor Red
        exit 1
    }
    Write-Host " OK" -ForegroundColor Green
}

function Show-Plan {
    <#
    .SYNOPSIS
        Display the execution plan for download/upgrade.
    #>
    param(
        [string]$CommandName,
        [string]$TargetVersion,
        [hashtable]$Clusters,
        [array]$Standalone,
        [array]$Skipped,
        [string]$OnErrorMode,
        [bool]$IsDryRun
    )

    $total = ($Clusters.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum + $Standalone.Count

    $mode = if ($IsDryRun) { "DRY RUN" } else { "LIVE" }
    Write-Host ""
    Write-Host ('=' * 70)
    Write-Host "  $($CommandName.ToUpper()) PLAN [$mode]"
    Write-Host ('=' * 70)
    Write-Host "  Target version : $TargetVersion"
    Write-Host "  Gateways       : $total to process, $($Skipped.Count) skipped (already at target)"
    Write-Host "  On error       : $OnErrorMode"

    if ($Skipped.Count -gt 0) {
        Write-Host ""
        Write-Host "  Skipped (already at $TargetVersion):"
        foreach ($gw in $Skipped) {
            Write-Host "    - $($gw.name) ($($gw.site_name))"
        }
    }

    $step = 1

    if ($Clusters.Count -gt 0) {
        Write-Host ""
        Write-Host "  Clustered gateways (standby first, then active):"
        foreach ($cid in ($Clusters.Keys | Sort-Object)) {
            $gws = $Clusters[$cid]
            $siteName = if ($gws.Count -gt 0) { $gws[0].site_name } else { 'unknown' }
            Write-Host "    Cluster $cid ($siteName):"
            foreach ($gw in $gws) {
                Write-Host "      Step ${step}: $($gw.name) [$($gw.ha_role)] ($($gw.running_version) -> $TargetVersion)"
                $step++
            }
        }
    }

    if ($Standalone.Count -gt 0) {
        Write-Host ""
        Write-Host "  Standalone gateways:"
        foreach ($gw in $Standalone) {
            Write-Host "      Step ${step}: $($gw.name) ($($gw.site_name)) ($($gw.running_version) -> $TargetVersion)"
            $step++
        }
    }

    Write-Host ""
}

function Invoke-PrepareRun {
    <#
    .SYNOPSIS
        Orchestrate pre-checks, selection, plan display, and confirmation.
        On dry-run, prints plan and exits. Otherwise prompts for confirmation.
    #>
    param(
        [ApiClient]$Api,
        [string]$CommandName,
        [string]$VersionArg,
        [bool]$SelectAll,
        [string]$SiteFilter,
        [string]$ClusterFilter,
        [string]$GatewayFilter,
        [string]$BelowVersionFilter,
        [string]$FromFileFilter,
        [bool]$IsDryRun,
        [string]$OnErrorMode,
        [int]$TimeoutMinutes
    )

    Write-Host "`n--- $($CommandName.ToUpper()) preparation ---`n"

    # Resolve version
    $target = Resolve-FirmwareVersion -Api $Api -VersionArg $VersionArg
    Write-Host "  Target version: $target"

    # Pre-checks
    Write-Host "`n  Pre-checks:"
    Invoke-PreChecks -Api $Api -TargetVersion $target

    # Fetch and filter
    $gateways = Get-Gateways -Api $Api
    Write-Host "`n  Fetching gateways... $($gateways.Count) found"

    $selected = Select-Gateways -Gateways $gateways -SelectAll $SelectAll `
        -SiteFilter $SiteFilter -ClusterFilter $ClusterFilter `
        -GatewayFilter $GatewayFilter -BelowVersionFilter $BelowVersionFilter `
        -FromFileFilter $FromFileFilter

    if ($selected.Count -eq 0) {
        Write-Host "ERROR: No gateways match the selection criteria." -ForegroundColor Red
        exit 1
    }
    Write-Host "  Selected: $($selected.Count) gateway(s)"

    # Skip already-at-target
    $splitResult = Split-AtTarget -Gateways $selected -TargetVersion $target
    $toProcess = $splitResult.ToProcess
    $skipped = $splitResult.Skipped

    if ($toProcess.Count -eq 0) {
        Write-Host "`n  All $($skipped.Count) selected gateway(s) are already at version $target. Nothing to do."
        exit 0
    }

    # Partition
    $partResult = Split-ByCluster -Gateways $toProcess
    $clusters = $partResult.Clusters
    $standalone = $partResult.Standalone

    # Display plan
    Show-Plan -CommandName $CommandName -TargetVersion $target `
        -Clusters $clusters -Standalone $standalone -Skipped $skipped `
        -OnErrorMode $OnErrorMode -IsDryRun $IsDryRun

    if ($IsDryRun) {
        Write-Host "  Dry-run mode -- no changes made."
        exit 0
    }

    # Confirm
    $answer = Read-Host "  Proceed? [y/N]"
    if ($answer -notin @('y', 'yes')) {
        Write-Host "  Aborted."
        exit 1
    }

    return @{
        Target     = $target
        Clusters   = $clusters
        Standalone = $standalone
        Skipped    = $skipped
    }
}

# ── State management ──────────────────────────────────────────────────────

function New-UpgradeState {
    <#
    .SYNOPSIS
        Create initial state dict for a run.
    #>
    param(
        [string]$CommandName,
        [string]$TargetVersion,
        [hashtable]$Clusters,
        [array]$Standalone,
        [array]$Skipped,
        [string]$OnErrorMode
    )

    $now = [DateTime]::UtcNow
    $runId = $now.ToString('yyyyMMdd-HHmmss')

    # Build ordered list of cluster IDs (sorted for determinism)
    $clustersOrder = @($Clusters.Keys | Sort-Object | ForEach-Object { [string]$_ })

    $gateways = @{}

    # Add clustered gateways
    foreach ($cid in $clustersOrder) {
        foreach ($gw in $Clusters[$cid]) {
            $gateways[[string]$gw.id] = @{
                name           = $gw.name
                site           = if ($gw.site_name) { $gw.site_name } else { 'unknown' }
                cluster_id     = $gw.cluster_id
                ha_role        = if ($gw.ha_role) { $gw.ha_role } else { 'unknown' }
                version_before = if ($gw.running_version) { $gw.running_version } else { '' }
                version_after  = $null
                status         = 'pending'
                phase          = $null
                error          = $null
                started        = $null
                finished       = $null
            }
        }
    }

    # Add standalone gateways
    foreach ($gw in $Standalone) {
        $gateways[[string]$gw.id] = @{
            name           = $gw.name
            site           = if ($gw.site_name) { $gw.site_name } else { 'unknown' }
            cluster_id     = $gw.cluster_id
            ha_role        = if ($gw.ha_role) { $gw.ha_role } else { 'standalone' }
            version_before = if ($gw.running_version) { $gw.running_version } else { '' }
            version_after  = $null
            status         = 'pending'
            phase          = $null
            error          = $null
            started        = $null
            finished       = $null
        }
    }

    # Add skipped gateways
    foreach ($gw in $Skipped) {
        $gateways[[string]$gw.id] = @{
            name           = $gw.name
            site           = if ($gw.site_name) { $gw.site_name } else { 'unknown' }
            cluster_id     = $gw.cluster_id
            ha_role        = if ($gw.ha_role) { $gw.ha_role } else { 'unknown' }
            version_before = if ($gw.running_version) { $gw.running_version } else { '' }
            version_after  = if ($gw.running_version) { $gw.running_version } else { '' }
            status         = 'skipped'
            phase          = $null
            error          = $null
            started        = $null
            finished       = $null
        }
    }

    return @{
        run_id         = $runId
        command        = $CommandName
        target_version = $TargetVersion
        on_error       = $OnErrorMode
        clusters_order = $clustersOrder
        started        = $now.ToString('o')
        finished       = $null
        gateways       = $gateways
    }
}

function Save-UpgradeState {
    <#
    .SYNOPSIS
        Persist state to the state file (JSON, human-readable).
    #>
    param([hashtable]$State)

    $State | ConvertTo-Json -Depth 10 | Set-Content -Path $script:STATE_FILE -Encoding UTF8
}

function Read-UpgradeState {
    <#
    .SYNOPSIS
        Load state from the state file. Returns $null if file does not exist.
    #>
    if (-not (Test-Path $script:STATE_FILE)) {
        return $null
    }
    $content = Get-Content -Path $script:STATE_FILE -Raw
    return $content | ConvertFrom-Json -AsHashtable
}

function Update-GatewayState {
    <#
    .SYNOPSIS
        Update a gateway's fields in the state and persist immediately.
    #>
    param(
        [hashtable]$State,
        [string]$GwId,
        [hashtable]$Updates
    )

    $gwKey = [string]$GwId
    if ($State.gateways.ContainsKey($gwKey)) {
        foreach ($entry in $Updates.GetEnumerator()) {
            $State.gateways[$gwKey][$entry.Key] = $entry.Value
        }
        Save-UpgradeState -State $State
    }
}

# ── Core engine ───────────────────────────────────────────────────────────

function Remove-OldImages {
    <#
    .SYNOPSIS
        Delete old staged images from a gateway to free disk space.
    #>
    param(
        [ApiClient]$Api,
        [string]$GwId,
        [string]$TargetVersion
    )

    try {
        $gwData = $Api.Get("/api/v2/Gateway/id/$GwId")
        # Unwrap if needed
        if ($gwData.PSObject -and $gwData.PSObject.Properties.Name -contains 'result') {
            $gwData = $gwData.result
            if ($gwData -is [array] -and $gwData.Count -gt 0) {
                $gwData = $gwData[0]
            }
        }
    } catch {
        return  # Non-fatal
    }

    $running = if ($gwData.running_version) { $gwData.running_version } else { '' }
    $images = @()
    if ($gwData.sw_image_status -and $gwData.sw_image_status.images) {
        $images = @($gwData.sw_image_status.images)
    }

    foreach ($img in $images) {
        $imgVersion = if ($img.version) { $img.version } else { '' }
        if ($imgVersion -and $imgVersion -ne $running -and $imgVersion -ne $TargetVersion) {
            try {
                $Api.Post("/api/v2/Gateway/sw_image_update/id/$GwId", @{
                    action  = 'delete'
                    version = $imgVersion
                }) | Out-Null
            } catch {
                # Non-fatal
            }
        }
    }
}

function Invoke-DownloadImage {
    <#
    .SYNOPSIS
        Initiate firmware download on a gateway.
    #>
    param(
        [ApiClient]$Api,
        [string]$GwId,
        [string]$TargetVersion
    )

    return $Api.Post("/api/v2/Gateway/sw_image_update/id/$GwId", @{
        action  = 'download'
        version = $TargetVersion
    })
}

function Invoke-ActivateUpgrade {
    <#
    .SYNOPSIS
        Activate a firmware upgrade on a gateway.
    #>
    param(
        [ApiClient]$Api,
        [string]$GwId,
        [string]$TargetVersion
    )

    return $Api.Post("/api/v2/Gateway/upgrade", @{
        gateway_id      = $GwId
        desired_version = $TargetVersion
    })
}

function Test-ImageDownloaded {
    <#
    .SYNOPSIS
        Check if the target firmware image is downloaded on a gateway.
    #>
    param(
        [ApiClient]$Api,
        [string]$GwId,
        [string]$TargetVersion
    )

    try {
        $gwData = $Api.Get("/api/v2/Gateway/id/$GwId")
        if ($gwData.PSObject -and $gwData.PSObject.Properties.Name -contains 'result') {
            $gwData = $gwData.result
            if ($gwData -is [array] -and $gwData.Count -gt 0) {
                $gwData = $gwData[0]
            }
        }
    } catch {
        return $false
    }

    # Check sw_image_status.images[]
    if ($gwData.sw_image_status -and $gwData.sw_image_status.images) {
        foreach ($img in $gwData.sw_image_status.images) {
            if ($img.version -eq $TargetVersion) {
                $imgStatus = ($img.status).ToLower()
                if ($imgStatus -in @('downloaded', 'completed')) {
                    return $true
                }
            }
        }
    }

    # Also check download_status.versions[]
    if ($gwData.download_status -and $gwData.download_status.versions) {
        foreach ($ver in $gwData.download_status.versions) {
            if ($ver.version -eq $TargetVersion) {
                $verStatus = ($ver.status).ToLower()
                if ($verStatus -in @('downloaded', 'completed')) {
                    return $true
                }
            }
        }
    }

    return $false
}

function Wait-GatewayUpgrade {
    <#
    .SYNOPSIS
        Poll a gateway until it is online at the target version, or timeout.
    #>
    param(
        [ApiClient]$Api,
        [string]$GwId,
        [string]$TargetVersion,
        [int]$TimeoutMinutes
    )

    $deadline = [DateTimeOffset]::UtcNow.AddMinutes($TimeoutMinutes)

    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        try {
            $gwData = $Api.Get("/api/v2/Gateway/id/$GwId")
            if ($gwData.PSObject -and $gwData.PSObject.Properties.Name -contains 'result') {
                $gwData = $gwData.result
                if ($gwData -is [array] -and $gwData.Count -gt 0) {
                    $gwData = $gwData[0]
                }
            }

            $running = if ($gwData.running_version) { $gwData.running_version } else { '' }
            $health = if ($gwData.health_color) { $gwData.health_color } else { '' }

            if ($running -eq $TargetVersion -and $health -eq 'green') {
                return $true
            }
        } catch {
            # Gateway may be rebooting, keep polling
        }

        Start-Sleep -Seconds $script:POLL_INTERVAL
    }

    return $false
}

function Invoke-ProcessGateway {
    <#
    .SYNOPSIS
        Orchestrate download/upgrade for a single gateway.
        Returns $true on success, $false on failure.
    #>
    param(
        [ApiClient]$Api,
        [hashtable]$State,
        [string]$GwId,
        [string]$TargetVersion,
        [string]$CommandName,
        [int]$TimeoutMinutes
    )

    $gwState = $State.gateways[[string]$GwId]
    if (-not $gwState) { return $false }

    $gwName = $gwState.name
    $haLabel = $gwState.ha_role.ToUpper()
    $t0 = [DateTimeOffset]::UtcNow

    Update-GatewayState -State $State -GwId $GwId -Updates @{
        status  = 'in_progress'
        started = [DateTime]::UtcNow.ToString('o')
    }

    # Phase 1: Download (if not already downloaded)
    if ($gwState.phase -ne 'downloaded') {
        Write-Host "  $gwName ($haLabel)  cleaning old images..." -NoNewline
        Update-GatewayState -State $State -GwId $GwId -Updates @{ phase = 'cleanup' }
        try {
            Remove-OldImages -Api $Api -GwId $GwId -TargetVersion $TargetVersion
            Write-Host " done"
        } catch {
            Write-Host " warning: $_" -ForegroundColor Yellow
            # Non-fatal, continue
        }

        Write-Host "  $gwName ($haLabel)  downloading..." -NoNewline
        Update-GatewayState -State $State -GwId $GwId -Updates @{ phase = 'download' }
        try {
            Invoke-DownloadImage -Api $Api -GwId $GwId -TargetVersion $TargetVersion | Out-Null
        } catch {
            $elapsed = [int]([DateTimeOffset]::UtcNow - $t0).TotalSeconds
            Write-Host " FAILED (${elapsed}s)" -ForegroundColor Red
            Update-GatewayState -State $State -GwId $GwId -Updates @{
                status   = 'failed'
                phase    = 'download'
                error    = [string]$_
                finished = [DateTime]::UtcNow.ToString('o')
            }
            return $false
        }

        # Poll until download completes
        $dlDeadline = [DateTimeOffset]::UtcNow.AddMinutes($TimeoutMinutes)
        $downloadCompleted = $false
        while ([DateTimeOffset]::UtcNow -lt $dlDeadline) {
            if (Test-ImageDownloaded -Api $Api -GwId $GwId -TargetVersion $TargetVersion) {
                $downloadCompleted = $true
                break
            }
            Start-Sleep -Seconds $script:POLL_INTERVAL
        }

        if (-not $downloadCompleted) {
            $elapsed = [int]([DateTimeOffset]::UtcNow - $t0).TotalSeconds
            Write-Host " TIMEOUT (${elapsed}s)" -ForegroundColor Red
            Update-GatewayState -State $State -GwId $GwId -Updates @{
                status   = 'failed'
                phase    = 'download'
                error    = 'download timed out'
                finished = [DateTime]::UtcNow.ToString('o')
            }
            return $false
        }

        $elapsed = [int]([DateTimeOffset]::UtcNow - $t0).TotalSeconds
        Write-Host " done (${elapsed}s)" -ForegroundColor Green
        Update-GatewayState -State $State -GwId $GwId -Updates @{ phase = 'downloaded' }
    }

    # If command is download-only, we're done
    if ($CommandName -eq 'download') {
        Update-GatewayState -State $State -GwId $GwId -Updates @{
            status   = 'completed'
            phase    = 'downloaded'
            finished = [DateTime]::UtcNow.ToString('o')
        }
        return $true
    }

    # Phase 2: Activate upgrade
    Write-Host "  $gwName ($haLabel)  upgrading..." -NoNewline
    Update-GatewayState -State $State -GwId $GwId -Updates @{ phase = 'activate' }
    try {
        Invoke-ActivateUpgrade -Api $Api -GwId $GwId -TargetVersion $TargetVersion | Out-Null
    } catch {
        $elapsed = [int]([DateTimeOffset]::UtcNow - $t0).TotalSeconds
        Write-Host " FAILED (${elapsed}s)" -ForegroundColor Red
        Update-GatewayState -State $State -GwId $GwId -Updates @{
            status   = 'failed'
            phase    = 'activate'
            error    = [string]$_
            finished = [DateTime]::UtcNow.ToString('o')
        }
        return $false
    }

    # Poll until gateway is online at target version
    if (Wait-GatewayUpgrade -Api $Api -GwId $GwId -TargetVersion $TargetVersion -TimeoutMinutes $TimeoutMinutes) {
        $elapsed = [int]([DateTimeOffset]::UtcNow - $t0).TotalSeconds
        Write-Host " done (${elapsed}s)" -ForegroundColor Green
        Update-GatewayState -State $State -GwId $GwId -Updates @{
            status        = 'completed'
            phase         = 'complete'
            version_after = $TargetVersion
            finished      = [DateTime]::UtcNow.ToString('o')
        }
        return $true
    } else {
        $elapsed = [int]([DateTimeOffset]::UtcNow - $t0).TotalSeconds
        Write-Host " TIMEOUT (${elapsed}s)" -ForegroundColor Red
        Update-GatewayState -State $State -GwId $GwId -Updates @{
            status   = 'failed'
            phase    = 'activate'
            error    = 'upgrade timed out waiting for gateway'
            finished = [DateTime]::UtcNow.ToString('o')
        }
        return $false
    }
}

function Invoke-ProcessCluster {
    <#
    .SYNOPSIS
        Process a cluster with HA-aware ordering (standby first, then active).
    #>
    param(
        [ApiClient]$Api,
        [hashtable]$State,
        [string]$ClusterId,
        [array]$GwIds,
        [string]$TargetVersion,
        [string]$CommandName,
        [string]$OnErrorMode,
        [int]$TimeoutMinutes
    )

    # Sort gateway IDs: standby/backup first
    $sortedIds = @($GwIds | Sort-Object {
        $gwState = $State.gateways[[string]$_]
        $role = if ($gwState) { $gwState.ha_role } else { 'unknown' }
        $name = if ($gwState) { $gwState.name } else { '' }
        if ($role -eq 'standby') { "0|$name" } else { "1|$name" }
    })

    $clusterOk = $true
    for ($i = 0; $i -lt $sortedIds.Count; $i++) {
        $gwId = $sortedIds[$i]
        $gwState = $State.gateways[[string]$gwId]

        # Skip already completed or skipped
        if ($gwState -and $gwState.status -in @('completed', 'skipped')) {
            continue
        }

        $success = Invoke-ProcessGateway -Api $Api -State $State -GwId $gwId `
            -TargetVersion $TargetVersion -CommandName $CommandName `
            -TimeoutMinutes $TimeoutMinutes

        if (-not $success) {
            $clusterOk = $false
            if ($OnErrorMode -eq 'Stop') {
                return $false
            }
            # on_error == Continue: skip remaining in this cluster
            for ($j = $i + 1; $j -lt $sortedIds.Count; $j++) {
                $remainingId = $sortedIds[$j]
                $remaining = $State.gateways[[string]$remainingId]
                if ($remaining -and $remaining.status -eq 'pending') {
                    Update-GatewayState -State $State -GwId $remainingId -Updates @{
                        status = 'skipped'
                        error  = 'skipped due to prior failure in cluster'
                    }
                }
            }
            break
        }
    }

    return $clusterOk
}

function Invoke-Run {
    <#
    .SYNOPSIS
        Top-level orchestration for download/upgrade.
    #>
    param(
        [ApiClient]$Api,
        [string]$CommandName,
        [string]$TargetVersion,
        [hashtable]$Clusters,
        [array]$Standalone,
        [array]$Skipped,
        [string]$OnErrorMode,
        [int]$TimeoutMinutes
    )

    $t0 = [DateTimeOffset]::UtcNow

    $state = New-UpgradeState -CommandName $CommandName -TargetVersion $TargetVersion `
        -Clusters $Clusters -Standalone $Standalone -Skipped $Skipped `
        -OnErrorMode $OnErrorMode
    Save-UpgradeState -State $state
    Write-Host "`n  State file: $($script:STATE_FILE) (run_id: $($state.run_id))`n"

    # Process clusters sequentially
    foreach ($cid in $state.clusters_order) {
        # Collect gateway IDs for this cluster (handle int/str key mismatch)
        $clusterGws = @()
        if ($Clusters.ContainsKey($cid)) {
            $clusterGws = $Clusters[$cid]
        } else {
            # Try numeric key
            try {
                $numCid = [int]$cid
                if ($Clusters.ContainsKey($numCid)) {
                    $clusterGws = $Clusters[$numCid]
                }
            } catch { }
        }

        $gwIds = @($clusterGws | ForEach-Object { [string]$_.id })
        if ($gwIds.Count -eq 0) { continue }

        $siteName = $state.gateways[$gwIds[0]].site
        Write-Host "  --- Cluster $cid ($siteName) ---"

        $ok = Invoke-ProcessCluster -Api $Api -State $state -ClusterId $cid `
            -GwIds $gwIds -TargetVersion $TargetVersion -CommandName $CommandName `
            -OnErrorMode $OnErrorMode -TimeoutMinutes $TimeoutMinutes

        if (-not $ok -and $OnErrorMode -eq 'Stop') {
            Write-Host "`n  Stopping due to failure (--on-error=stop)."
            break
        }
    }

    # Process standalone gateways
    if ($Standalone.Count -gt 0) {
        Write-Host "`n  --- Standalone gateways ---"
        foreach ($gw in $Standalone) {
            $gwId = [string]$gw.id
            $gwState = $state.gateways[$gwId]
            if ($gwState -and $gwState.status -in @('completed', 'skipped')) {
                continue
            }
            $ok = Invoke-ProcessGateway -Api $Api -State $state -GwId $gwId `
                -TargetVersion $TargetVersion -CommandName $CommandName `
                -TimeoutMinutes $TimeoutMinutes
            if (-not $ok -and $OnErrorMode -eq 'Stop') {
                Write-Host "`n  Stopping due to failure (--on-error=stop)."
                break
            }
        }
    }

    $elapsed = ([DateTimeOffset]::UtcNow - $t0).TotalSeconds
    $state.finished = [DateTime]::UtcNow.ToString('o')
    Save-UpgradeState -State $state

    Write-Host ""
    Show-Summary -State $state -ElapsedSeconds $elapsed
    Write-Reports -State $state -ElapsedSeconds $elapsed
}

# ── Summary and reports ───────────────────────────────────────────────────

function Show-Summary {
    <#
    .SYNOPSIS
        Display a summary of the run with status counts and markers.
    #>
    param(
        [hashtable]$State,
        [double]$ElapsedSeconds
    )

    $gateways = $State.gateways

    $completed = @($gateways.Values | Where-Object { $_.status -eq 'completed' })
    $failed = @($gateways.Values | Where-Object { $_.status -eq 'failed' })
    $skippedList = @($gateways.Values | Where-Object { $_.status -eq 'skipped' })
    $pending = @($gateways.Values | Where-Object { $_.status -notin @('completed', 'failed', 'skipped') })

    $minutes = [int][Math]::Floor($ElapsedSeconds / 60)
    $seconds = [int]($ElapsedSeconds % 60)

    Write-Host ('=' * 70)
    Write-Host "  $($State.command.ToUpper()) SUMMARY (run_id: $($State.run_id))"
    Write-Host ('=' * 70)
    Write-Host "  Target version : $($State.target_version)"
    Write-Host "  Elapsed time   : ${minutes}m ${seconds}s"
    Write-Host ""
    Write-Host "  " -NoNewline; Write-Host ([char]0x2713) -ForegroundColor Green -NoNewline; Write-Host " Completed : $($completed.Count)"
    Write-Host "  " -NoNewline; Write-Host ([char]0x2717) -ForegroundColor Red -NoNewline; Write-Host " Failed    : $($failed.Count)"
    Write-Host "  " -NoNewline; Write-Host ([char]0x25CB) -ForegroundColor Yellow -NoNewline; Write-Host " Skipped   : $($skippedList.Count)"
    Write-Host "  " -NoNewline; Write-Host ([char]0x2022) -NoNewline; Write-Host " Pending   : $($pending.Count)"

    if ($failed.Count -gt 0) {
        Write-Host ""
        Write-Host "  Failed gateways:"
        foreach ($g in $failed) {
            $errorMsg = if ($g.error) { $g.error } else { 'unknown error' }
            Write-Host "    " -NoNewline; Write-Host ([char]0x2717) -ForegroundColor Red -NoNewline; Write-Host " $($g.name) -- $errorMsg"
        }
    }

    Write-Host ""
}

function Write-Reports {
    <#
    .SYNOPSIS
        Generate JSON and CSV report files for the run.
    #>
    param(
        [hashtable]$State,
        [double]$ElapsedSeconds
    )

    $runId = $State.run_id
    $gateways = $State.gateways

    # Summary counts
    $counts = @{ completed = 0; failed = 0; skipped = 0; pending = 0 }
    foreach ($g in $gateways.Values) {
        $status = $g.status
        if ($counts.ContainsKey($status)) {
            $counts[$status]++
        } else {
            $counts['pending']++
        }
    }

    # JSON report
    $jsonPath = "ztb_upgrade_report_${runId}.json"
    $report = @{
        run_id           = $runId
        command          = $State.command
        target_version   = $State.target_version
        started          = $State.started
        finished         = $State.finished
        duration_seconds = [Math]::Round($ElapsedSeconds, 1)
        summary          = $counts
        gateways         = $gateways
    }
    $report | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8

    # CSV report
    $csvPath = "ztb_upgrade_report_${runId}.csv"
    $csvRows = @()
    foreach ($entry in $gateways.GetEnumerator()) {
        $gwId = $entry.Key
        $g = $entry.Value

        # Calculate per-gateway duration
        $duration = ''
        if ($g.started -and $g.finished) {
            try {
                $tStart = [DateTime]::Parse($g.started)
                $tEnd = [DateTime]::Parse($g.finished)
                $durationSec = [int]($tEnd - $tStart).TotalSeconds
                $duration = "${durationSec}s"
            } catch { }
        }

        $csvRows += [PSCustomObject]@{
            gateway_id     = $gwId
            gateway_name   = if ($g.name) { $g.name } else { '' }
            site           = if ($g.site) { $g.site } else { '' }
            cluster        = if ($g.cluster_id) { $g.cluster_id } else { '' }
            version_before = if ($g.version_before) { $g.version_before } else { '' }
            version_after  = if ($g.version_after) { $g.version_after } else { '' }
            status         = if ($g.status) { $g.status } else { '' }
            phase          = if ($g.phase) { $g.phase } else { '' }
            duration       = $duration
            error          = if ($g.error) { $g.error } else { '' }
        }
    }
    $csvRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    Write-Host "  Reports:"
    Write-Host "    JSON: $jsonPath"
    Write-Host "    CSV:  $csvPath"
    Write-Host ""
}

# ── Commands ──────────────────────────────────────────────────────────────

function Invoke-Inventory {
    <#
    .SYNOPSIS
        List all gateways with current firmware versions.
    #>
    param([ApiClient]$Api)

    $gateways = Get-Gateways -Api $Api
    $releases = Get-Releases -Api $Api

    $latest = if ($releases.Count -gt 0) { $releases[0].version_number } else { 'unknown' }
    $total = $gateways.Count

    Write-Host ""
    Write-Host ('=' * 70)
    Write-Host "  ZTB Gateway Inventory -- $total gateway(s), latest firmware: $latest"
    Write-Host ('=' * 70)

    # Version distribution
    $versionCounts = @{}
    foreach ($gw in $gateways) {
        $ver = if ($gw.running_version) { $gw.running_version } else { '(unknown)' }
        if (-not $versionCounts.ContainsKey($ver)) { $versionCounts[$ver] = 0 }
        $versionCounts[$ver]++
    }

    Write-Host ""
    Write-Host "  Version distribution:"
    foreach ($ver in ($versionCounts.Keys | Sort-Object)) {
        $count = $versionCounts[$ver]
        $marker = if ($ver -eq $latest) { ' (latest)' } else { '' }
        Write-Host "    ${ver}: $count gateway(s)$marker"
    }

    # Table
    Write-Host ""
    Write-Host ("  {0,-22} {1,-20} {2,7}  {3,-10} {4,-15} {5}" -f 'Gateway', 'Site', 'Cluster', 'HA Role', 'Version', 'Status')
    Write-Host ("  {0,-22} {1,-20} {2,7}  {3,-10} {4,-15} {5}" -f ('-' * 22), ('-' * 20), ('-' * 7), ('-' * 10), ('-' * 15), ('-' * 8))
    foreach ($gw in $gateways) {
        $statusIcon = if ($gw.status -eq 'online') { [char]0x2713 } else { [char]0x2717 }
        $clusterStr = if ($gw.cluster_id) { [string]$gw.cluster_id } else { '-' }
        $statusColor = if ($gw.status -eq 'online') { 'Green' } else { 'Red' }
        Write-Host ("  {0,-22} {1,-20} {2,7}  {3,-10} {4,-15} " -f $gw.name, $gw.site_name, $clusterStr, $gw.ha_role, $gw.running_version) -NoNewline
        Write-Host "$statusIcon $($gw.status)" -ForegroundColor $statusColor
    }

    Write-Host ""
}

function Invoke-Download {
    <#
    .SYNOPSIS
        Download firmware to selected gateways.
    #>
    param([ApiClient]$Api)

    $prepResult = Invoke-PrepareRun -Api $Api -CommandName 'download' `
        -VersionArg $script:Version -SelectAll $script:All.IsPresent `
        -SiteFilter $script:Site -ClusterFilter $script:Cluster `
        -GatewayFilter $script:Gateway -BelowVersionFilter $script:BelowVersion `
        -FromFileFilter $script:FromFile -IsDryRun $script:DryRun.IsPresent `
        -OnErrorMode $script:OnError -TimeoutMinutes $script:Timeout

    Invoke-Run -Api $Api -CommandName 'download' -TargetVersion $prepResult.Target `
        -Clusters $prepResult.Clusters -Standalone $prepResult.Standalone `
        -Skipped $prepResult.Skipped -OnErrorMode $script:OnError `
        -TimeoutMinutes $script:Timeout
}

function Invoke-Upgrade {
    <#
    .SYNOPSIS
        Upgrade selected gateways to a target version.
    #>
    param([ApiClient]$Api)

    $prepResult = Invoke-PrepareRun -Api $Api -CommandName 'upgrade' `
        -VersionArg $script:Version -SelectAll $script:All.IsPresent `
        -SiteFilter $script:Site -ClusterFilter $script:Cluster `
        -GatewayFilter $script:Gateway -BelowVersionFilter $script:BelowVersion `
        -FromFileFilter $script:FromFile -IsDryRun $script:DryRun.IsPresent `
        -OnErrorMode $script:OnError -TimeoutMinutes $script:Timeout

    Invoke-Run -Api $Api -CommandName 'upgrade' -TargetVersion $prepResult.Target `
        -Clusters $prepResult.Clusters -Standalone $prepResult.Standalone `
        -Skipped $prepResult.Skipped -OnErrorMode $script:OnError `
        -TimeoutMinutes $script:Timeout
}

function Invoke-Resume {
    <#
    .SYNOPSIS
        Resume an interrupted upgrade operation.
    #>
    param([ApiClient]$Api)

    $state = Read-UpgradeState
    if (-not $state) {
        Write-Host "ERROR: No state file found ($($script:STATE_FILE)). Nothing to resume." -ForegroundColor Red
        exit 1
    }

    $commandName = if ($state.command) { $state.command } else { 'upgrade' }
    $target = if ($state.target_version) { $state.target_version } else { '' }
    $onErrorMode = if ($state.on_error) { $state.on_error } else { 'continue' }
    $gateways = $state.gateways

    # Count current status
    $completed = @($gateways.Keys | Where-Object { $gateways[$_].status -eq 'completed' })
    $failed = @($gateways.Keys | Where-Object { $gateways[$_].status -eq 'failed' })
    $skippedList = @($gateways.Keys | Where-Object { $gateways[$_].status -eq 'skipped' })
    $pending = @($gateways.Keys | Where-Object { $gateways[$_].status -notin @('completed', 'failed', 'skipped') })

    Write-Host ""
    Write-Host ('=' * 70)
    Write-Host "  RESUME -- run_id: $($state.run_id)"
    Write-Host ('=' * 70)
    Write-Host "  Command        : $commandName"
    Write-Host "  Target version : $target"
    Write-Host "  Completed      : $($completed.Count)"
    Write-Host "  Failed         : $($failed.Count)"
    Write-Host "  Skipped        : $($skippedList.Count)"
    Write-Host "  Pending        : $($pending.Count)"

    if ($failed.Count -eq 0 -and $pending.Count -eq 0) {
        Write-Host "`n  Nothing to resume -- all gateways are completed or skipped."
        return
    }

    # Reset failed gateways for retry
    if ($failed.Count -gt 0) {
        Write-Host "`n  Resetting $($failed.Count) failed gateway(s) for retry:"
        foreach ($gid in $failed) {
            $g = $gateways[$gid]
            # If phase was "activate" and command is "upgrade", skip re-download
            if ($g.phase -eq 'activate' -and $commandName -eq 'upgrade') {
                Write-Host "    $($g.name): reset to pending (skip download, image already staged)"
                Update-GatewayState -State $state -GwId $gid -Updates @{
                    status   = 'pending'
                    phase    = 'downloaded'
                    error    = $null
                    finished = $null
                }
            } else {
                Write-Host "    $($g.name): reset to pending"
                Update-GatewayState -State $state -GwId $gid -Updates @{
                    status   = 'pending'
                    phase    = $null
                    error    = $null
                    finished = $null
                }
            }
        }
    }

    # Also reset skipped-due-to-failure gateways
    foreach ($gid in $gateways.Keys) {
        $g = $gateways[$gid]
        if ($g.status -eq 'skipped' -and $g.error -and $g.error.StartsWith('skipped due to')) {
            Update-GatewayState -State $state -GwId $gid -Updates @{
                status = 'pending'
                phase  = $null
                error  = $null
            }
        }
    }

    # Confirm
    $answer = Read-Host "`n  Proceed with resume? [y/N]"
    if ($answer -notin @('y', 'yes')) {
        Write-Host "  Aborted."
        exit 1
    }

    $t0 = [DateTimeOffset]::UtcNow
    $timeoutMinutes = $script:Timeout

    # Replay cluster order from state
    foreach ($cid in $state.clusters_order) {
        # Collect gateway IDs for this cluster that still need processing
        $gwIds = @($gateways.Keys | Where-Object {
            [string]$gateways[$_].cluster_id -eq [string]$cid -and
            $gateways[$_].status -notin @('completed', 'skipped')
        })
        if ($gwIds.Count -eq 0) { continue }

        $siteName = $gateways[$gwIds[0]].site
        Write-Host "`n  --- Cluster $cid ($siteName) ---"

        $ok = Invoke-ProcessCluster -Api $Api -State $state -ClusterId $cid `
            -GwIds $gwIds -TargetVersion $target -CommandName $commandName `
            -OnErrorMode $onErrorMode -TimeoutMinutes $timeoutMinutes

        if (-not $ok -and $onErrorMode -eq 'Stop') {
            Write-Host "`n  Stopping due to failure (--on-error=stop)."
            break
        }
    }

    # Process standalone gateways (those without a cluster in clusters_order)
    $clusterGwIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($cid in $state.clusters_order) {
        foreach ($gid in $gateways.Keys) {
            if ([string]$gateways[$gid].cluster_id -eq [string]$cid) {
                [void]$clusterGwIds.Add($gid)
            }
        }
    }

    $standaloneIds = @($gateways.Keys | Where-Object {
        -not $clusterGwIds.Contains($_) -and
        $gateways[$_].status -notin @('completed', 'skipped')
    })

    if ($standaloneIds.Count -gt 0) {
        Write-Host "`n  --- Standalone gateways ---"
        foreach ($gwId in $standaloneIds) {
            $ok = Invoke-ProcessGateway -Api $Api -State $state -GwId $gwId `
                -TargetVersion $target -CommandName $commandName `
                -TimeoutMinutes $timeoutMinutes
            if (-not $ok -and $onErrorMode -eq 'Stop') {
                Write-Host "`n  Stopping due to failure (--on-error=stop)."
                break
            }
        }
    }

    $elapsed = ([DateTimeOffset]::UtcNow - $t0).TotalSeconds
    $state.finished = [DateTime]::UtcNow.ToString('o')
    Save-UpgradeState -State $state

    Write-Host ""
    Show-Summary -State $state -ElapsedSeconds $elapsed
    Write-Reports -State $state -ElapsedSeconds $elapsed
}

# ── Interactive wizard ────────────────────────────────────────────────────

function Read-PromptChoice {
    <#
    .SYNOPSIS
        Display numbered options and return selected index (or list if multi).
    #>
    param(
        [string]$Prompt,
        [string[]]$Options,
        [switch]$AllowMulti
    )

    Write-Host "`n  $Prompt"
    for ($i = 0; $i -lt $Options.Count; $i++) {
        Write-Host "    $($i + 1). $($Options[$i])"
    }

    $hint = if ($AllowMulti) { 'comma-separated' } else { 'number' }
    while ($true) {
        $raw = Read-Host "  Choice ($hint)"
        if (-not $raw) { continue }

        if ($AllowMulti) {
            try {
                $indices = @($raw -split ',' | ForEach-Object { [int]$_.Trim() - 1 })
                $valid = $true
                foreach ($idx in $indices) {
                    if ($idx -lt 0 -or $idx -ge $Options.Count) { $valid = $false; break }
                }
                if ($valid) { return $indices }
            } catch { }
            Write-Host "    Invalid input. Enter numbers 1-$($Options.Count) separated by commas."
        } else {
            try {
                $idx = [int]$raw - 1
                if ($idx -ge 0 -and $idx -lt $Options.Count) { return $idx }
            } catch { }
            Write-Host "    Invalid input. Enter a number 1-$($Options.Count)."
        }
    }
}

function Invoke-Wizard {
    <#
    .SYNOPSIS
        Interactive upgrade wizard (no subcommand).
    #>

    try {
        Invoke-WizardInner
    } catch [System.Management.Automation.PipelineStoppedException] {
        Write-Host "`n  Aborted."
    } catch {
        if ($_.Exception.Message -match 'user cancel|abort|OperationStopped') {
            Write-Host "`n  Aborted."
        } else {
            throw
        }
    }
}

function Invoke-WizardInner {
    <#
    .SYNOPSIS
        Inner implementation of the interactive wizard.
    #>

    Write-Host ""
    Write-Host ('=' * 70)
    Write-Host "  ZTB Bulk Upgrade -- Interactive Wizard"
    Write-Host ('=' * 70)

    # Step 1: Load credentials and connect
    $config = Get-ZtbConfig -CliClientId '' -CliClientSecret '' -CliVanityDomain '' -CliAirgapSite '' -CliEnvFile ''
    $api = [ApiClient]::new($config)

    Write-Host "`n  Connecting to AirGap API..."
    $gateways = Get-Gateways -Api $api
    $releases = Get-Releases -Api $api

    if ($gateways.Count -eq 0) {
        Write-Host "  No gateways found in tenant. Nothing to do."
        return
    }

    $latest = if ($releases.Count -gt 0) { $releases[0].version_number } else { 'unknown' }
    Write-Host "  Found $($gateways.Count) gateway(s), latest firmware: $latest"

    # Step 2: Choose action
    $action = Read-PromptChoice -Prompt "What would you like to do?" -Options @(
        'View inventory',
        'Download firmware only',
        'Download + Upgrade'
    )

    if ($action -eq 0) {
        Invoke-Inventory -Api $api
        return
    }

    $commandName = if ($action -eq 1) { 'download' } else { 'upgrade' }

    # Step 3: Choose target version
    $maxShown = [Math]::Min(5, $releases.Count)
    $versionOptions = @()
    for ($i = 0; $i -lt $maxShown; $i++) {
        $r = $releases[$i]
        $dateStr = if ($r.release_date) { $r.release_date.Substring(0, [Math]::Min(10, $r.release_date.Length)) } else { 'unknown date' }
        $versionOptions += "$($r.version_number)  ($dateStr)"
    }
    $versionOptions += 'Enter manually'

    $verIdx = Read-PromptChoice -Prompt "Target version:" -Options $versionOptions

    if ($verIdx -lt $maxShown) {
        $target = $releases[$verIdx].version_number
    } else {
        $rawVer = Read-Host "  Version string"
        if (-not $rawVer) {
            Write-Host "  Aborted."
            return
        }
        $target = Resolve-FirmwareVersion -Api $api -VersionArg $rawVer
    }

    Write-Host "`n  Target version: $target"

    # Step 4: Show upgrade gap
    $splitResult = Split-AtTarget -Gateways $gateways -TargetVersion $target
    $toProcess = $splitResult.ToProcess
    $alreadyAt = $splitResult.Skipped

    Write-Host "  $($toProcess.Count) gateway(s) need upgrade, $($alreadyAt.Count) already at $target"

    if ($toProcess.Count -eq 0) {
        Write-Host "  Nothing to do -- all gateways are at the target version."
        return
    }

    # Step 5: Gateway selection
    $sites = @{}
    $clustersMap = @{}
    foreach ($gw in $toProcess) {
        if (-not $sites.ContainsKey($gw.site_name)) { $sites[$gw.site_name] = @() }
        $sites[$gw.site_name] += $gw
        if ($gw.cluster_id) {
            if (-not $clustersMap.ContainsKey($gw.cluster_id)) { $clustersMap[$gw.cluster_id] = @() }
            $clustersMap[$gw.cluster_id] += $gw
        }
    }

    $selectionOptions = @(
        "All ($($toProcess.Count) gateway(s))",
        'By site',
        'By cluster',
        'Below a specific version',
        'From file'
    )
    $selIdx = Read-PromptChoice -Prompt "Select gateways:" -Options $selectionOptions

    $selected = @($toProcess)

    switch ($selIdx) {
        0 {
            # All -- keep selected as is
        }
        1 {
            # By site
            $siteNames = @($sites.Keys | Sort-Object)
            if ($siteNames.Count -eq 0) {
                Write-Host "  No sites found."
                return
            }
            $siteOptions = @($siteNames | ForEach-Object { "$_ ($($sites[$_].Count) gw)" })
            $chosen = Read-PromptChoice -Prompt "Select site(s):" -Options $siteOptions -AllowMulti
            $chosenSites = @($chosen | ForEach-Object { $siteNames[$_] })
            $selected = @($toProcess | Where-Object { $_.site_name -in $chosenSites })
        }
        2 {
            # By cluster
            $clusterIds = @($clustersMap.Keys | Sort-Object)
            if ($clusterIds.Count -eq 0) {
                Write-Host "  No clusters found (all gateways are standalone)."
                return
            }
            $clusterOptions = @($clusterIds | ForEach-Object {
                $gws = $clustersMap[$_]
                $siteName = if ($gws.Count -gt 0) { $gws[0].site_name } else { 'unknown' }
                "Cluster $_ -- $siteName ($($gws.Count) gw)"
            })
            $chosen = Read-PromptChoice -Prompt "Select cluster(s):" -Options $clusterOptions -AllowMulti
            $chosenIds = @($chosen | ForEach-Object { $clusterIds[$_] })
            $selected = @($toProcess | Where-Object { $_.cluster_id -in $chosenIds })
        }
        3 {
            # Below a specific version
            $threshold = Read-Host "  Version threshold (gateways below this)"
            if (-not $threshold) {
                Write-Host "  Aborted."
                return
            }
            $selected = @($toProcess | Where-Object {
                $_.running_version -and (Compare-VersionLt -A $_.running_version -B $threshold)
            })
        }
        4 {
            # From file
            $fpath = Read-Host "  File path (one gateway name per line)"
            if (-not $fpath) {
                Write-Host "  Aborted."
                return
            }
            if (-not (Test-Path $fpath)) {
                Write-Host "  ERROR: File not found: $fpath" -ForegroundColor Red
                return
            }
            $fileIds = @(Get-Content $fpath | ForEach-Object { $_.Trim() } |
                Where-Object { $_ -and -not $_.StartsWith('#') })
            $selected = @($toProcess | Where-Object { $_.name -in $fileIds -or $_.id -in $fileIds })
        }
    }

    if ($selected.Count -eq 0) {
        Write-Host "  No gateways match the selection. Aborting."
        return
    }

    Write-Host "`n  Selected $($selected.Count) gateway(s) for $commandName."

    # Step 6: On-error behavior
    $errIdx = Read-PromptChoice -Prompt "On error:" -Options @('Continue', 'Stop')
    $onErrorMode = if ($errIdx -eq 0) { 'Continue' } else { 'Stop' }

    # Step 7: Partition, display plan, confirm
    $finalSplit = Split-AtTarget -Gateways $selected -TargetVersion $target
    $finalProcess = $finalSplit.ToProcess
    $finalSkipped = $finalSplit.Skipped

    if ($finalProcess.Count -eq 0) {
        Write-Host "  All selected gateways are already at target. Nothing to do."
        return
    }

    $partResult = Split-ByCluster -Gateways $finalProcess
    $clusters = $partResult.Clusters
    $standalone = $partResult.Standalone

    $allSkipped = @($finalSkipped) + @($alreadyAt)
    Show-Plan -CommandName $commandName -TargetVersion $target `
        -Clusters $clusters -Standalone $standalone -Skipped $allSkipped `
        -OnErrorMode $onErrorMode -IsDryRun $false

    $answer = Read-Host "  Proceed? [y/N]"
    if ($answer -notin @('y', 'yes')) {
        Write-Host "  Aborted."
        return
    }

    # Step 8: Run
    Invoke-Run -Api $api -CommandName $commandName -TargetVersion $target `
        -Clusters $clusters -Standalone $standalone -Skipped $allSkipped `
        -OnErrorMode $onErrorMode -TimeoutMinutes $script:DEFAULT_TIMEOUT
}

# ── Main ──────────────────────────────────────────────────────────────────

# If no command and no meaningful parameters -> wizard
if (-not $Command -and -not $Version -and -not $All -and -not $Site -and
    -not $Cluster -and -not $Gateway -and -not $BelowVersion -and -not $FromFile) {
    Invoke-Wizard
    return
}

# Validate required params for download/upgrade
if ($Command -in @('download', 'upgrade') -and -not $Version) {
    Write-Host "ERROR: -Version is required for $Command command." -ForegroundColor Red
    exit 1
}

# Build config and API client
$config = Get-ZtbConfig -CliClientId $ClientId -CliClientSecret $ClientSecret `
    -CliVanityDomain $VanityDomain -CliAirgapSite $AirgapSite -CliEnvFile $EnvFile
$api = [ApiClient]::new($config)

# Dispatch
switch ($Command) {
    'inventory' {
        Invoke-Inventory -Api $api
    }
    'download' {
        Invoke-Download -Api $api
    }
    'upgrade' {
        Invoke-Upgrade -Api $api
    }
    'resume' {
        Invoke-Resume -Api $api
    }
    default {
        Invoke-Wizard
    }
}
