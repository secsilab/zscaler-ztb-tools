#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Compact firmware download tool for Zscaler ZTB gateways via AirGap API.

.DESCRIPTION
    Pre-stages firmware across the fleet in one command. No state file,
    no resume, no wizard, no reports -- just download.

.EXAMPLE
    ./ztb_download.ps1 -Version latest -All
.EXAMPLE
    ./ztb_download.ps1 -Version 24.3.1 -Site "Paris-*" -DryRun
.EXAMPLE
    ./ztb_download.ps1 -Version latest -BelowVersion 24.3.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Version,
    [switch]$All,
    [string]$Site,
    [string]$Cluster,
    [string]$Gateway,
    [string]$BelowVersion,
    [switch]$DryRun,
    [string]$ClientId,
    [string]$ClientSecret,
    [string]$VanityDomain,
    [string]$AirgapSite,
    [string]$EnvFile
)

$script:TOKEN_AUDIENCE = "https://api.zscaler.com"
$script:TOKEN_REFRESH_MARGIN = 60
$script:POLL_INTERVAL = 20
$script:DOWNLOAD_TIMEOUT = 900

# ── Env & config ─────────────────────────────────────────────────────────

function Import-EnvFile {
    param([string]$Path)
    if (-not $Path) {
        $Path = Join-Path $PSScriptRoot ".env"
    }
    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) { return }
    foreach ($line in Get-Content $Path) {
        $line = $line.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
            $eqIndex = $line.IndexOf('=')
            $key = $line.Substring(0, $eqIndex).Trim()
            $value = $line.Substring($eqIndex + 1).Trim()
            if (-not [System.Environment]::GetEnvironmentVariable($key)) {
                [System.Environment]::SetEnvironmentVariable($key, $value)
            }
        }
    }
}

function Get-ZtbConfig {
    Import-EnvFile -Path $EnvFile

    $cliMap = @{
        'client_id'     = $ClientId
        'client_secret' = $ClientSecret
        'vanity_domain' = $VanityDomain
        'airgap_site'   = $AirgapSite
    }
    $envMap = @{
        'client_id'     = 'ZSCALER_CLIENT_ID'
        'client_secret' = 'ZSCALER_CLIENT_SECRET'
        'vanity_domain' = 'ZSCALER_VANITY_DOMAIN'
        'airgap_site'   = 'ZSCALER_AIRGAP_SITE'
    }

    $config = @{}
    $missing = @()
    foreach ($key in @('client_id', 'client_secret', 'vanity_domain', 'airgap_site')) {
        $value = $cliMap[$key]
        if (-not $value) { $value = [System.Environment]::GetEnvironmentVariable($envMap[$key]) }
        if (-not $value) {
            $missing += "  --$($key -replace '_','-') / $($envMap[$key])"
        } else {
            $config[$key] = $value
        }
    }
    if ($missing.Count -gt 0) {
        Write-Host "ERROR: Missing credentials:" -ForegroundColor Red
        $missing | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        exit 1
    }
    $config['token_url'] = "https://$($config['vanity_domain']).zslogin.net/oauth2/v1/token"
    $config['api_base'] = "https://$($config['airgap_site'])-api.goairgap.com"
    return $config
}

# ── API client ───────────────────────────────────────────────────────────

class ApiClient {
    [string]$Cid
    [string]$Secret
    [string]$TokenUrl
    [string]$Base
    [string]$Token
    [double]$Expiry

    ApiClient([hashtable]$config) {
        $this.Cid = $config['client_id']
        $this.Secret = $config['client_secret']
        $this.TokenUrl = $config['token_url']
        $this.Base = $config['api_base']
        $this.Token = $null
        $this.Expiry = 0
    }

    [void] EnsureToken() {
        $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        if ($this.Token -and $now -lt ($this.Expiry - $script:TOKEN_REFRESH_MARGIN)) { return }
        $body = @{
            client_id     = $this.Cid
            client_secret = $this.Secret
            grant_type    = 'client_credentials'
            audience      = $script:TOKEN_AUDIENCE
        }
        $resp = Invoke-RestMethod -Uri $this.TokenUrl -Method Post `
            -ContentType 'application/x-www-form-urlencoded' -Body $body -ErrorAction Stop
        $this.Token = $resp.access_token
        $expiresIn = if ($resp.expires_in) { $resp.expires_in } else { 3600 }
        $this.Expiry = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $expiresIn
    }

    [object] Request([string]$method, [string]$path, [object]$data) {
        $this.EnsureToken()
        $url = "$($this.Base)$path"
        $headers = @{ 'Authorization' = "Bearer $($this.Token)"; 'Accept' = 'application/json' }
        $params = @{ Uri = $url; Method = $method; Headers = $headers; ContentType = 'application/json'; ErrorAction = 'Stop' }
        if ($null -ne $data) { $params['Body'] = ($data | ConvertTo-Json -Depth 10 -Compress) }
        try {
            return Invoke-RestMethod @params
        } catch {
            $code = 0; $msg = $_.Exception.Message
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            throw "HTTP $code on ${url}: $($msg.Substring(0, [Math]::Min(200, $msg.Length)))"
        }
    }

    [object] Get([string]$path) { return $this.Request('GET', $path, $null) }
    [object] Post([string]$path, [object]$data) { return $this.Request('POST', $path, $data) }
    [object] Post([string]$path) { return $this.Request('POST', $path, $null) }
}

# ── Data helpers ─────────────────────────────────────────────────────────

function Get-Rows {
    param([object]$Response)
    if ($null -eq $Response) { return @() }
    if ($Response -is [array]) { return $Response }
    $inner = $Response
    if ($Response.PSObject -and $Response.PSObject.Properties.Name -contains 'result') { $inner = $Response.result }
    if ($null -eq $inner) { return @() }
    if ($inner -is [array]) { return $inner }
    if ($inner.PSObject -and $inner.PSObject.Properties.Name -contains 'rows') {
        if ($null -eq $inner.rows) { return @() }
        return @($inner.rows)
    }
    return @($inner)
}

function Get-ZtbGateways {
    param([ApiClient]$Api)
    $rows = Get-Rows ($Api.Get("/api/v2/Gateway/"))
    $siteMap = @{}
    try {
        foreach ($s in Get-Rows ($Api.Get("/api/v2/Site/"))) {
            $name = if ($s.name) { $s.name } else { 'unknown' }
            if ($s.clusters) {
                foreach ($cl in $s.clusters) {
                    if ($null -ne $cl.cluster_id) { $siteMap[$cl.cluster_id] = $name }
                }
            }
        }
    } catch {}

    $gateways = @()
    foreach ($gw in $rows) {
        $cid = $gw.cluster_id
        $gateways += [PSCustomObject]@{
            id              = if ($gw.gateway_id) { $gw.gateway_id } else { $gw.id }
            name            = if ($gw.gateway_name) { $gw.gateway_name } else { $gw.name }
            site_name       = if ($siteMap.ContainsKey($cid)) { $siteMap[$cid] } else { 'unknown' }
            cluster_id      = $cid
            running_version = if ($gw.running_version) { $gw.running_version } else { '' }
        }
    }
    return $gateways | Sort-Object site_name, name
}

function Resolve-ZtbVersion {
    param([ApiClient]$Api, [string]$VersionArg)
    $releases = Get-Rows ($Api.Get("/api/v2/Gateway/releases"))
    $releases = $releases | Sort-Object { $_.release_date } -Descending
    if ($releases.Count -eq 0) {
        Write-Host "ERROR: No releases available." -ForegroundColor Red; exit 1
    }
    if ($VersionArg -eq 'latest') { return $releases[0].version_number }
    $available = $releases | ForEach-Object { $_.version_number }
    if ($VersionArg -in $available) { return $VersionArg }
    Write-Host "ERROR: Version '$VersionArg' not found. Available: $($available -join ', ')" -ForegroundColor Red
    exit 1
}

function Compare-VersionLt {
    param([string]$a, [string]$b)
    $pa = [int[]]([regex]::Matches($a, '\d+') | ForEach-Object { $_.Value })
    $pb = [int[]]([regex]::Matches($b, '\d+') | ForEach-Object { $_.Value })
    $len = [Math]::Max($pa.Length, $pb.Length)
    for ($i = 0; $i -lt $len; $i++) {
        $va = if ($i -lt $pa.Length) { $pa[$i] } else { 0 }
        $vb = if ($i -lt $pb.Length) { $pb[$i] } else { 0 }
        if ($va -lt $vb) { return $true }
        if ($va -gt $vb) { return $false }
    }
    return $a -lt $b
}

function Select-ZtbGateways {
    param([array]$Gateways)
    if (-not $All -and -not $Site -and -not $Cluster -and -not $Gateway -and -not $BelowVersion) {
        Write-Host "ERROR: No selection. Use -All, -Site, -Cluster, -Gateway, or -BelowVersion" -ForegroundColor Red
        exit 1
    }
    $sel = @($Gateways)
    if (-not $All) {
        if ($Site) { $sel = @($sel | Where-Object { $_.site_name -like $Site }) }
        if ($Cluster) { $sel = @($sel | Where-Object { "$($_.cluster_id)" -eq $Cluster }) }
        if ($Gateway) {
            $names = $Gateway -split ',' | ForEach-Object { $_.Trim() }
            $sel = @($sel | Where-Object { $_.name -in $names })
        }
        if ($BelowVersion) {
            $sel = @($sel | Where-Object { $_.running_version -and (Compare-VersionLt $_.running_version $BelowVersion) })
        }
    }
    return $sel
}

# ── Download logic ───────────────────────────────────────────────────────

function Remove-OldImages {
    param([ApiClient]$Api, [string]$GwId, [string]$TargetVersion)
    try {
        $gwData = $Api.Get("/api/v2/Gateway/id/$GwId")
        if ($gwData.PSObject -and $gwData.PSObject.Properties.Name -contains 'result') {
            $gwData = $gwData.result
            if ($gwData -is [array] -and $gwData.Count -gt 0) { $gwData = $gwData[0] }
        }
        $running = if ($gwData.running_version) { $gwData.running_version } else { '' }
        $images = @()
        if ($gwData.sw_image_status -and $gwData.sw_image_status.images) { $images = @($gwData.sw_image_status.images) }
        foreach ($img in $images) {
            $v = if ($img.version) { $img.version } else { '' }
            if ($v -and $v -ne $running -and $v -ne $TargetVersion) {
                try { $Api.Post("/api/v2/Gateway/sw_image_update/id/$GwId", @{ action = 'delete'; version = $v }) | Out-Null } catch {}
            }
        }
    } catch {}
}

function Test-ImageDownloaded {
    param([ApiClient]$Api, [string]$GwId, [string]$TargetVersion)
    try {
        $gwData = $Api.Get("/api/v2/Gateway/id/$GwId")
        if ($gwData.PSObject -and $gwData.PSObject.Properties.Name -contains 'result') {
            $gwData = $gwData.result
            if ($gwData -is [array] -and $gwData.Count -gt 0) { $gwData = $gwData[0] }
        }
        if ($gwData.sw_image_status -and $gwData.sw_image_status.images) {
            foreach ($img in @($gwData.sw_image_status.images)) {
                if ($img.version -eq $TargetVersion -and $img.status -match '(?i)^(downloaded|completed)$') { return $true }
            }
        }
        if ($gwData.download_status -and $gwData.download_status.versions) {
            foreach ($ver in @($gwData.download_status.versions)) {
                if ($ver.version -eq $TargetVersion -and $ver.status -match '(?i)^(downloaded|completed)$') { return $true }
            }
        }
    } catch {}
    return $false
}

function Invoke-DownloadAndPoll {
    param([ApiClient]$Api, [string]$GwId, [string]$TargetVersion)
    $Api.Post("/api/v2/Gateway/sw_image_update/id/$GwId", @{ action = 'download'; version = $TargetVersion }) | Out-Null
    $deadline = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $script:DOWNLOAD_TIMEOUT
    while ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt $deadline) {
        if (Test-ImageDownloaded -Api $Api -GwId $GwId -TargetVersion $TargetVersion) { return $true }
        Start-Sleep -Seconds $script:POLL_INTERVAL
    }
    return $false
}

# ── Main ─────────────────────────────────────────────────────────────────

$config = Get-ZtbConfig
$api = [ApiClient]::new($config)

$target = Resolve-ZtbVersion -Api $api -VersionArg $Version
Write-Host "Target version: $target"

$gateways = Get-ZtbGateways -Api $api
$selected = Select-ZtbGateways -Gateways $gateways

$toProcess = @($selected | Where-Object { $_.running_version -ne $target })
$atTarget = @($selected | Where-Object { $_.running_version -eq $target })

if ($atTarget.Count -gt 0) { Write-Host "Skipping $($atTarget.Count) gateway(s) already at $target" }

if ($toProcess.Count -eq 0) { Write-Host "Nothing to download."; exit 0 }

Write-Host "Downloading firmware to $($toProcess.Count) gateway(s)..."

if ($DryRun) {
    for ($i = 0; $i -lt $toProcess.Count; $i++) {
        $gw = $toProcess[$i]
        Write-Host "  [$($i+1)/$($toProcess.Count)] $($gw.name) ($($gw.site_name), current: $($gw.running_version)) -- DRY RUN"
    }
    Write-Host "`nDry run complete. $($toProcess.Count) gateway(s) would be processed."
    exit 0
}

$downloaded = 0; $skippedCount = 0; $failedCount = 0

for ($i = 0; $i -lt $toProcess.Count; $i++) {
    $gw = $toProcess[$i]
    $label = "[$($i+1)/$($toProcess.Count)] $($gw.name)"
    $t0 = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

    if (Test-ImageDownloaded -Api $api -GwId $gw.id -TargetVersion $target) {
        Write-Host "  $label... skipped (already downloaded)"
        $skippedCount++
        continue
    }

    Write-Host -NoNewline "  $label... "
    try {
        Remove-OldImages -Api $api -GwId $gw.id -TargetVersion $target
        $ok = Invoke-DownloadAndPoll -Api $api -GwId $gw.id -TargetVersion $target
        $elapsed = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $t0
        if ($ok) {
            Write-Host "done ($($elapsed)s)"
            $downloaded++
        } else {
            Write-Host "TIMEOUT ($($elapsed)s)"
            $failedCount++
        }
    } catch {
        $elapsed = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $t0
        Write-Host "FAILED ($($elapsed)s) -- $($_.Exception.Message)"
        $failedCount++
    }
}

Write-Host "`nSummary: $downloaded downloaded, $skippedCount skipped, $failedCount failed"
