<#
.SYNOPSIS
    Prepare a Windows host to publish single applications (RemoteApp) to
    OpenIDX, and/or report its published apps + posture as JSON.

.DESCRIPTION
    OpenIDX delivers individual Windows applications to the browser over RDP
    (RemoteApp) instead of a full desktop. This script is the host side:

      -Report   Enumerate published apps (TSAppAllowList) + installed apps
                (App Paths, Start Menu, AppX) and the host's security posture,
                and print a JSON document. Paste it into the OpenIDX console
                ("Windows Apps -> Import from host") or let the OpenIDX agent
                post it. Read-only.

      -Publish  Enable RDP with NLA and register the applications in
                -AppsJson under TSAppAllowList so they can launch as RemoteApp,
                with the allowlist ENFORCED. Idempotent.

    Security stance: this script NEVER sets fAllowUnlistedRemotePrograms.
    That flag lets any program (including cmd.exe) run as a RemoteApp, which
    defeats the whole point of an allowlist. -Report flags it as a finding when
    another tool has enabled it; the OpenIDX console then shows a warning.

    Requires an elevated (Administrator) session for -Publish. Windows 10/11
    Pro/Enterprise or Windows Server. On desktop editions only one concurrent
    RemoteApp session is available; use a host pool in OpenIDX to scale.

.PARAMETER Report
    Print the JSON posture + app report and exit. Read-only.

.PARAMETER Publish
    Configure RDP/NLA and publish the apps in -AppsJson.

.PARAMETER AppsJson
    JSON array of apps to publish, e.g.
      '[{"alias":"SSMS","name":"SQL Server Management Studio","path":"C:\\...\\Ssms.exe"}]'
    Each item: alias (required), name (required), path (required),
    args (optional), working_dir (optional).

.EXAMPLE
    .\Prepare-OpenIDXAppHost.ps1 -Report

.EXAMPLE
    .\Prepare-OpenIDXAppHost.ps1 -Publish -AppsJson (Get-Content apps.json -Raw)
#>
[CmdletBinding(DefaultParameterSetName = 'Report')]
param(
    [Parameter(ParameterSetName = 'Report')]
    [switch]$Report,

    [Parameter(ParameterSetName = 'Publish', Mandatory = $true)]
    [switch]$Publish,

    [Parameter(ParameterSetName = 'Publish', Mandatory = $true)]
    [string]$AppsJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TSKey       = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server'
$AllowKey    = "$TSKey\TSAppAllowList"
$AppsKey     = "$AllowKey\Applications"
$TSControl   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$RdpTcpKey   = "$TSControl\WinStations\RDP-Tcp"
$PolicyTSKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'

# Safely read a property from a PSCustomObject (StrictMode-safe), with a default.
function Get-Prop($obj, [string]$Name, $Default = '') {
    if ($null -ne $obj -and ($obj.PSObject.Properties.Name -contains $Name)) {
        return $obj.$Name
    }
    return $Default
}

function Get-DwordOrNull([string]$Path, [string]$Name) {
    try {
        $v = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return [int]$v.$Name
    } catch { return $null }
}

function Get-HostPosture {
    $denyTS   = Get-DwordOrNull $TSControl 'fDenyTSConnections'
    $nla      = Get-DwordOrNull $RdpTcpKey 'UserAuthentication'
    $disabled = Get-DwordOrNull $AllowKey  'fDisabledAllowList'
    $unlisted = Get-DwordOrNull $PolicyTSKey 'fAllowUnlistedRemotePrograms'

    $edition = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { '' }

    # allowlist is enforced when it is NOT disabled (fDisabledAllowList=0/absent)
    # AND unlisted programs are not allowed.
    $allowlistEnforced = (($null -eq $disabled) -or ($disabled -eq 0)) -and (($null -eq $unlisted) -or ($unlisted -eq 0))

    return [ordered]@{
        os_edition                     = $edition
        nla_enabled                    = ($nla -eq 1)
        allow_unlisted_remote_programs = ($unlisted -eq 1)
        allowlist_enforced             = [bool]$allowlistEnforced
        rdp_enabled                    = ($denyTS -eq 0)
    }
}

# Read the published RemoteApps from TSAppAllowList\Applications.
function Get-PublishedApps {
    $apps = @()
    if (-not (Test-Path $AppsKey)) { return $apps }
    Get-ChildItem $AppsKey | ForEach-Object {
        $p = Get-ItemProperty $_.PSPath
        $name = if ($p.PSObject.Properties.Name -contains 'Name') { $p.Name } else { $_.PSChildName }
        $path = if ($p.PSObject.Properties.Name -contains 'Path') { $p.Path } else { '' }
        $iconB64 = ''
        if ($path -and (Test-Path $path)) {
            $iconB64 = Get-IconB64 $path
        }
        $apps += [ordered]@{
            alias       = $_.PSChildName
            name        = [string]$name
            path        = [string]$path
            args        = ''
            working_dir = ''
            icon_b64    = $iconB64
            source      = 'tsapp'
        }
    }
    return $apps
}

# Best-effort: extract the executable's icon as a small base64 PNG (<= a few KB).
function Get-IconB64([string]$exePath) {
    try {
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        $icon = [System.Drawing.Icon]::ExtractAssociatedIcon($exePath)
        if ($null -eq $icon) { return '' }
        $bmp = $icon.ToBitmap()
        $ms  = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $bytes = $ms.ToArray()
        $ms.Dispose(); $bmp.Dispose(); $icon.Dispose()
        if ($bytes.Length -gt 32768) { return '' }  # cap matches the server (maxAppIconBytes)
        return [Convert]::ToBase64String($bytes)
    } catch { return '' }
}

# Installed apps not (yet) published: App Paths + Start Menu shortcuts + AppX.
# These import as "unverified" so an admin can promote and publish them.
function Get-InstalledApps {
    $apps = @()
    $seen = @{}

    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths')) {
        if (-not (Test-Path $root)) { continue }
        Get-ChildItem $root | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            $exe = if ($p.PSObject.Properties.Name -contains '(default)') { $p.'(default)' } else { '' }
            $alias = [System.IO.Path]::GetFileNameWithoutExtension($_.PSChildName)
            if ($exe -and -not $seen.ContainsKey($alias)) {
                $seen[$alias] = $true
                $apps += [ordered]@{
                    alias = $alias; name = $alias; path = [string]$exe
                    args = ''; working_dir = ''; icon_b64 = ''; source = 'app_paths'
                }
            }
        }
    }

    foreach ($menu in @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs",
                        "$env:AppData\Microsoft\Windows\Start Menu\Programs")) {
        if (-not (Test-Path $menu)) { continue }
        Get-ChildItem -Path $menu -Filter *.lnk -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $sh = New-Object -ComObject WScript.Shell
                $lnk = $sh.CreateShortcut($_.FullName)
                $target = $lnk.TargetPath
                $name = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
                if ($target -and $target.ToLower().EndsWith('.exe') -and -not $seen.ContainsKey($name)) {
                    $seen[$name] = $true
                    $apps += [ordered]@{
                        alias = $name; name = $name; path = [string]$target
                        args = [string]$lnk.Arguments; working_dir = [string]$lnk.WorkingDirectory
                        icon_b64 = ''; source = 'start_menu'
                    }
                }
            } catch { }
        }
    }

    try {
        Get-AppxPackage -ErrorAction SilentlyContinue | ForEach-Object {
            $name = $_.Name
            if (-not $seen.ContainsKey($name)) {
                $seen[$name] = $true
                $apps += [ordered]@{
                    alias = $name; name = $name
                    path = "shell:AppsFolder\$($_.PackageFamilyName)!App"
                    args = ''; working_dir = ''; icon_b64 = ''; source = 'appx'
                }
            }
        }
    } catch { }

    return $apps
}

function Invoke-Report {
    $posture = Get-HostPosture
    $published = @(Get-PublishedApps)
    $installed = @(Get-InstalledApps)

    if ($posture.allow_unlisted_remote_programs) {
        Write-Warning 'fAllowUnlistedRemotePrograms is ENABLED: any program can run as a RemoteApp (including cmd.exe). OpenIDX will flag this host. Disable it and rely on the TSAppAllowList allowlist.'
    }

    $report = [ordered]@{
        host = [ordered]@{
            os_edition                     = $posture.os_edition
            nla_enabled                    = $posture.nla_enabled
            allow_unlisted_remote_programs = $posture.allow_unlisted_remote_programs
            allowlist_enforced             = $posture.allowlist_enforced
        }
        apps = @($published + $installed)
    }
    # Depth 5 covers host{} + apps[]{} nesting.
    $report | ConvertTo-Json -Depth 5
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Publishing requires an elevated (Administrator) PowerShell session.'
    }
}

function Set-DwordProperty([string]$Path, [string]$Name, [int]$Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

function Invoke-Publish {
    Assert-Admin

    $apps = $AppsJson | ConvertFrom-Json
    if ($null -eq $apps) { throw 'AppsJson did not parse to an array.' }

    # 1. Enable RDP + require NLA.
    Set-DwordProperty $TSControl 'fDenyTSConnections' 0
    Set-DwordProperty $RdpTcpKey 'UserAuthentication' 1

    # 2. Enforce the allowlist. Explicitly enforce it (fDisabledAllowList=0) and
    #    NEVER set fAllowUnlistedRemotePrograms. If a prior tool enabled unlisted
    #    programs, refuse silently-continuing: warn loudly.
    if (-not (Test-Path $AllowKey)) { New-Item -Path $AllowKey -Force | Out-Null }
    Set-DwordProperty $AllowKey 'fDisabledAllowList' 0
    $unlisted = Get-DwordOrNull $PolicyTSKey 'fAllowUnlistedRemotePrograms'
    if ($unlisted -eq 1) {
        Write-Warning 'fAllowUnlistedRemotePrograms=1 is set elsewhere (likely group policy). The allowlist below is bypassed until it is cleared. OpenIDX will flag this host.'
    }

    # 3. Register each app under TSAppAllowList\Applications\<alias>. Idempotent.
    if (-not (Test-Path $AppsKey)) { New-Item -Path $AppsKey -Force | Out-Null }
    foreach ($app in $apps) {
        $alias = ([string](Get-Prop $app 'alias') -replace '^\|\|', '').Trim()
        $path  = [string](Get-Prop $app 'path')
        $name  = [string](Get-Prop $app 'name' $alias)
        if (-not $alias -or -not $path) {
            Write-Warning "Skipping app with missing alias/path: $($app | ConvertTo-Json -Compress)"
            continue
        }
        $key = "$AppsKey\$alias"
        if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
        New-ItemProperty -Path $key -Name 'Name' -Value $name -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name 'Path' -Value $path -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name 'CommandLineSetting' -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $key -Name 'RequiredCommandLine' -Value ([string](Get-Prop $app 'args')) -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name 'IconPath' -Value $path -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $key -Name 'ShowInTSWA' -Value 1 -PropertyType DWord -Force | Out-Null
        Write-Host "Published RemoteApp: $alias -> $path"
    }

    Write-Host ''
    Write-Host 'Done. Now run with -Report and import the JSON into OpenIDX (Windows Apps -> Import from host).'
    Write-Host 'Hardening reminder: run published apps on a dedicated low-privilege host and constrain them with AppLocker/WDAC — a published app can still break out via File Open/Save dialogs. See docs/architecture/windows-app-delivery.md.'
}

switch ($PSCmdlet.ParameterSetName) {
    'Publish' { Invoke-Publish }
    default   { Invoke-Report }
}
