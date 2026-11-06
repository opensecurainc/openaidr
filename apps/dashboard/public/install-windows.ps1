param([string]$EnrollmentLink)

# Windows PowerShell 5.1 or PowerShell 7. Run as the signed-in user, without elevation.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-OpenAIDRSignature([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or -not $signature.TimeStamperCertificate -or
        $signature.SignerCertificate.Subject -notmatch '(^|,\s*)O=("OpenSecura, Inc\."|OpenSecura, Inc\.)(,|$)') {
        throw 'The OpenSecura signature or timestamp is invalid. Installation stopped.'
    }
}

function Get-OpenAIDRFile([string]$Url, [string]$Path) {
    Invoke-WebRequest -Uri $Url -OutFile $Path -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 600
}

function Expand-OpenAIDRInstaller([string]$Archive, [string]$Directory) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($Archive)
    try {
        if ($zip.Entries.Count -ne 1 -or $zip.Entries[0].FullName -cnotmatch
            '^OpenAIDR_\d{4}\.\d{1,2}\.\d{1,2}\+[a-f0-9]{7,40}_signed-[a-f0-9]{7,40}_x64-setup\.exe$') {
            throw 'The installer archive has unexpected contents.'
        }
        $installer = Join-Path $Directory 'OpenAIDR-setup.exe'
        [IO.Compression.ZipFileExtensions]::ExtractToFile($zip.Entries[0], $installer)
        return $installer
    } finally { $zip.Dispose() }
}

function Invoke-OpenAIDRBridge([string]$Sensor, [string]$Action, [hashtable]$Params) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Sensor
    $info.Arguments = 'desktop-bridge'
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = New-Object Text.UTF8Encoding($false)
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        # .NET Framework creates and flushes stdin using Console.InputEncoding at
        # process start. Suppress its BOM before any JSON reaches the sensor.
        $consoleEncoding = [Console]::InputEncoding
        try {
            [Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
            [void]$process.Start()
        } finally { [Console]::InputEncoding = $consoleEncoding }
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        $json = @{action=$Action; params=$Params} | ConvertTo-Json -Compress -Depth 5
        # ASCII JSON works with both the bundled Python Windows code page and UTF-8.
        $json = [regex]::Replace($json, '[^\x00-\x7f]', { param($match) '\u{0:x4}' -f [int][char]$match.Value })
        $inputBytes = [Text.Encoding]::UTF8.GetBytes($json)
        $process.StandardInput.BaseStream.Write($inputBytes, 0, $inputBytes.Length)
        $process.StandardInput.BaseStream.Close()
        if (-not $process.WaitForExit(180000)) {
            $process.Kill()
            throw 'OpenAIDR did not respond. Open the app to check the connection before trying again.'
        }
        if ($process.ExitCode -ne 0) { throw 'OpenAIDR could not complete the request. Open the app to check the connection.' }
        try { $result = $output.GetAwaiter().GetResult() | ConvertFrom-Json } catch { $result = $null }
        if (-not $result -or $result.ok -ne $true -or -not $result.data) {
            throw 'Could not confirm the connection. Check the link in OpenAIDR before retrying. Use the app for private server certificates.'
        }
        return $result.data
    } finally { $process.Dispose() }
}

function Confirm-OpenAIDR([string]$Message) {
    if ((Read-Host "$Message Type YES to continue") -cne 'YES') { throw 'Installation cancelled. Any completed installation is kept.' }
}

function Find-OpenAIDRApp {
    $roots = @('OpenAIDR\app', 'OpenAIDR', 'OpenAIDR Sensor')
    $apps = @($roots | ForEach-Object { Join-Path $env:LOCALAPPDATA "$_\openaidr-desktop.exe" } |
        Where-Object { Test-Path -LiteralPath $_ })
    if ($apps.Count -gt 1) { throw 'More than one OpenAIDR app is installed. Keep one installed copy before continuing.' }
    if ($apps.Count -eq 1) { return $apps[0] }
    $registered = @(Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -match '^OpenAIDR( Sensor)?$' })
    if ($registered.Count) { throw 'A custom or machine-wide OpenAIDR installation exists. Open that app to connect this device.' }
}

function Install-OpenAIDR {
    $app = Find-OpenAIDRApp
    if (-not $app) {
        Confirm-OpenAIDR 'Download and install OpenAIDR for your Windows account?'
        $temporary = Join-Path ([IO.Path]::GetTempPath()) ('openaidr-install-' + [Guid]::NewGuid())
        [void][IO.Directory]::CreateDirectory($temporary)
        try {
            Write-Host 'Downloading OpenAIDR...'
            $archive = Join-Path $temporary 'OpenAIDR.zip'
            Get-OpenAIDRFile 'https://releases.opensecura.ai/openaidr/latest/OpenAIDR-windows-x64.zip' $archive
            $installer = Expand-OpenAIDRInstaller $archive $temporary
            Assert-OpenAIDRSignature $installer
            $process = Start-Process -FilePath $installer -ArgumentList '/S' -Wait -PassThru
            if ($process.ExitCode -ne 0) { throw 'Installation failed. Check Windows security settings and open the installer manually.' }
        } finally { Remove-Item -LiteralPath $temporary -Recurse -Force }
        $app = Find-OpenAIDRApp
        if (-not $app) { throw 'Cannot find the installed app. Open OpenAIDR from the Start menu.' }
    }
    Assert-OpenAIDRSignature $app
    return $app
}

function Connect-OpenAIDR([string]$App, [string]$Link) {
    $root = Split-Path -Parent $App
    $sensors = @('runtime\openaidr.exe', 'runtime\openaidr-sensor.exe', 'sensor\openaidr.exe', 'sensor\openaidr-sensor.exe')
    $sensor = $sensors | ForEach-Object { Join-Path $root $_ } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $sensor) { throw 'Cannot find the bundled sensor. Open OpenAIDR to finish setup.' }
    Assert-OpenAIDRSignature $sensor
    $state = Invoke-OpenAIDRBridge $sensor 'status' @{}
    if ($state.enrolled -isnot [bool]) { throw 'Cannot verify the existing enrollment. Open OpenAIDR to check its status.' }
    if ($state.enrolled) {
        Start-Process -FilePath $App
        Write-Host 'OpenAIDR is already enrolled. The existing connection is kept.'
        return
    }
    $preview = Invoke-OpenAIDRBridge $sensor 'enrollment.preview' @{link=$Link}
    if (-not $preview.tenant.id -or -not $preview.tenant.name -or -not $preview.server_url) {
        throw 'The enrollment preview is incomplete. Open OpenAIDR to connect.'
    }
    Confirm-OpenAIDR "Connect this device to $($preview.tenant.name) at $($preview.server_url)? OpenAIDR will set up its sensor and detected coding agents."
    $connected = Invoke-OpenAIDRBridge $sensor 'enrollment.connect' @{link=$Link; tenant_id=$preview.tenant.id}
    if ($connected.enrolled -ne $true) { throw 'Enrollment could not be confirmed. Check the app before trying again.' }
    try { Start-Process -FilePath $App } catch { throw 'Enrollment succeeded. Open OpenAIDR from the Start menu to finish setup. Do not reuse the link.' }
    Write-Host 'This device is enrolled. OpenAIDR is opening to finish setup. Check its status, then restart coding-agent sessions.'
}

function Start-OpenAIDRInstall([string]$Link) {
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or
        $env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or $env:PROCESSOR_ARCHITEW6432) {
        throw 'Use 64-bit PowerShell on Windows x64.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this command as your normal Windows account, without Run as administrator.'
    }
    if ($Link.Length -gt 4096 -or $Link -cnotmatch '^https://[^\s?#@\\]+/enroll#token=oaet_[A-Za-z0-9_-]{43}$') {
        throw 'Supply the complete HTTPS enrollment link from your administrator.'
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $app = Install-OpenAIDR
    Connect-OpenAIDR $app $Link
}

# Dot sourcing loads the functions for deterministic tests without installing anything.
if ($MyInvocation.InvocationName -ne '.') { Start-OpenAIDRInstall $EnrollmentLink }
