$ErrorActionPreference = 'Stop'
. "$PSScriptRoot/../apps/dashboard/public/install-windows.ps1"

function Assert($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Action, [string]$Message) {
    $caught = $null
    try { & $Action } catch { $caught = $_ }
    Assert ($null -ne $caught) "Expected failure: $Message"
    Assert ($caught.Exception.Message -match $Message) "Unexpected failure: $caught"
}
function Test-Case([string]$Name, [scriptblock]$Action) {
    & $Action
    Write-Host "PASS: $Name"
}

Test-Case 'Valid OpenSecura signatures require a trusted timestamp and exact publisher' {
    function Get-AuthenticodeSignature { return $signature }
    foreach ($subject in @('CN=OpenSecura, O="OpenSecura, Inc.", C=US', 'CN=OpenSecura, O=OpenSecura, Inc.')) {
        $signature = [pscustomobject]@{ Status='Valid'; TimeStamperCertificate='timestamp'; SignerCertificate=[pscustomobject]@{Subject=$subject} }
        Assert-OpenAIDRSignature 'app.exe'
    }
    foreach ($case in @('invalid', 'timestamp', 'publisher')) {
        $signature = [pscustomobject]@{ Status='Valid'; TimeStamperCertificate='timestamp'; SignerCertificate=[pscustomobject]@{Subject='O="OpenSecura, Inc.", C=US'} }
        if ($case -eq 'invalid') { $signature.Status = 'HashMismatch' }
        if ($case -eq 'timestamp') { $signature.TimeStamperCertificate = $null }
        if ($case -eq 'publisher') { $signature.SignerCertificate.Subject = 'O="Not OpenSecura, Inc.", C=US' }
        Assert-Throws { Assert-OpenAIDRSignature 'app.exe' } 'signature or timestamp'
    }
}

Test-Case 'ZIP extraction rejects extra files and traversal' {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $directory = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
    [void][IO.Directory]::CreateDirectory($directory)
    try {
        $name = 'OpenAIDR_2026.10.19+73302c5_signed-73302c5_x64-setup.exe'
        foreach ($case in @('valid', 'traversal', 'extra')) {
            $archive = Join-Path $directory "$case.zip"
            $zip = [IO.Compression.ZipFile]::Open($archive, 'Create')
            $entryName = if ($case -eq 'traversal') { "../$name" } else { $name }
            [void]$zip.CreateEntry($entryName)
            if ($case -eq 'extra') { [void]$zip.CreateEntry('unexpected.dll') }
            $zip.Dispose()
            if ($case -eq 'valid') {
                $result = Expand-OpenAIDRInstaller $archive $directory
                Assert (Test-Path -LiteralPath $result) 'The installer was not extracted.'
            } else {
                Assert-Throws { Expand-OpenAIDRInstaller $archive $directory } 'unexpected contents'
            }
        }
    } finally { Remove-Item -LiteralPath $directory -Recurse -Force }
}

Test-Case 'Signature and installer failures prevent execution and enrollment' {
    function Find-OpenAIDRApp { return $null }
    function Confirm-OpenAIDR {}
    function Get-OpenAIDRFile {}
    function Expand-OpenAIDRInstaller { return 'installer.exe' }
    function Assert-OpenAIDRSignature { if ($failSignature) { throw 'bad signature' } }
    function Start-Process { $calls.Add('install'); return [pscustomobject]@{ExitCode=1} }
    foreach ($failSignature in @($true, $false)) {
        $calls = New-Object 'Collections.Generic.List[string]'
        Assert-Throws { Install-OpenAIDR } $(if ($failSignature) { 'bad signature' } else { 'Installation failed' })
        Assert ($calls.Count -eq $(if ($failSignature) { 0 } else { 1 })) 'Executed an unverified installer.'
    }
}

Test-Case 'Connect confirms the organization and consumes the link only once' {
    function Test-Path { return $true }
    function Assert-OpenAIDRSignature {}
    function Invoke-OpenAIDRBridge($Sensor, $Action, $Params) {
        $calls.Add($Action)
        if ($Action -eq 'status') { return [pscustomobject]@{enrolled=$alreadyEnrolled} }
        if ($Action -eq 'enrollment.preview') {
            return [pscustomobject]@{tenant=[pscustomobject]@{id='tenant'; name='Example'}; server_url='https://tenant.example'}
        }
        Assert ($Params.link -eq $link -and $Params.tenant_id -eq 'tenant') 'Incorrect enrollment request.'
        return [pscustomobject]@{enrolled=$true}
    }
    function Confirm-OpenAIDR($Message) {
        Assert ($Message -match 'Example at https://tenant.example') 'Organization was not shown.'
        Assert (($calls -join ',') -eq 'status,enrollment.preview') 'Link was consumed before confirmation.'
        if ($cancel) { throw 'cancelled' }
    }
    function Start-Process { $calls.Add('open'); if ($failOpen) { throw 'cannot open' } }
    $link = 'https://tenant.example/enroll#token=oaet_' + ('a' * 43)
    foreach ($case in @('fresh', 'existing', 'cancel', 'open-failure')) {
        $calls = New-Object 'Collections.Generic.List[string]'
        $alreadyEnrolled = $case -eq 'existing'
        $cancel = $case -eq 'cancel'
        $failOpen = $case -eq 'open-failure'
        if ($cancel -or $failOpen) {
            Assert-Throws { Connect-OpenAIDR (Join-Path ([IO.Path]::GetTempPath()) 'app.exe') $link } $(if ($cancel) { 'cancelled' } else { 'Enrollment succeeded' })
        } else { Connect-OpenAIDR (Join-Path ([IO.Path]::GetTempPath()) 'app.exe') $link }
        $expected = if ($alreadyEnrolled) { 'status,open' } elseif ($cancel) { 'status,enrollment.preview' } else { 'status,enrollment.preview,enrollment.connect,open' }
        Assert (($calls -join ',') -eq $expected) "Incorrect flow for $case"
    }
}

Test-Case 'Installed app and sensor are verified before bridge calls' {
    function Find-OpenAIDRApp { return 'existing.exe' }
    function Assert-OpenAIDRSignature { throw 'bad signature' }
    function Test-Path { return $true }
    function Invoke-OpenAIDRBridge { throw 'Must not call bridge' }
    Assert-Throws { Install-OpenAIDR } 'bad signature'
    Assert-Throws { Connect-OpenAIDR (Join-Path ([IO.Path]::GetTempPath()) 'app.exe') 'unused' } 'bad signature'
}

if ([Environment]::OSVersion.Platform -eq 'Win32NT') {
    Test-Case 'Native bridge transport sends Unicode JSON on stdin without secret arguments' {
        $directory = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString())
        [void][IO.Directory]::CreateDirectory($directory)
        try {
            $source = Join-Path $directory 'Bridge.cs'
            $executable = Join-Path $directory 'Bridge.exe'
            @'
using System;
using System.IO;
using System.Text;
class Bridge {
    static int Main(string[] args) {
        if (args.Length != 1 || args[0] != "desktop-bridge") return 1;
        string input;
        using (var source = Console.OpenStandardInput())
        using (var buffer = new MemoryStream()) {
            source.CopyTo(buffer);
            input = Encoding.UTF8.GetString(buffer.ToArray());
        }
        Console.Error.Write("Diagnostics must not be shown: " + input);
        string bytes = Convert.ToBase64String(Encoding.UTF8.GetBytes(input));
        Console.Write("{\"ok\":true,\"data\":{\"input\":\"" + bytes + "\"}}");
        return 0;
    }
}
'@ | Set-Content -LiteralPath $source
            & "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo "/out:$executable" $source
            Assert ($LASTEXITCODE -eq 0) 'Could not compile the native transport fixture.'
            $link = 'https://tenant.example/enroll#token=oaet_' + ('a' * 43)
            $tenant = 'organization-' + [char]0x03A9
            $consoleEncoding = [Console]::InputEncoding
            try {
                [Console]::InputEncoding = [Text.Encoding]::UTF8
                $result = Invoke-OpenAIDRBridge $executable 'enrollment.connect' @{link=$link; tenant_id=$tenant}
                Assert ([Console]::InputEncoding.GetPreamble().Length -eq 3) 'Transport changed the console encoding.'
            } finally { [Console]::InputEncoding = $consoleEncoding }
            $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($result.input))
            Assert (-not $json.Contains([char]0xFEFF)) 'Transport appended an encoding preamble to JSON.'
            try { $request = $json | ConvertFrom-Json } catch {
                throw "Invalid fixture JSON (UTF-8 base64): $($result.input)"
            }
            Assert ($request.params.link -eq $link -and $request.params.tenant_id -eq $tenant) 'Transport changed the enrollment request.'
        } finally { Remove-Item -LiteralPath $directory -Recurse -Force }
    }
}
