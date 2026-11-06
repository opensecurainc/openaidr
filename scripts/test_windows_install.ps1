# Exercise the published NSIS installer on a fresh hosted runner.
param(
  [Parameter(Mandatory = $true)][string]$Artifacts,
  [Parameter(Mandatory = $true)][string]$Output
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'Run this test only on a disposable GitHub-hosted Windows runner.'
}
$installRoot = Join-Path $env:LOCALAPPDATA 'OpenAIDR\app'
if (Test-Path (Split-Path $installRoot)) { throw 'The test requires a fresh OpenAIDR profile.' }
$installers = @(Get-ChildItem $Artifacts -Recurse -Filter '*_x64-setup.exe')
if ($installers.Count -ne 1) { throw 'Expected exactly one Windows installer.' }
New-Item -ItemType Directory -Force $Output | Out-Null
$signature = Get-AuthenticodeSignature $installers[0].FullName
if ($signature.Status -notin @('Valid', 'NotSigned')) {
  throw "Installer signature is invalid: $($signature.Status)"
}
if ($signature.Status -eq 'NotSigned') {
  Write-Warning 'This installer has no verified publisher. SmartScreen and company policy can block it.'
}
$installer = Start-Process $installers[0].FullName -ArgumentList '/S' -PassThru
if (-not $installer.WaitForExit(180000)) { $installer.Kill(); throw 'Installer timed out.' }
if ($installer.ExitCode -ne 0) { throw "Installer failed: $($installer.ExitCode)" }
$executable = Join-Path $installRoot 'openaidr-desktop.exe'
$sensor = Join-Path $installRoot 'runtime\openaidr.exe'
if (-not (Test-Path $executable) -or -not (Test-Path $sensor)) {
  throw 'Installed desktop or bundled sensor is missing.'
}
$build = & $sensor build-info | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or $build.source_commit -ne $env:GITHUB_SHA) {
  throw 'The installed sensor cannot run or does not match this build.'
}
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$app = Start-Process $executable -PassThru
try {
  $deadline = [DateTime]::UtcNow.AddSeconds(90)
  $found = $false
  while ([DateTime]::UtcNow -lt $deadline) {
    $app.Refresh()
    if ($app.HasExited) { throw "App exited before setup appeared: $($app.ExitCode)" }
    if ($app.MainWindowHandle -ne [IntPtr]::Zero) {
      $window = [System.Windows.Automation.AutomationElement]::FromHandle($app.MainWindowHandle)
      $condition = [System.Windows.Automation.PropertyCondition]::new(
        [System.Windows.Automation.AutomationElement]::NameProperty, 'Continue for free')
      $control = $window.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
      if ($null -ne $control) { $found = $true; break }
    }
    Start-Sleep -Seconds 1
  }
  if (-not $found) { throw 'The packaged app did not render its first-run controls.' }
  @{
    first_run_visible = $true
    installer_signature = $signature.Status.ToString()
    version = $build.version
    source_commit = $build.source_commit
  } | ConvertTo-Json | Set-Content (Join-Path $Output 'result.json')
} finally {
  if (-not $app.HasExited) { taskkill /PID $app.Id /T /F | Out-Null }
  $logs = Join-Path $env:LOCALAPPDATA 'com.opensecura.openaidr.sensor\logs'
  if (Test-Path $logs) { Copy-Item "$logs\*.log" $Output -ErrorAction SilentlyContinue }
}
$uninstaller = Join-Path $installRoot 'uninstall.exe'
$remove = Start-Process $uninstaller -ArgumentList '/S' -PassThru
if (-not $remove.WaitForExit(120000)) { $remove.Kill(); throw 'Uninstaller timed out.' }
if ($remove.ExitCode -ne 0) { throw "Uninstaller failed: $($remove.ExitCode)" }
$deadline = [DateTime]::UtcNow.AddSeconds(60)
while ((Test-Path $executable) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Seconds 1 }
if (Test-Path $executable) { throw 'Uninstall left the desktop executable installed.' }
Write-Output 'Windows installation, first launch, and removal passed.'
