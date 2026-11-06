# Invoked only by the native updater with fixed operations and local paths.
$ErrorActionPreference = 'Stop'
$inputData = $env:OPENAIDR_UPDATE_INPUT | ConvertFrom-Json
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$sections = [System.Security.AccessControl.AccessControlSections]'Owner, Access'

function Account-Sid([string]$Identity) {
  if ($Identity -eq $sid) { return $sid }
  try { ([Security.Principal.NTAccount]$Identity).Translate([Security.Principal.SecurityIdentifier]).Value }
  catch { '' }
}

function Check-PrivatePath([string]$Path) {
  $item = Get-Item -LiteralPath $Path -Force
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Update paths cannot be links.' }
  $acl = Get-Acl -LiteralPath $Path
  $type = [System.Security.Principal.SecurityIdentifier]
  $rules = @($acl.GetAccessRules($true, $true, $type))
  if ($acl.GetOwner($type).Value -ne $sid -or -not $rules.Count) { throw 'Update data must belong to this account.' }
  foreach ($rule in $rules) {
    if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -ne $sid) {
      throw 'Update data must be private to this account.'
    }
  }
}

switch ($inputData.operation) {
  'directory' {
    $path = [string]$inputData.path
    # The parent is the existing per-user sensor data location. Reject links
    # before creating the private updater child, without changing its ACL.
    $parent = [IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($path))
    while ($null -ne $parent) {
      if ($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Update paths cannot be links.'
      }
      $parent = $parent.Parent
    }
    if (-not (Test-Path -LiteralPath $path)) {
      $acl = [System.Security.AccessControl.DirectorySecurity]::new()
      $acl.SetSecurityDescriptorSddlForm("O:${sid}D:P(A;OICI;FA;;;${sid})", $sections)
      [IO.Directory]::CreateDirectory($path, $acl) | Out-Null
    }
    Check-PrivatePath $path
  }
  'identity' { Check-PrivatePath ([string]$inputData.path) }
  'private-file' {
    $path = [string]$inputData.path
    $item = Get-Item -LiteralPath $path -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw 'The private update file is unsafe.'
    }
    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetSecurityDescriptorSddlForm("O:${sid}D:P(A;;FA;;;${sid})", $sections)
    [IO.File]::SetAccessControl($path, $acl)
    Check-PrivatePath $path
  }
  'signature' {
    $signature = Get-AuthenticodeSignature -LiteralPath ([string]$inputData.path)
    if ($signature.Status -ne 'Valid' -or -not $signature.TimeStamperCertificate -or
        $signature.SignerCertificate.Subject -notlike '*O="OpenSecura, Inc."*') {
      throw 'The installer does not have a valid timestamped OpenSecura signature.'
    }
  }
  'schedule' {
    $name = "OpenAIDR update $sid"
    $executable = [string]$inputData.path
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    $ownerDirectory = [IO.Path]::GetFullPath([string]$inputData.directory)
    if ($inputData.previous_directory) {
      $previousDirectory = [IO.Path]::GetFullPath([string]$inputData.previous_directory)
      $local = [Environment]::GetFolderPath('LocalApplicationData')
      $allowed = @((Join-Path $local 'OpenAIDR Sensor\desktop-update'),
                   (Join-Path $local 'OpenAIDR\migration'),
                   (Join-Path $local 'OpenAIDR\data\desktop-update'))
      if ($ownerDirectory -notin $allowed -or $previousDirectory -notin $allowed) {
        throw 'Invalid Windows migration schedule locations.'
      }
      Check-PrivatePath $ownerDirectory
      Check-PrivatePath $previousDirectory
      if ($task -and [IO.Path]::GetDirectoryName($task.Actions[0].Execute) -eq $previousDirectory) {
        $ownerDirectory = $previousDirectory
      }
    }
    if ($task) {
      $actions = @($task.Actions)
      $triggers = @($task.Triggers)
      $repeats = @($triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskTimeTrigger' })
      $logons = @($triggers | Where-Object { $_.CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger' })
      if ($actions.Count -eq 1 -and $actions[0].Execute -eq $executable -and
          $actions[0].Arguments -eq '--update-worker' -and
          $actions[0].WorkingDirectory -eq [IO.Path]::GetDirectoryName($executable) -and
          $triggers.Count -eq 2 -and $repeats.Count -eq 1 -and $logons.Count -eq 1 -and
          $repeats[0].Repetition.Interval -eq 'PT5M' -and -not $repeats[0].Repetition.Duration -and
          $repeats[0].Enabled -and -not $repeats[0].EndBoundary -and
          $logons[0].Enabled -and -not $logons[0].EndBoundary -and (Account-Sid $logons[0].UserId) -eq $sid -and
          (Account-Sid $task.Principal.UserId) -eq $sid -and
          $task.Principal.LogonType -eq 'Interactive' -and $task.Principal.RunLevel -eq 'Limited' -and
          $task.Settings.Enabled -and $task.Settings.MultipleInstances -eq 'IgnoreNew' -and
          $task.Settings.StartWhenAvailable -and -not $task.Settings.DisallowStartIfOnBatteries -and
          -not $task.Settings.StopIfGoingOnBatteries -and $task.Settings.ExecutionTimeLimit -eq 'PT20M') { return }
      # An unrelated installation's registration must not be overwritten.
      if ($actions.Count -ne 1 -or $actions[0].Arguments -ne '--update-worker' -or
          [IO.Path]::GetDirectoryName($actions[0].Execute) -ne $ownerDirectory -or
          (Account-Sid $task.Principal.UserId) -ne $sid -or
          $task.Principal.LogonType -ne 'Interactive' -or $task.Principal.RunLevel -ne 'Limited' -or
          [IO.Path]::GetFileName($actions[0].Execute) -notmatch '^worker-[a-f0-9]{40}\.exe$') {
        throw 'Another OpenAIDR installation owns the update schedule.'
      }
    }
    $action = New-ScheduledTaskAction -Execute $executable -Argument '--update-worker' `
      -WorkingDirectory ([IO.Path]::GetDirectoryName($executable))
    $triggers = @(
      (New-ScheduledTaskTrigger -AtLogOn -User $sid),
      (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 5))
    )
    $triggers[1].Repetition.Duration = ''
    $principal = New-ScheduledTaskPrincipal -UserId $sid -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
      -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 20)
    Register-ScheduledTask -TaskName $name -Action $action -Trigger $triggers `
      -Principal $principal -Settings $settings -Force | Out-Null
  }
  'remove' {
    $name = "OpenAIDR update $sid"
    $task = Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
    if ($task) {
      $actions = @($task.Actions)
      if ($actions.Count -ne 1 -or $actions[0].Execute -ne [string]$inputData.path) {
        throw 'Another OpenAIDR installation owns the update schedule.'
      }
      Stop-ScheduledTask -TaskName $name
      Unregister-ScheduledTask -TaskName $name -Confirm:$false
    }
  }
  default { throw 'Unsupported update operation.' }
}
# A missing task is a successful, repeatable removal. PowerShell otherwise
# inherits the failed lookup status even when SilentlyContinue handled it.
exit 0
