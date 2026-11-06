# Restrict the per-user OpenAIDR installation to the installing account, as
# the ADR installer does, so another local account cannot replace the
# executables the sensor is staged from. Links are rejected so the ACL change
# cannot be redirected elsewhere.
param(
  [Parameter(Mandatory = $true)]
  [string]$InstallRoot
)

$ErrorActionPreference = "Stop"
$root = [System.IO.DirectoryInfo]::new($InstallRoot)
if (-not $root.Exists -or ($root.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
  throw "OpenAIDR installation root is unavailable or unsafe."
}

$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$directorySddl = "O:${sid}D:P(A;OICI;FA;;;${sid})"
$fileSddl = "O:${sid}D:P(A;;FA;;;${sid})"
# Owner and access rules only: writing every section also writes the audit
# list, which needs SeSecurityPrivilege that a standard user lacks.
$sections = [System.Security.AccessControl.AccessControlSections]'Owner, Access'
$entries = @(
  [System.IO.Directory]::EnumerateFileSystemEntries(
    $root.FullName, "*", [System.IO.SearchOption]::AllDirectories
  )
)

foreach ($entryPath in $entries) {
  $attributes = [System.IO.File]::GetAttributes($entryPath)
  if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "OpenAIDR installation contains an unsupported link."
  }
  if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($directorySddl, $sections)
    [System.IO.Directory]::SetAccessControl($entryPath, $acl)
  } else {
    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetSecurityDescriptorSddlForm($fileSddl, $sections)
    [System.IO.File]::SetAccessControl($entryPath, $acl)
  }
}

$rootAcl = [System.Security.AccessControl.DirectorySecurity]::new()
$rootAcl.SetSecurityDescriptorSddlForm($directorySddl, $sections)
[System.IO.Directory]::SetAccessControl($root.FullName, $rootAcl)
