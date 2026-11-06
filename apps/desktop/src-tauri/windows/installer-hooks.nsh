; OpenAIDR NSIS hooks, following the ADR Windows installer.
;
; The app folder holds the desktop window and the one-directory sensor
; runtime in app\runtime\. Installing the background service copies it to
; %LOCALAPPDATA%\OpenAIDR\data\runtime\<version>-<build>, where a per-user
; Scheduled Task runs it. Uninstalling first removes the task and those copies,
; using the bundled sensor; if that fails, the uninstall stops before removing
; anything, as ADR's does. Sensor configuration, queued activity, and agent
; hook settings are kept for a later reinstall. An uninstall run as part of an
; upgrade (/UPDATE) leaves the task alone.

!include "FileFunc.nsh"

; GUI initialization updates the directory page. Silent updates also call the
; same function from PREINSTALL. Explicit custom install directories survive.
!define MUI_CUSTOMFUNCTION_GUIINIT OpenAIDRInstallDirectory
Function OpenAIDRInstallDirectory
  ; The shipped layout-1 worker passes /D with OpenAIDR/app. NSIS removes
  ; that slash before this hook runs. Repair only that exact raw argument;
  ; an explicitly selected OpenAIDRapp directory must remain a custom path.
  ${If} $INSTDIR == "$LOCALAPPDATA\OpenAIDRapp"
    Push $0
    Push $1
    System::Call 'kernel32::GetCommandLine() t .r0'
    StrLen $1 " /D=$LOCALAPPDATA\OpenAIDR/app"
    IntOp $1 0 - $1
    StrCpy $0 $0 "" $1
    ${If} $0 == " /D=$LOCALAPPDATA\OpenAIDR/app"
      ; Tauri creates the output directory before PREINSTALL. Remove it only
      ; when empty; keep any files left by a previous failed migration.
      SetOutPath "$TEMP"
      RMDir "$INSTDIR"
      StrCpy $INSTDIR "$LOCALAPPDATA\OpenAIDR\app"
    ${EndIf}
    Pop $1
    Pop $0
  ${EndIf}
  ${If} $INSTDIR == "$LOCALAPPDATA\OpenAIDR"
    StrCpy $INSTDIR "$LOCALAPPDATA\OpenAIDR\app"
  ${EndIf}
  ; A normal upgrade offers to run the registered uninstaller before copying
  ; files. That uninstaller refuses a pending migration. Re-enter this signed
  ; installer in its existing passive update mode before reaching that page.
  ; Preserve all original arguments, including a final /D and /NS.
  ${IfNot} ${Silent}
  ${AndIf} $INSTDIR == "$LOCALAPPDATA\OpenAIDR\app"
  ${AndIfNot} ${FileExists} "$LOCALAPPDATA\OpenAIDR\openaidr-desktop.exe"
  ${AndIf} ${FileExists} "$LOCALAPPDATA\OpenAIDR\migration\desktop-update.json"
  ${AndIfNot} ${FileExists} "$LOCALAPPDATA\OpenAIDR\migration\complete"
    Push $0
    Push $1
    ClearErrors
    ${GetOptions} $CMDLINE "/UPDATE" $0
    ${If} ${Errors}
      ${GetParameters} $1
      HideWindow
      ClearErrors
      ExecWait '"$EXEPATH" /P /UPDATE $1' $0
      ${If} ${Errors}
        MessageBox MB_OK|MB_ICONSTOP "OpenAIDR could not start installation recovery. Reopen the installer to retry."
        StrCpy $0 1
      ${EndIf}
      SetErrorLevel $0
      Quit
    ${EndIf}
    Pop $1
    Pop $0
  ${EndIf}
FunctionEnd

!macro NSIS_HOOK_PREINSTALL
  Call OpenAIDRInstallDirectory
  ${If} $INSTDIR == "$LOCALAPPDATA\OpenAIDR\app"
  ${AndIf} ${FileExists} "$LOCALAPPDATA\OpenAIDR\openaidr-desktop.exe"
    SetOutPath "$TEMP"
    RMDir "$INSTDIR"
    SetErrorLevel 3
    Abort "Open the existing OpenAIDR app and use its in-app updater to migrate this installation."
  ${EndIf}
  SetOutPath $INSTDIR
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\harden-installation.ps1" -InstallRoot "$INSTDIR"'
  Pop $0
  Pop $1
  ${If} $0 != 0
    DetailPrint "OpenAIDR could not secure its installation directory: $1"
    Abort "OpenAIDR could not secure its installation directory."
  ${EndIf}
  ; Tauri preserves shortcuts during /UPDATE, but its built-in repair assumes
  ; the installation directory did not change. Retarget only our old links.
  ${If} $INSTDIR == "$LOCALAPPDATA\OpenAIDR\app"
    !insertmacro IsShortcutTarget "$SMPROGRAMS\OpenAIDR.lnk" "$LOCALAPPDATA\OpenAIDR\openaidr-desktop.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro SetShortcutTarget "$SMPROGRAMS\OpenAIDR.lnk" "$INSTDIR\openaidr-desktop.exe"
      !insertmacro SetLnkAppUserModelId "$SMPROGRAMS\OpenAIDR.lnk"
    ${EndIf}
    !insertmacro IsShortcutTarget "$DESKTOP\OpenAIDR.lnk" "$LOCALAPPDATA\OpenAIDR\openaidr-desktop.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro SetShortcutTarget "$DESKTOP\OpenAIDR.lnk" "$INSTDIR\openaidr-desktop.exe"
      !insertmacro SetLnkAppUserModelId "$DESKTOP\OpenAIDR.lnk"
    ${EndIf}
    ; A corrective install supplies the new recovery code even when the old
    ; worker cannot finish its saved transaction. Run after all app files,
    ; permissions, registration, and shortcuts are installed. Do not wait:
    ; an in-app update worker can hold the lock while waiting for NSIS to exit.
    ${If} ${FileExists} "$LOCALAPPDATA\OpenAIDR\migration\desktop-update.json"
    ${AndIfNot} ${FileExists} "$LOCALAPPDATA\OpenAIDR\migration\complete"
      Exec '"$INSTDIR\openaidr-desktop.exe" --resume-migration'
    ${EndIf}
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ClearErrors
  ${GetOptions} $CMDLINE "/UPDATE" $2
  ${If} ${Errors}
    ; Cleanup belongs to the signed uninstaller, independent of an incomplete
    ; app installation or a removed recovery executable. Its early command
    ; does not load app resources or create a WebView.
    InitPluginsDir
    File /oname=$PLUGINSDIR\openaidr-update-cleanup.exe "${MAINBINARYSRCPATH}"
    nsExec::ExecToStack /TIMEOUT=60000 '"$PLUGINSDIR\openaidr-update-cleanup.exe" --remove-update-service "$INSTDIR\openaidr-desktop.exe"'
    Pop $0
    Pop $1
    Delete "$PLUGINSDIR\openaidr-update-cleanup.exe"
    ${If} $0 != 0
      SetErrorLevel 3
      Abort "OpenAIDR could not stop automatic updates. Close OpenAIDR, then retry."
    ${EndIf}
    StrCpy $3 "$INSTDIR\runtime\openaidr.exe"
    ${IfNot} ${FileExists} "$3"
      StrCpy $3 "$INSTDIR\runtime\openaidr-sensor.exe"
    ${EndIf}
    ${If} ${FileExists} "$3"
      DetailPrint "Stopping the OpenAIDR background service..."
      nsExec::ExecToStack /TIMEOUT=120000 '"$3" uninstall'
      Pop $0
      Pop $1
      ${If} $0 != 0
        DetailPrint "OpenAIDR background sensor cleanup failed: $1"
        IfSilent +2
          MessageBox MB_ICONSTOP|MB_OK "OpenAIDR could not stop its background sensor. Close OpenAIDR, then retry. No application files were removed.$\r$\n$\r$\n$1"
        SetErrorLevel 3
        Abort "OpenAIDR background sensor cleanup failed."
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend
