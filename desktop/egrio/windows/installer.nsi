; The Windows installer, built by `cargo xtask package` (xtask/src/windows.rs)
; with NSIS, which passes:
;   VERSION          the app's version
;   FILE_VERSION     its numbers as Windows writes a file version, a.b.c.d
;   RUNTIME_VERSION  the Windows App SDK release the app is built with
;   APP              egrio.exe
;   SERVICE          egrio-service.exe
;   BOOTSTRAPPER     Microsoft.WindowsAppRuntime.Bootstrap.dll
;   WINTUN           wintun.dll
;   LICENSE          the project's distribution license text
;   ICON             the plated system app icon
;   MARK             the transparent in-window mark
;   ARTWORK          the transparent mark on white page backgrounds:
;                    <scale>.bmp for sidebars, header.bmp for other pages
;   OUTFILE          the setup program to write
; It installs for all users wherever the user chooses, Program Files at
; first. The privileged service runs from there as LocalSystem, so only
; administrators may change what Egrio installs. What it does and why is in
; docs/platforms/windows.md.

Unicode true
ManifestDPIAware true
SetCompressor /SOLID lzma
RequestExecutionLevel admin

!include FileFunc.nsh
!include LogicLib.nsh
!include WinMessages.nsh
!include x64.nsh
!include MUI2.nsh

; WINDOWS_SERVICE_NAME in egrio-platform-windows's service_layout.rs.
!define SERVICE_NAME "EgrioService"
!define SERVICE_KEY "SYSTEM\CurrentControlSet\Services\${SERVICE_NAME}"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Egrio"
; The login item the app writes (AUTOSTART_NAME in egrio-desktop).
!define RUN_KEY "Software\Microsoft\Windows\CurrentVersion\Run"
; Who may do what with Egrio's files, as under Program Files: SYSTEM and
; administrators everything, users and app containers read and run them
; (icacls with well-known SIDs). The folder's entries pass on to its files.
!define FILE_ACCESS "*S-1-5-18:F *S-1-5-32-544:F *S-1-5-32-545:RX *S-1-15-2-1:RX *S-1-15-2-2:RX"
!define FOLDER_ACCESS "*S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F *S-1-5-32-545:(OI)(CI)RX *S-1-15-2-1:(OI)(CI)RX *S-1-15-2-2:(OI)(CI)RX"

Name "Egrio"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\Egrio"
BrandingText "Egrio ${VERSION}"

; The folder of the Egrio installed before this one ran, and its version.
Var Installed
Var InstalledVersion
; 1 when the app runs this installer to update itself (/UPDATE).
Var Update
; 1 when the all-users desktop had Egrio's shortcut.
Var HadShortcut
Var ServiceCommand
Var LoginItem
; The installation WaitForApp and ServiceIsHere look at.
Var AppDir
Var Title
Var Text

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_RIGHT
!define MUI_HEADERIMAGE_BITMAP "${ARTWORK}\header.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "${ARTWORK}\100.bmp"
!define MUI_ABORTWARNING
!define MUI_CUSTOMFUNCTION_GUIINIT InitPageMark
!define MUI_CUSTOMFUNCTION_UNGUIINIT un.InitPageMark

!define MUI_PAGE_CUSTOMFUNCTION_PRE WelcomePre
!define MUI_PAGE_CUSTOMFUNCTION_SHOW WelcomeShow
!define MUI_WELCOMEPAGE_TITLE "$Title"
!define MUI_WELCOMEPAGE_TEXT "$Text"
!insertmacro MUI_PAGE_WELCOME

; DirText and UninstallText fall back to their defaults on an empty string.
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipWhenUpdating
!define MUI_PAGE_HEADER_TEXT "$(LocationTitle)"
!define MUI_PAGE_HEADER_SUBTEXT ""
!define MUI_DIRECTORYPAGE_TEXT_TOP " "
!insertmacro MUI_PAGE_DIRECTORY

!define MUI_PAGE_HEADER_TEXT "$(InstallingTitle)"
!define MUI_PAGE_HEADER_SUBTEXT ""
!insertmacro MUI_PAGE_INSTFILES

!define MUI_PAGE_CUSTOMFUNCTION_PRE FinishPre
!define MUI_PAGE_CUSTOMFUNCTION_SHOW FinishShow
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE FinishLeave
!define MUI_FINISHPAGE_TITLE "$Title"
!define MUI_FINISHPAGE_TEXT ""
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "$(RunApp)"
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchApp
!define MUI_FINISHPAGE_SHOWREADME
!define MUI_FINISHPAGE_SHOWREADME_TEXT "$(DesktopShortcut)"
!define MUI_FINISHPAGE_SHOWREADME_FUNCTION CreateDesktopShortcut
!insertmacro MUI_PAGE_FINISH

!define MUI_PAGE_HEADER_SUBTEXT ""
!define MUI_UNCONFIRMPAGE_TEXT_TOP " "
!insertmacro MUI_UNPAGE_CONFIRM
!define MUI_PAGE_HEADER_SUBTEXT ""
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "SimpChinese"
; The system's UI fonts instead of the dialogs' legacy one.
SetFont /LANG=${LANG_ENGLISH} "Segoe UI" 9
SetFont /LANG=${LANG_SIMPCHINESE} "Microsoft YaHei UI" 9

; Only ICON_SMALL is replaced; the system app icon remains the plated one.
; The loaded icon stays in use for this installer process's lifetime.
!macro PAGE_MARK
  InitPluginsDir
  File "/oname=$PLUGINSDIR\app-mark.ico" "${MARK}"
  System::Call 'user32::GetDpiForWindow(p $HWNDPARENT) i .r0'
  System::Call 'user32::GetSystemMetricsForDpi(i 49, i r0) i .r0'
  System::Call 'user32::LoadImageW(p 0, w "$PLUGINSDIR\app-mark.ico", i 1, i r0, i r0, i 0x10) p .r0'
  SendMessage $HWNDPARENT ${WM_SETICON} 0 $0
!macroend

Function InitPageMark
  !insertmacro PAGE_MARK
FunctionEnd

Function un.InitPageMark
  !insertmacro PAGE_MARK
FunctionEnd

; The project states no copyright line for the version resource.
!pragma warning disable 9100
VIProductVersion "${FILE_VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "CompanyName" "xinvexo"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductName" "Egrio"
VIAddVersionKey /LANG=${LANG_ENGLISH} "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileDescription" "Egrio Setup"
VIAddVersionKey /LANG=${LANG_ENGLISH} "FileVersion" "${VERSION}"

LangString Unsupported ${LANG_ENGLISH} "Egrio needs 64-bit Windows on an x64 processor."
LangString Unsupported ${LANG_SIMPCHINESE} "Egrio 需要 x64 处理器上的 64 位 Windows。"
LangString InstallTitle ${LANG_ENGLISH} "Install Egrio"
LangString InstallTitle ${LANG_SIMPCHINESE} "安装 Egrio"
LangString UpdateTitle ${LANG_ENGLISH} "Update Egrio"
LangString UpdateTitle ${LANG_SIMPCHINESE} "更新 Egrio"
LangString VersionLabel ${LANG_ENGLISH} "Version ${VERSION}"
LangString VersionLabel ${LANG_SIMPCHINESE} "版本 ${VERSION}"
LangString LocationTitle ${LANG_ENGLISH} "Install location"
LangString LocationTitle ${LANG_SIMPCHINESE} "安装位置"
LangString InstallingTitle ${LANG_ENGLISH} "Installing"
LangString InstallingTitle ${LANG_SIMPCHINESE} "正在安装"
LangString InstalledTitle ${LANG_ENGLISH} "Egrio is installed"
LangString InstalledTitle ${LANG_SIMPCHINESE} "Egrio 已安装"
LangString UpdatedTitle ${LANG_ENGLISH} "Egrio is updated to ${VERSION}"
LangString UpdatedTitle ${LANG_SIMPCHINESE} "Egrio 已更新到 ${VERSION}"
LangString RunApp ${LANG_ENGLISH} "Run Egrio"
LangString RunApp ${LANG_SIMPCHINESE} "运行 Egrio"
LangString DesktopShortcut ${LANG_ENGLISH} "Desktop shortcut"
LangString DesktopShortcut ${LANG_SIMPCHINESE} "桌面快捷方式"
LangString PreparingRuntime ${LANG_ENGLISH} "Preparing the Windows App Runtime…"
LangString PreparingRuntime ${LANG_SIMPCHINESE} "正在准备 Windows App Runtime…"
LangString RuntimeFailed ${LANG_ENGLISH} "The Windows App Runtime could not be installed ($0)."
LangString RuntimeFailed ${LANG_SIMPCHINESE} "Windows App Runtime 未能安装（$0）"
LangString AppRunning ${LANG_ENGLISH} "Egrio is running."
LangString AppRunning ${LANG_SIMPCHINESE} "Egrio 正在运行"
LangString ProtectFailed ${LANG_ENGLISH} "The permissions of Egrio's files could not be set ($0)."
LangString ProtectFailed ${LANG_SIMPCHINESE} "未能设置 Egrio 文件的权限（$0）"
LangString ServiceFailed ${LANG_ENGLISH} "The Egrio service could not be restarted ($0)."
LangString ServiceFailed ${LANG_SIMPCHINESE} "Egrio 服务未能重新启动（$0）"

Function .onInit
  ${IfNot} ${IsNativeAMD64}
    MessageBox MB_OK|MB_ICONSTOP "$(Unsupported)" /SD IDOK
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
  ReadRegStr $Installed HKLM "${UNINSTALL_KEY}" "InstallLocation"
  ${If} $Installed != ""
  ${AndIf} ${FileExists} "$Installed\egrio.exe"
    ReadRegStr $InstalledVersion HKLM "${UNINSTALL_KEY}" "DisplayVersion"
    ; The location page offers where Egrio is, unless /D names a folder.
    ${If} $INSTDIR == "$PROGRAMFILES64\Egrio"
      StrCpy $INSTDIR $Installed
    ${EndIf}
    ${GetParameters} $0
    ClearErrors
    ${GetOptions} $0 "/UPDATE" $1
    ${IfNot} ${Errors}
      StrCpy $Update 1
    ${EndIf}
  ${Else}
    StrCpy $Installed ""
  ${EndIf}
  ${If} ${FileExists} "$DESKTOP\Egrio.lnk"
    StrCpy $HadShortcut 1
  ${EndIf}
FunctionEnd

; An update from the app only shows its progress, then starts the app again.
Function SkipWhenUpdating
  ${If} $Update == 1
    Abort
  ${EndIf}
FunctionEnd

Function WelcomePre
  Call SkipWhenUpdating
  ${If} $Installed != ""
  ${AndIf} $InstalledVersion != "${VERSION}"
    StrCpy $Title "$(UpdateTitle)"
    StrCpy $Text "$InstalledVersion → ${VERSION}"
  ${Else}
    StrCpy $Title "$(InstallTitle)"
    StrCpy $Text "$(VersionLabel)"
  ${EndIf}
FunctionEnd

; Shows the sidebar rendered nearest above the picture's size, which the
; page then barely stretches: Windows scales a bitmap by dropping or
; repeating pixels, and the page grows with the display's scale.
!macro SIDEBAR control bitmap
  System::Call "*(i, i, i, i) p .r1"
  System::Call "user32::GetClientRect(p ${control}, p r1)"
  System::Call "*$1(i, i, i .r2, i)"
  System::Free $1
  ${If} $2 <= 164
    File "/oname=$PLUGINSDIR\sidebar.bmp" "${ARTWORK}\100.bmp"
  ${ElseIf} $2 <= 205
    File "/oname=$PLUGINSDIR\sidebar.bmp" "${ARTWORK}\125.bmp"
  ${ElseIf} $2 <= 246
    File "/oname=$PLUGINSDIR\sidebar.bmp" "${ARTWORK}\150.bmp"
  ${ElseIf} $2 <= 287
    File "/oname=$PLUGINSDIR\sidebar.bmp" "${ARTWORK}\175.bmp"
  ${ElseIf} $2 <= 328
    File "/oname=$PLUGINSDIR\sidebar.bmp" "${ARTWORK}\200.bmp"
  ${ElseIf} $2 <= 369
    File "/oname=$PLUGINSDIR\sidebar.bmp" "${ARTWORK}\225.bmp"
  ${ElseIf} $2 <= 410
    File "/oname=$PLUGINSDIR\sidebar.bmp" "${ARTWORK}\250.bmp"
  ${Else}
    File "/oname=$PLUGINSDIR\sidebar.bmp" "${ARTWORK}\300.bmp"
  ${EndIf}
  ${NSD_FreeImage} ${bitmap}
  ${NSD_SetStretchedImage} ${control} "$PLUGINSDIR\sidebar.bmp" ${bitmap}
!macroend

Function WelcomeShow
  !insertmacro SIDEBAR $mui.WelcomePage.Image $mui.WelcomePage.Image.Bitmap
FunctionEnd

Function FinishPre
  Call SkipWhenUpdating
  ${If} $Installed != ""
  ${AndIf} $InstalledVersion != "${VERSION}"
    StrCpy $Title "$(UpdatedTitle)"
  ${Else}
    StrCpy $Title "$(InstalledTitle)"
  ${EndIf}
FunctionEnd

; A new installation gets the desktop shortcut unless the user unticks it;
; an update keeps what the desktop had.
Function FinishShow
  !insertmacro SIDEBAR $mui.FinishPage.Image $mui.FinishPage.Image.Bitmap
  ${If} $Installed != ""
  ${AndIf} $HadShortcut != 1
    ${NSD_Uncheck} $mui.FinishPage.ShowReadme
  ${EndIf}
FunctionEnd

Function FinishLeave
  ${NSD_GetState} $mui.FinishPage.ShowReadme $0
  ${If} $0 != ${BST_CHECKED}
    Delete "$DESKTOP\Egrio.lnk"
  ${EndIf}
FunctionEnd

Function CreateDesktopShortcut
  CreateShortcut "$DESKTOP\Egrio.lnk" "$INSTDIR\egrio.exe"
FunctionEnd

Function LaunchApp
  ; Started by Explorer, the app runs with the signed-in user's own rights
  ; rather than this installer's elevated ones.
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\egrio.exe"'
FunctionEnd

Function .onInstSuccess
  ${If} $Update == 1
    Call LaunchApp
  ${EndIf}
FunctionEnd

; Waits for a running egrio.exe in $AppDir to exit, which it does right
; after the app opens this installer to update itself; Windows keeps the
; file of a running program from being written.
!macro WAIT_FOR_APP un
Function ${un}WaitForApp
  StrCpy $1 0
  ${DoWhile} ${FileExists} "$AppDir\egrio.exe"
    ClearErrors
    FileOpen $0 "$AppDir\egrio.exe" a
    ${IfNot} ${Errors}
      FileClose $0
      ${Break}
    ${EndIf}
    IntOp $1 $1 + 1
    ${If} $1 < 20
      Sleep 500
    ${Else}
      MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "$(AppRunning)" /SD IDCANCEL IDRETRY retry
      Abort
      retry:
      StrCpy $1 0
    ${EndIf}
  ${Loop}
FunctionEnd
!macroend
!insertmacro WAIT_FOR_APP ""
!insertmacro WAIT_FOR_APP "un."

; Whether the registered service runs $AppDir's egrio-service.exe: its
; command line opens with that quoted path (windows_service_command_line in
; service_layout.rs). Leaves 1 or 0 in $0.
!macro SERVICE_IS_HERE un
Function ${un}ServiceIsHere
  StrCpy $1 '"$AppDir\egrio-service.exe"'
  StrLen $2 $1
  StrCpy $3 $ServiceCommand $2
  ${If} $3 == $1
    StrCpy $0 1
  ${Else}
    StrCpy $0 0
  ${EndIf}
FunctionEnd
!macroend
!insertmacro SERVICE_IS_HERE ""
!insertmacro SERVICE_IS_HERE "un."

; Whether $INSTDIR is Egrio's own folder: missing, empty or holding only
; what Egrio installs. Leaves 1 or 0 in $0.
Function IsOwnFolder
  StrCpy $0 1
  FindFirst $1 $2 "$INSTDIR\*"
  ${DoWhile} $2 != ""
    ${Switch} $2
      ${Case} "."
      ${Case} ".."
      ${Case} "egrio.exe"
      ${Case} "egrio-service.exe"
      ${Case} "Microsoft.WindowsAppRuntime.Bootstrap.dll"
      ${Case} "wintun.dll"
      ${Case} "Egrio-LICENSE.txt"
      ${Case} "uninstall.exe"
        ${Break}
      ${Default}
        StrCpy $0 0
    ${EndSwitch}
    ${If} $0 == 0
      ${Break}
    ${EndIf}
    FindNext $1 $2
  ${Loop}
  FindClose $1
FunctionEnd

!macro PROTECT path access
  nsExec::ExecToLog '"$SYSDIR\icacls.exe" "${path}" /inheritance:r /grant:r ${access}'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONEXCLAMATION "$(ProtectFailed)" /SD IDOK
  ${EndIf}
!macroend

Section
  InitPluginsDir
  File "/oname=$PLUGINSDIR\runtime.ps1" "runtime.ps1"
  DetailPrint "$(PreparingRuntime)"
  ; The 64-bit PowerShell: this installer is a 32-bit program.
  nsExec::ExecToLog '"$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\runtime.ps1" -Version ${RUNTIME_VERSION}'
  Pop $0
  ${If} $0 != 0
    ; The runtime installer's errors are HRESULTs.
    ${If} $0 < 0
      IntFmt $0 "0x%08X" $0
    ${EndIf}
    MessageBox MB_OK|MB_ICONEXCLAMATION "$(RuntimeFailed)" /SD IDOK
  ${EndIf}

  ${If} $Installed != ""
    StrCpy $AppDir $Installed
    Call WaitForApp
  ${EndIf}
  StrCpy $AppDir $INSTDIR
  Call WaitForApp

  ; Read before an installation elsewhere uninstalls itself: any Egrio
  ; service starts again from here afterwards, and the login item follows.
  ReadRegStr $ServiceCommand HKLM "${SERVICE_KEY}" "ImagePath"
  ReadRegStr $LoginItem HKCU "${RUN_KEY}" "Egrio"
  ${If} $Installed != ""
  ${AndIf} $Installed != $INSTDIR
    ; Egrio moves here: the installation it leaves removes itself.
    ExecWait '"$Installed\uninstall.exe" /S _?=$Installed'
    Delete "$Installed\uninstall.exe"
    RMDir "$Installed"
  ${Else}
    ; A service running this installation's egrio-service.exe stops while
    ; the file is replaced.
    Call ServiceIsHere
    ${If} $0 == 1
      nsExec::ExecToLog '"$SYSDIR\net.exe" stop ${SERVICE_NAME}'
      Pop $0
    ${EndIf}
  ${EndIf}

  ; Only administrators may change what the service runs: the folder when
  ; it is Egrio's own, each of Egrio's files in any folder.
  Call IsOwnFolder
  StrCpy $4 $0
  SetOutPath "$INSTDIR"
  ${If} $4 == 1
    !insertmacro PROTECT "$INSTDIR" "${FOLDER_ACCESS}"
  ${EndIf}
  File "${APP}"
  File "${SERVICE}"
  File "${BOOTSTRAPPER}"
  File "${WINTUN}"
  File /oname=Egrio-LICENSE.txt "${LICENSE}"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  !insertmacro PROTECT "$INSTDIR\egrio.exe" "${FILE_ACCESS}"
  !insertmacro PROTECT "$INSTDIR\egrio-service.exe" "${FILE_ACCESS}"
  !insertmacro PROTECT "$INSTDIR\Microsoft.WindowsAppRuntime.Bootstrap.dll" "${FILE_ACCESS}"
  !insertmacro PROTECT "$INSTDIR\wintun.dll" "${FILE_ACCESS}"
  !insertmacro PROTECT "$INSTDIR\Egrio-LICENSE.txt" "${FILE_ACCESS}"
  !insertmacro PROTECT "$INSTDIR\uninstall.exe" "${FILE_ACCESS}"

  ${If} $ServiceCommand != ""
    nsExec::ExecToLog '"$INSTDIR\egrio-service.exe" bootstrap-windows-service'
    Pop $0
    ${If} $0 != 0
      MessageBox MB_OK|MB_ICONEXCLAMATION "$(ServiceFailed)" /SD IDOK
    ${EndIf}
  ${EndIf}

  ; The signed-in user's login item started the installation Egrio left.
  ${If} $Installed != ""
  ${AndIf} $Installed != $INSTDIR
    StrCpy $1 '"$Installed\egrio.exe"'
    StrLen $2 $1
    StrCpy $3 $LoginItem $2
    ${If} $3 == $1
      StrCpy $3 $LoginItem "" $2
      WriteRegStr HKCU "${RUN_KEY}" "Egrio" '"$INSTDIR\egrio.exe"$3'
    ${EndIf}
  ${EndIf}

  CreateShortcut "$SMPROGRAMS\Egrio.lnk" "$INSTDIR\egrio.exe"
  ${If} $HadShortcut == 1
    CreateShortcut "$DESKTOP\Egrio.lnk" "$INSTDIR\egrio.exe"
  ${EndIf}
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "Egrio"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "xinvexo"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\egrio.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "${UNINSTALL_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "EstimatedSize" $0
SectionEnd

Function un.onInit
  SetRegView 64
  SetShellVarContext all
FunctionEnd

Section Uninstall
  StrCpy $AppDir $INSTDIR
  Call un.WaitForApp
  ; Only a service this installation registered goes with it.
  ReadRegStr $ServiceCommand HKLM "${SERVICE_KEY}" "ImagePath"
  Call un.ServiceIsHere
  ${If} $0 == 1
    nsExec::ExecToLog '"$INSTDIR\egrio-service.exe" uninstall-windows-service'
    Pop $0
  ${EndIf}
  ; The signed-in user's login item, when it starts this installation.
  ReadRegStr $1 HKCU "${RUN_KEY}" "Egrio"
  StrCpy $2 '"$INSTDIR\egrio.exe"'
  StrLen $3 $2
  StrCpy $1 $1 $3
  ${If} $1 == $2
    DeleteRegValue HKCU "${RUN_KEY}" "Egrio"
  ${EndIf}

  ; Only what Egrio installed: the folder may hold other things.
  Delete "$INSTDIR\egrio.exe"
  Delete "$INSTDIR\egrio-service.exe"
  Delete "$INSTDIR\Microsoft.WindowsAppRuntime.Bootstrap.dll"
  Delete "$INSTDIR\wintun.dll"
  Delete "$INSTDIR\Egrio-LICENSE.txt"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  Delete "$SMPROGRAMS\Egrio.lnk"
  Delete "$DESKTOP\Egrio.lnk"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
SectionEnd
