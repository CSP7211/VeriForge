; VeriForge Red — Inno Setup Installer Script
;
; Creates a professional Windows installer that:
;   - Installs VeriForgeRed.exe (desktop GUI app)
;   - Installs VeriForgeRedService.exe (background service)
;   - Creates Start Menu and Desktop shortcuts
;   - Optionally installs the Windows service
;   - Registers an uninstaller entry
;
; Build with Inno Setup 6:
;   iscc installer.iss

#define MyAppName      "VeriForge Red"
#define MyAppVersion   "1.0.0"
#define MyAppPublisher "VeriForge"
#define MyAppURL       "https://veriforge.dev"
#define MyAppExeName   "VeriForgeRed.exe"
#define MySvcExeName   "VeriForgeRedService.exe"

[Setup]
AppId={{7A2F4C9E-5B1D-4E8A-9C3F-6D7E8B5A2C1F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=no
DefaultGroupName={#MyAppName}
OutputDir=dist
OutputBaseFilename=VeriForgeRed_Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
LicenseFile=..\..\LICENSE
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "installservice"; Description: "Install Windows Service (auto-start on boot)"; GroupDescription: "Service:"; Flags: checkedonce

[Files]
; Main executables
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "dist\{#MySvcExeName}"; DestDir: "{app}"; Flags: ignoreversion
; Icon
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start Menu
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
; Desktop
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Run]
; Optionally install and start the Windows service
Filename: "{app}\{#MySvcExeName}"; Parameters: "install"; Flags: runhidden; Tasks: installservice
Filename: "{app}\{#MySvcExeName}"; Parameters: "start"; Flags: runhidden; Tasks: installservice; AfterInstall: RefreshEnvironment
; Launch the app after install
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop and remove the service on uninstall
Filename: "{app}\{#MySvcExeName}"; Parameters: "stop"; Flags: runhidden; RunOnceId: StopService
Filename: "{app}\{#MySvcExeName}"; Parameters: "remove"; Flags: runhidden; RunOnceId: RemoveService

[UninstallDelete]
Type: files; Name: "{app}\icon.ico"

[Code]
{ Refresh Windows Explorer after install so the new shortcuts appear immediately }
procedure RefreshEnvironment;
var
  S: Longint;
begin
  S := SendMessage(HWND_BROADCAST, WM_SETTINGCHANGE, 0, 0);
end;

{ Check whether the service is running before uninstall }
function InitializeUninstall(): Boolean;
begin
  Result := True;
  { Prompt for confirmation if service is installed }
  if MsgBox('This will remove {#MyAppName} and its Windows service.'#13#10'Continue?',
            mbConfirmation, MB_YESNO) = IDYES then
    Result := True
  else
    Result := False;
end;

{ Post-install finish page }
procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    { Notify user about service installation }
    if WizardIsTaskSelected('installservice') then
    begin
      MsgBox('The VeriForge Red background service has been installed and started.'#13#10
             'It will automatically start on boot.',
             mbInformation, MB_OK);
    end;
  end;
end;
