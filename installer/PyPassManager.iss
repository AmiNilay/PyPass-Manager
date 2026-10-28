; Inno Setup script - turns the PyInstaller output into a single Windows installer.
;
; 1. Build the app first:   .venv\Scripts\python.exe -m PyInstaller --noconfirm "PyPass Manager.spec"
; 2. Compile this script:   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\PyPassManager.iss
; Result: installer\Output\PyPass-Manager-Setup-<version>.exe
;
; Keep MyAppVersion in sync with APP_VERSION in config/settings.py.
; Never change AppId - Windows uses it to recognise upgrades of the same app.

#define MyAppName "PyPass Manager"
; CI overrides the version with: ISCC /DMyAppVersion=<tag version>
#ifndef MyAppVersion
  #define MyAppVersion "2.0.0"
#endif
#define MyAppPublisher "Nilay Naha"
#define MyAppURL "https://github.com/AmiNilay/PyPass-Manager"
#define MyAppExeName "PyPass Manager.exe"

[Setup]
AppId={{68A8FF95-1019-437B-B92D-C302DE066368}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}/issues
AppUpdatesURL={#MyAppURL}/releases
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; Per-user install by default (no admin prompt); users can choose "all users" in the wizard
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=Output
OutputBaseFilename=PyPass-Manager-Setup-{#MyAppVersion}
SetupIconFile=..\assets\icons\app_icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\PyPass Manager\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent

; The vault lives in %USERPROFILE%\.pypass_manager and is deliberately NOT removed on
; uninstall, so reinstalling or upgrading never deletes a user's passwords.
