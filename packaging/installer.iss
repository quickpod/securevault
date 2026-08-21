; Inno Setup script for SecureVault - builds a friendly Windows installer that
; drops SecureVault.exe and the full suite, then creates Desktop and Start Menu
; shortcuts and an Add/Remove Programs entry. Compiled in CI by iscc.
;
; Expects (staged by the GitHub Actions workflow into packaging\staging\):
;   SecureVault.exe, svhost.exe, extension\, nativehost\, docs\, *.ps1,
;   README.md, LICENSE, quickopen-root.crt

#define AppName "SecureVault"
#define AppVersion "1.0.14"
#define AppPublisher "QuickOpen (quickopen.ai)"
#define AppURL "https://quickopen.ai/projects/securevault"

[Setup]
AppMutex=QuickOpen.SecureVault
AppId={{9E7C2B4A-2F51-4E3B-9C7A-5EC0A1B2D3F0}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\SecureVault.exe
OutputDir=dist
OutputBaseFilename=SecureVault-Setup
SetupIconFile=..\securevault.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardImageFile=branding\wizard-large.bmp
WizardSmallImageFile=branding\wizard-small.bmp
AppCopyright=Apache-2.0. 100%% AI-built, published on QuickOpen (quickopen.ai).
VersionInfoCompany=QuickOpen
VersionInfoProductName=SecureVault
VersionInfoVersion=1.0.14.0
; Install per-user by default (no admin, and the app directory stays writable so
; the browser-autofill wizard can inject the extension key + write the native
; host manifest). {autopf} then resolves to %LOCALAPPDATA%\Programs\SecureVault.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel1=Welcome to SecureVault by [name/ver]
WelcomeLabel2=SecureVault is a 100%% AI-built, open-source encrypted vault and Windows hardening toolkit, published on QuickOpen (quickopen.ai).%n%nThis will install it on your computer.
BeveledLabel=QuickOpen · quickopen.ai

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "trustca"; Description: "Trust the QuickOpen Root CA (lets Windows verify QuickOpen signatures)"; GroupDescription: "Security:"; Flags: unchecked

[Files]
Source: "staging\SecureVault.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\svhost.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\quickopen-root.crt"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "staging\LICENSE"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\extension\*"; DestDir: "{app}\extension"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "staging\nativehost\*"; DestDir: "{app}\nativehost"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "staging\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
Source: "staging\*.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\SecureVault"; Filename: "{app}\SecureVault.exe"; IconFilename: "{app}\SecureVault.exe"
Name: "{group}\SecureVault Documentation"; Filename: "{app}\docs\USAGE.md"
Name: "{group}\Uninstall SecureVault"; Filename: "{uninstallexe}"
Name: "{autodesktop}\SecureVault"; Filename: "{app}\SecureVault.exe"; IconFilename: "{app}\SecureVault.exe"; Tasks: desktopicon

[Run]
; Optional: register the app's own Explorer shell integration.
Filename: "{app}\SecureVault.exe"; Parameters: "register"; Flags: runhidden skipifdoesntexist; StatusMsg: "Registering shell integration..."
; Optional: trust the QuickOpen Root CA (per the trustca task).
Filename: "certutil.exe"; Parameters: "-addstore -user Root ""{app}\quickopen-root.crt"""; Tasks: trustca; Flags: runhidden; StatusMsg: "Trusting the QuickOpen Root CA..."
Filename: "{app}\SecureVault.exe"; Description: "Launch SecureVault now"; Flags: nowait postinstall skipifsilent skipifdoesntexist

[UninstallRun]
Filename: "{app}\SecureVault.exe"; Parameters: "unregister"; Flags: runhidden skipifdoesntexist; RunOnceId: "SvUnregister"

[UninstallDelete]
; App-owned state only. The vault file (SecureVault.dat) is the user's data,
; lives wherever they chose, and is intentionally never touched.
Type: filesandordirs; Name: "{localappdata}\SecureVault"

