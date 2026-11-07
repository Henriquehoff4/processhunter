[Setup]
AppName=ProcessHunter
AppVersion=1.0.0
DefaultDirName={autopf}\ProcessHunter
DefaultGroupName=ProcessHunter
OutputDir=.
OutputBaseFilename=ProcessHunter-Setup-Inno
SetupIconFile=..\src\ProcessHunter\Assets\app.ico
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "..\publish\standalone\ProcessHunter.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\ProcessHunter"; Filename: "{app}\ProcessHunter.exe"
Name: "{autodesktop}\ProcessHunter"; Filename: "{app}\ProcessHunter.exe"
